require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT || 3000);

// =========================
// DATABASE
// =========================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

// =========================
// BASIC SETTINGS
// =========================

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || true,
    credentials: true,
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

// =========================
// SESSION
// =========================

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
    }),

    secret: process.env.SESSION_SECRET || "CHANGE_ME",

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

// =========================
// RATE LIMIT
// =========================

app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// =========================
// ADMIN AUTH
// =========================

function auth(req, res, next) {
  if (req.session.adminId) {
    return next();
  }

  return res.status(401).json({
    error: "Unauthorized",
  });
}

// =========================
// PHONE VALIDATION
// =========================

function validPhone(value) {
  return /^[0-9+\- ]{8,20}$/.test(String(value || ""));
}

// =========================
// HEALTH CHECK
// =========================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
    });
  } catch (error) {
    res.status(503).json({
      ok: false,
      database: "unavailable",
    });
  }
});

// =========================
// PRODUCTS
// =========================

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products WHERE active=true ORDER BY created_at DESC"
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Could not load products",
    });
  }
});

// =========================
// ADMIN LOGIN
// =========================

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password required",
    });
  }

  try {
    const result = await pool.query(
      "SELECT id, username, password_hash FROM admins WHERE username=$1",
      [username]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid login",
      });
    }

    req.session.adminId = result.rows[0].id;
    req.session.adminUsername = result.rows[0].username;

    res.json({
      ok: true,
      username: result.rows[0].username,
    });
  } catch (error) {
    res.status(500).json({
      error: "Login failed",
    });
  }
});

// =========================
// ADMIN LOGOUT
// =========================

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true,
    });
  });
});

// =========================
// ADMIN PROFILE
// =========================

app.get("/api/admin/me", auth, (req, res) => {
  res.json({
    ok: true,
    username: req.session.adminUsername,
  });
});

// =========================
// ADMIN ORDERS
// =========================

app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        o.*,
        COALESCE(
          json_agg(
            json_build_object(
              'productId', oi.product_id,
              'productName', oi.product_name,
              'unitPrice', oi.unit_price_bdt,
              'quantity', oi.quantity,
              'size', oi.size
            )
            ORDER BY oi.id
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'
        ) items
      FROM orders o
      LEFT JOIN order_items oi
        ON oi.order_id = o.id
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Could not load orders",
    });
  }
});

// =========================
// UPDATE ORDER STATUS
// =========================

app.patch("/api/admin/orders/:id", auth, async (req, res) => {
  const allowedStatuses = [
    "pending",
    "confirmed",
    "packed",
    "shipped",
    "delivered",
    "cancelled",
  ];

  if (!allowedStatuses.includes(req.body.status)) {
    return res.status(400).json({
      error: "Invalid status",
    });
  }

  try {
    const result = await pool.query(
      "UPDATE orders SET order_status=$1 WHERE id=$2 RETURNING *",
      [req.body.status, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Order not found",
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      error: "Could not update order",
    });
  }
});

// =========================
// ADD PRODUCT
// =========================

app.post("/api/admin/products", auth, async (req, res) => {
  const {
    id,
    name,
    price_bdt,
    old_price_bdt,
    category = "new",
    sizes = "",
    image_url = "",
  } = req.body || {};

  if (!id || !name || !Number.isInteger(Number(price_bdt))) {
    return res.status(400).json({
      error: "id, name and valid price required",
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO products
        (id, name, price_bdt, old_price_bdt, category, sizes, image_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        id,
        name,
        Number(price_bdt),
        old_price_bdt ? Number(old_price_bdt) : null,
        category,
        sizes,
        image_url,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      error: "Could not add product",
    });
  }
});

// =========================
// DELETE PRODUCT
// =========================

app.delete("/api/admin/products/:id", auth, async (req, res) => {
  try {
    await pool.query(
      "UPDATE products SET active=false WHERE id=$1",
      [req.params.id]
    );

    res.json({
      ok: true,
    });
  } catch (error) {
    res.status(500).json({
      error: "Could not delete product",
    });
  }
});

// =========================
// CREATE ORDER
// =========================

app.post("/api/orders", async (req, res) => {
  const {
    customerName,
    phone,
    address,
    paymentMethod,
    items,
  } = req.body || {};

  if (
    !customerName ||
    !validPhone(phone) ||
    !address ||
    !Array.isArray(items) ||
    !items.length
  ) {
    return res.status(400).json({
      error:
        "Customer name, valid phone, address and items are required",
    });
  }

  if (!["cod", "bkash", "nagad"].includes(paymentMethod)) {
    return res.status(400).json({
      error: "Invalid payment method",
    });
  }

  try {
    const ids = [
      ...new Set(
        items.map((item) => String(item.productId))
      ),
    ];

    const productsResult = await pool.query(
      "SELECT * FROM products WHERE active=true AND id=ANY($1::text[])",
      [ids]
    );

    const products = productsResult.rows;

    if (products.length !== ids.length) {
      return res.status(400).json({
        error: "One or more products are unavailable",
      });
    }

    const productMap = new Map(
      products.map((product) => [
        product.id,
        product,
      ])
    );

    let total = 0;

    const normalizedItems = [];

    for (const item of items) {
      const product = productMap.get(
        String(item.productId)
      );

      const quantity = Number(item.quantity);

      if (
        !product ||
        !Number.isInteger(quantity) ||
        quantity < 1 ||
        quantity > 20
      ) {
        return res.status(400).json({
          error: "Invalid cart item",
        });
      }

      total += product.price_bdt * quantity;

      normalizedItems.push({
        product,
        quantity,
        size: item.size || null,
      });
    }

    const connection = await pool.connect();

    try {
      await connection.query("BEGIN");

      const orderResult = await connection.query(
        `INSERT INTO orders
          (customer_name, phone, address, payment_method, total_bdt)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, created_at`,
        [
          customerName,
          phone,
          address,
          paymentMethod,
          total,
        ]
      );

      for (const item of normalizedItems) {
        await connection.query(
          `INSERT INTO order_items
            (order_id, product_id, product_name,
             unit_price_bdt, quantity, size)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            orderResult.rows[0].id,
            item.product.id,
            item.product.name,
            item.product.price_bdt,
            item.quantity,
            item.size,
          ]
        );
      }

      await connection.query("COMMIT");

      res.status(201).json({
        ok: true,
        orderId: orderResult.rows[0].id,
        totalBdt: total,
      });
    } catch (error) {
      await connection.query("ROLLBACK");

      res.status(500).json({
        error: "Could not create order",
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    res.status(500).json({
      error: "Could not process order",
    });
  }
});

// =========================
// BKASH PAYMENT
// =========================

app.post("/api/payments/bkash/create", async (req, res) => {
  if (!process.env.BKASH_APP_KEY) {
    return res.status(503).json({
      error: "bKash merchant credentials are not configured",
    });
  }

  res.status(501).json({
    error:
      "Connect this endpoint to the current official bKash merchant API flow.",
  });
});

app.post("/api/payments/bkash/callback", (req, res) => {
  res.status(501).json({
    error: "Implement official bKash callback verification",
  });
});

// =========================
// NAGAD PAYMENT
// =========================

app.post("/api/payments/nagad/create", async (req, res) => {
  if (!process.env.NAGAD_MERCHANT_ID) {
    return res.status(503).json({
      error: "Nagad merchant credentials are not configured",
    });
  }

  res.status(501).json({
    error:
      "Connect this endpoint to the current official Nagad merchant API flow.",
  });
});

app.post("/api/payments/nagad/callback", (req, res) => {
  res.status(501).json({
    error: "Implement official Nagad callback verification",
  });
});

// =========================
// FRONTEND
// =========================

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// =========================
// START SERVER
// =========================

app.listen(port, () => {
  console.log(
    `TWO BRO ROYALE running on port ${port}`
  );
});
