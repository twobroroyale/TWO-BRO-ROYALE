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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

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

app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function auth(req, res, next) {
  if (req.session.adminId) {
    return next();
  }

  return res.status(401).json({
    error: "Unauthorized",
  });
}

// FIXED: phone-number validation regex
function validPhone(v) {
  return /^[0-9+\- ]{8,20}$/.test(String(v || ""));
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
    });
  } catch (e) {
    res.status(503).json({
      ok: false,
      database: "unavailable",
    });
  }
});

app.get("/api/products", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM products WHERE active=true ORDER BY created_at DESC"
    );

    res.json(r.rows);
  } catch (e) {
    res.status(500).json({
      error: "Could not load products",
    });
  }
});

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password required",
    });
  }

  const r = await pool.query(
    "SELECT id,username,password_hash FROM admins WHERE username=$1",
    [username]
  );

  if (
    !r.rowCount ||
    !(await bcrypt.compare(password, r.rows[0].password_hash))
  ) {
    return res.status(401).json({
      error: "Invalid login",
    });
  }

  req.session.adminId = r.rows[0].id;
  req.session.adminUsername = r.rows[0].username;

  res.json({
    ok: true,
    username: r.rows[0].username,
  });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true,
    });
  });
});

app.get("/api/admin/me", auth, (req, res) => {
  res.json({
    ok: true,
    username: req.session.adminUsername,
  });
});

app.get("/api/admin/orders", auth, async (req, res) => {
  const r = await pool.query(`
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
    LEFT JOIN order_items oi ON oi.order_id = o.id
    GROUP BY o.id
    ORDER BY o.created_at DESC
  `);

  res.json(r.rows);
});

app.patch("/api/admin/orders/:id", auth, async (req, res) => {
  const allowed = [
    "pending",
    "confirmed",
    "packed",
    "shipped",
    "delivered",
    "cancelled",
  ];

  if (!allowed.includes(req.body.status)) {
    return res.status(400).json({
      error: "Invalid status",
    });
  }

  const r = await pool.query(
    "UPDATE orders SET order_status=$1 WHERE id=$2 RETURNING *",
    [req.body.status, req.params.id]
  );

  if (!r.rowCount) {
    return res.status(404).json({
      error: "Order not found",
    });
  }

  res.json(r.rows[0]);
});

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

  const r = await pool.query(
    `INSERT INTO products
      (id,name,price_bdt,old_price_bdt,category,sizes,image_url)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
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

  res.status(201).json(r.rows[0]);
});

app.delete("/api/admin/products/:id", auth, async (req, res) => {
  await pool.query(
    "UPDATE products SET active=false WHERE id=$1",
    [req.params.id]
  );

  res.json({
    ok: true,
  });
});

app.post("/api/orders", async (req, res) => {
  const {
    customer
