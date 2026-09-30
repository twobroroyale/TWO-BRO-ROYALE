# TWO BRO ROYALE — REAL WEBSITE PACKAGE

এই package-এ frontend + Node.js backend + PostgreSQL schema + secure session-based admin login আছে।

## কী আছে
- Real server-side product API
- Real order storage
- PostgreSQL
- Admin login with bcrypt password hash
- Server-side session
- Admin order dashboard
- Product API
- Helmet/CORS/rate limiting
- bKash/Nagad server-side integration points

## আগে যা লাগবে
1. Domain
2. Node.js 20+ hosting/server
3. PostgreSQL database
4. Official bKash merchant/developer credentials (automatic payment চাইলে)
5. Official Nagad merchant credentials (automatic payment চাইলে)

## Setup
1. এই folder hosting/server-এ upload করুন।
2. `npm install`
3. `.env.example` কপি করে `.env` বানান।
4. PostgreSQL database তৈরি করুন।
5. `sql/schema.sql` database-এ চালান।
6. Admin password-এর bcrypt hash তৈরি করে `ADMIN_PASSWORD_HASH`-এ বসান।
7. `admins` table-এ owner user insert করুন:
   INSERT INTO admins(username,password_hash) VALUES('owner','YOUR_BCRYPT_HASH');
8. `npm start`
9. Domain-এর DNS hosting/server-এর দিকে point করুন।
10. HTTPS চালু করুন।

## Demo products
Database-এ products insert না করলে shop খালি থাকবে। Example SQL:
INSERT INTO products(id,name,price_bdt,old_price_bdt,category,sizes) VALUES
('royal-tee','Royal Essential T-Shirt',899,1099,'men','S/M/L/XL'),
('royal-shirt','Signature Royal Shirt',1490,1790,'men','M/L/XL/XXL'),
('royal-polo','Royale Premium Polo',1190,1390,'men','S/M/L/XL'),
('royal-denim','Royal Straight Denim',1690,1990,'men','30/32/34/36');

## Important
এই package-কে "লাইভ" করতে আমি আপনার domain/hosting/payment account-এর credentials নিজে তৈরি করতে পারি না। bKash/Nagad-এর official current API flow ও merchant credentials আপনার বৈধ account থেকে নিতে হবে। Secrets কখনো frontend-এ রাখবেন না।

Admin URL:
https://YOUR-DOMAIN.COM/admin.html
