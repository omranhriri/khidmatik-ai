const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "khidmatik.db");

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-this-password";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret";

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  service TEXT NOT NULL,
  details TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'new',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

function makeCode() {
  return "KH-" + Date.now().toString(36).toUpperCase() + "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase();
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function adminToken() {
  const payload = Buffer.from(JSON.stringify({
    u: ADMIN_USER,
    t: Date.now()
  })).toString("base64url");
  return payload + "." + sign(payload);
}

function isAdmin(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  const [payload, sig] = token.split(".");
  if (!payload || !sig || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(payload)))) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    return data.u === ADMIN_USER && Date.now() - data.t < 7 * 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

app.post("/api/orders", (req, res) => {
  const { name, phone, service, details = "" } = req.body || {};
  if (!name || !phone || !service) {
    return res.status(400).json({ error: "الاسم والهاتف والخدمة مطلوبة." });
  }
  let code;
  for (let i = 0; i < 5; i++) {
    code = makeCode();
    try {
      db.prepare(`
        INSERT INTO orders (code, name, phone, service, details)
        VALUES (?, ?, ?, ?, ?)
      `).run(code, String(name).trim(), String(phone).trim(), String(service).trim(), String(details).trim());
      break;
    } catch (e) {
      if (i === 4) return res.status(500).json({ error: "تعذر إنشاء الطلب." });
    }
  }
  res.status(201).json({ code });
});

app.get("/api/orders/:code", (req, res) => {
  const order = db.prepare(`
    SELECT code, name, service, details, status, created_at
    FROM orders WHERE code = ?
  `).get(req.params.code);
  if (!order) return res.status(404).json({ error: "الطلب غير موجود." });
  res.json(order);
});

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
    return res.json({ token: adminToken() });
  }
  res.status(401).json({ error: "بيانات الدخول غير صحيحة." });
});

app.get("/api/admin/orders", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: "غير مصرح." });
  const orders = db.prepare(`SELECT * FROM orders ORDER BY id DESC`).all();
  res.json(orders);
});

app.patch("/api/admin/orders/:id", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: "غير مصرح." });
  const allowed = new Set(["new", "in_progress", "completed"]);
  const { status } = req.body || {};
  if (!allowed.has(status)) return res.status(400).json({ error: "حالة غير صحيحة." });
  const result = db.prepare(`UPDATE orders SET status = ? WHERE id = ?`).run(status, req.params.id);
  if (!result.changes) return res.status(404).json({ error: "الطلب غير موجود." });
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, HOST, () => {
  console.log(`Khidmatik AI running on ${HOST}:${PORT}`);
});
