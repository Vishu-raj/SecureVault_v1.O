
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const { body, validationResult } = require("express-validator");
const Database = require("better-sqlite3"); // parameterized queries → no SQL injection

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "replace-with-256bit-random-secret";
const JWT_EXPIRES_IN = "1h";
const BCRYPT_ROUNDS = 12;

// ─── App ─────────────────────────────────────────────────────────────────────
const app = express();

// ─── Security Middleware (OWASP A05 – Misconfiguration) ──────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

// ─── CORS (whitelist only) ───────────────────────────────────────────────────
const ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:5173", "https://yourdomain.com"];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
    else cb(new Error("CORS policy violation"));
  },
  credentials: true,
}));

app.use(express.json({ limit: "10kb" })); // prevent large payload attacks

// ─── Rate Limiting (OWASP A07 – Auth Failures) ───────────────────────────────
const authLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 5,                // 5 login attempts
  message: { error: "Too many requests. Try again in 1 minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
});

app.use(generalLimiter);

// ─── SQLite DB (parameterized queries → SQL injection prevention) ─────────────
const db = new Database(":memory:"); // use a file path in production

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    UNIQUE NOT NULL,
    email     TEXT    UNIQUE NOT NULL,
    password  TEXT    NOT NULL,
    role      TEXT    NOT NULL DEFAULT 'viewer',
    status    TEXT    NOT NULL DEFAULT 'Active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token_hash TEXT    NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT NOT NULL,
    detail     TEXT,
    ip         TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed an admin user
const seedAdmin = async () => {
  const hashed = await bcrypt.hash("Admin@123", BCRYPT_ROUNDS);
  db.prepare(`
    INSERT OR IGNORE INTO users (username, email, password, role, status)
    VALUES (?, ?, ?, ?, ?)
  `).run("admin", "admin@example.com", hashed, "admin", "Active");
};
seedAdmin();

// ─── Payload Detection Engine (SQL Injection / XSS) ──────────────────────────
const ATTACK_PATTERNS = [
  // AUTH BYPASS
  { pattern: /OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /OR\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?\s*--/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /OR\s+\d+-\d+--/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /'\s*OR\s+/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /"\s*OR\s+/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /OR\s+["']1["']\s*=\s*["']1/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /1\s*=\s*1/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /LIMIT\s+\d/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /'\s*or\s+\d+-\d+--/i, type: "SQL Injection — Auth Bypass" },

  // UNION ATTACKS
  { pattern: /UNION\s+(ALL\s+)?SELECT/i, type: "SQL Injection — UNION Attack" },
  { pattern: /@@version/i, type: "SQL Injection — UNION Data Extraction" },
  { pattern: /database\s*\(\s*\)/i, type: "SQL Injection — UNION Data Extraction" },
  { pattern: /user\s*\(\s*\)/i, type: "SQL Injection — UNION Data Extraction" },

  // COMMENT INJECTION
  { pattern: /\/\*.*\*\//i, type: "SQL Injection — Comment Bypass" },
  { pattern: /--\s*$/m, type: "SQL Injection — Comment Injection" },
  { pattern: /%00/i, type: "SQL Injection — Null Byte Injection" },

  // DATA EXTRACTION
  { pattern: /AND\s+\d+-\d+--/i, type: "SQL Injection — Data Extraction" },
  { pattern: /SELECT\s+count\s*\(\s*\*\s*\)/i, type: "SQL Injection — Data Extraction" },
  { pattern: /Length\s*\(\s*database\s*\(\s*\)\s*\)/i, type: "SQL Injection — Data Extraction" },
  { pattern: /substring\s*\(/i, type: "SQL Injection — Data Extraction" },
  { pattern: /ord\s*\(\s*substring/i, type: "SQL Injection — Data Extraction" },

  // TIME-BASED
  { pattern: /SLEEP\s*\(/i, type: "SQL Injection — Time-Based Blind" },
  { pattern: /BENCHMARK\s*\(/i, type: "SQL Injection — Time-Based Blind" },
  { pattern: /pg_sleep\s*\(/i, type: "SQL Injection — Time-Based Blind" },
  { pattern: /WAITFOR\s+DELAY/i, type: "SQL Injection — Time-Based Blind" },

  // XSS
  { pattern: /<\s*script/i, type: "XSS — Script Injection" },
  { pattern: /on(error|load|click|mouseover)\s*=/i, type: "XSS — Event Handler Injection" },
  { pattern: /javascript\s*:/i, type: "XSS — Protocol Injection" },
  { pattern: /eval\s*\(/i, type: "XSS — Eval Injection" },
  { pattern: /<\s*img[^>]+onerror/i, type: "XSS — IMG Tag Injection" },
  { pattern: /<\s*iframe/i, type: "XSS — IFrame Injection" },
  { pattern: /<\s*svg[^>]+onload/i, type: "XSS — SVG Injection" },

  // GENERAL INJECTION
  { pattern: /;\s*DROP\s+TABLE/i, type: "SQL Injection — DROP TABLE" },
  { pattern: /;\s*DELETE\s+FROM/i, type: "SQL Injection — DELETE" },
  { pattern: /;\s*INSERT\s+INTO/i, type: "SQL Injection — INSERT" },
  { pattern: /;\s*UPDATE\s+.*SET/i, type: "SQL Injection — UPDATE" },
  { pattern: /EXEC\s*\(/i, type: "SQL Injection — Stored Procedure" },
  { pattern: /xp_cmdshell/i, type: "SQL Injection — Command Execution" },
];

/**
 * Scans a single value for attack patterns.
 * Returns { detected: true, type: "..." } or { detected: false }
 */
const detectPayload = (value) => {
  if (typeof value !== "string") return { detected: false };
  for (const { pattern, type } of ATTACK_PATTERNS) {
    if (pattern.test(value)) {
      return { detected: true, type, payload: value };
    }
  }
  return { detected: false };
};

/**
 * Recursively scans all values in an object.
 */
const scanObject = (obj) => {
  if (!obj || typeof obj !== "object") return null;
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === "string") {
      const result = detectPayload(val);
      if (result.detected) return { ...result, field: key };
    } else if (typeof val === "object") {
      const result = scanObject(val);
      if (result) return result;
    }
  }
  return null;
};

// ─── Payload Guard Middleware ─────────────────────────────────────────────────
const payloadGuard = (req, res, next) => {
  // Scan body
  const bodyResult = scanObject(req.body);
  if (bodyResult) {
    auditLog(null, `ATTACK_BLOCKED:${bodyResult.type}`, req.ip, bodyResult.payload);
    return res.status(400).json({
      error: "⚠ Security Alert: Potential injection attack detected!",
      attackType: bodyResult.type,
      field: bodyResult.field,
      blocked: true,
      message: "This incident has been logged and reported.",
    });
  }

  // Scan query params
  const queryResult = scanObject(req.query);
  if (queryResult) {
    auditLog(null, `ATTACK_BLOCKED:${queryResult.type}`, req.ip, queryResult.payload);
    return res.status(400).json({
      error: "⚠ Security Alert: Potential injection attack detected!",
      attackType: queryResult.type,
      field: queryResult.field,
      blocked: true,
      message: "This incident has been logged and reported.",
    });
  }

  // Scan URL params
  const paramResult = scanObject(req.params);
  if (paramResult) {
    auditLog(null, `ATTACK_BLOCKED:${paramResult.type}`, req.ip, paramResult.payload);
    return res.status(400).json({
      error: "⚠ Security Alert: Potential injection attack detected!",
      attackType: paramResult.type,
      field: paramResult.field,
      blocked: true,
      message: "This incident has been logged and reported.",
    });
  }

  next();
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
const auditLog = (userId, action, ip, detail = null) => {
  db.prepare("INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)")
    .run(userId, action, detail, ip);
};

// ─── JWT Middleware ───────────────────────────────────────────────────────────
const authenticate = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

// ─── RBAC Middleware ──────────────────────────────────────────────────────────
const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) {
    return res.status(403).json({ error: "Insufficient permissions" });
  }
  next();
};

// ─── Routes ──────────────────────────────────────────────────────────────────

// POST /auth/register — with payload guard
app.post("/auth/register", authLimiter, payloadGuard, [
  body("username")
    .trim()
    .isAlphanumeric().withMessage("Username must be alphanumeric")
    .isLength({ min: 3, max: 30 }).withMessage("Username 3–30 chars"),
  body("email")
    .normalizeEmail()
    .isEmail().withMessage("Invalid email"),
  body("password")
    .isStrongPassword({
      minLength: 8, minUppercase: 1, minLowercase: 1,
      minNumbers: 1, minSymbols: 1,
    }).withMessage("Password not strong enough"),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    // Parameterized query — safe from SQL injection
    db.prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
      .run(username, email, hashed);

    auditLog(null, `REGISTER:${username}`, req.ip);
    res.status(201).json({ message: "Account created" });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Registration failed" });
  }
});

// POST /auth/login — with payload guard
app.post("/auth/login", authLimiter, payloadGuard, [
  body("username").trim().notEmpty(),
  body("password").notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid input" });

  const { username, password } = req.body;
  // Parameterized query — safe from SQL injection
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    auditLog(user?.id || null, `FAILED_LOGIN:${username}`, req.ip);
    // Consistent response time prevents timing attacks
    await bcrypt.hash("dummy", BCRYPT_ROUNDS); // dummy work
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { sub: user.username, role: user.role, id: user.id },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN, algorithm: "HS256" }
  );

  auditLog(user.id, "LOGIN_SUCCESS", req.ip);
  res.json({ token, role: user.role });
});

// GET /auth/oauth/google — OAuth 2.0 redirect (stub)
app.get("/auth/oauth/google", (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: `${process.env.APP_URL}/auth/oauth/google/callback`,
    response_type: "code",
    scope: "openid email profile",
    state: Math.random().toString(36).slice(2), // CSRF token
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// GET /users — protected, admin only
app.get("/users", authenticate, requireRole("admin"), (req, res) => {
  // Never return passwords — SELECT specific columns only
  const users = db.prepare(
    "SELECT id, username, email, role, status, created_at FROM users ORDER BY id"
  ).all();
  res.json({ users });
});

// POST /users — admin only, create a new user (with payload guard)
app.post("/users", authenticate, requireRole("admin"), payloadGuard, [
  body("username")
    .trim()
    .isAlphanumeric().withMessage("Username must be alphanumeric")
    .isLength({ min: 3, max: 30 }).withMessage("Username 3–30 chars"),
  body("email")
    .normalizeEmail()
    .isEmail().withMessage("Invalid email"),
  body("password")
    .isStrongPassword({
      minLength: 8, minUppercase: 1, minLowercase: 1,
      minNumbers: 1, minSymbols: 1,
    }).withMessage("Password not strong enough"),
  body("role")
    .isIn(["admin", "editor", "viewer"]).withMessage("Role must be admin, editor, or viewer"),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password, role } = req.body;
  try {
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = db.prepare(
      "INSERT INTO users (username, email, password, role, status) VALUES (?, ?, ?, ?, ?)"
    ).run(username, email, hashed, role, "Active");

    auditLog(req.user.id, `CREATE_USER:${username}:${role}`, req.ip);
    res.status(201).json({
      message: "User created successfully",
      user: { id: result.lastInsertRowid, username, email, role, status: "Active" },
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "User creation failed" });
  }
});

// PUT /users/:id — admin only, update a user (with payload guard)
app.put("/users/:id", authenticate, requireRole("admin"), payloadGuard, [
  body("username")
    .optional()
    .trim()
    .isAlphanumeric().withMessage("Username must be alphanumeric")
    .isLength({ min: 3, max: 30 }).withMessage("Username 3–30 chars"),
  body("email")
    .optional()
    .normalizeEmail()
    .isEmail().withMessage("Invalid email"),
  body("role")
    .optional()
    .isIn(["admin", "editor", "viewer"]).withMessage("Role must be admin, editor, or viewer"),
  body("status")
    .optional()
    .isIn(["Active", "Inactive"]).withMessage("Status must be Active or Inactive"),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) return res.status(400).json({ error: "Invalid user ID" });

  const existing = db.prepare("SELECT id FROM users WHERE id = ?").get(userId);
  if (!existing) return res.status(404).json({ error: "User not found" });

  const { username, email, role, status } = req.body;
  const updates = [];
  const values = [];

  if (username) { updates.push("username = ?"); values.push(username); }
  if (email) { updates.push("email = ?"); values.push(email); }
  if (role) { updates.push("role = ?"); values.push(role); }
  if (status) { updates.push("status = ?"); values.push(status); }

  if (updates.length === 0) return res.status(400).json({ error: "No fields to update" });

  values.push(userId);
  try {
    db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).run(...values);
    auditLog(req.user.id, `UPDATE_USER:${userId}`, req.ip);

    const updated = db.prepare(
      "SELECT id, username, email, role, status, created_at FROM users WHERE id = ?"
    ).get(userId);
    res.json({ message: "User updated successfully", user: updated });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Update failed" });
  }
});

// GET /users/search — admin only, search users (with payload guard)
app.get("/users/search", authenticate, requireRole("admin"), payloadGuard, (req, res) => {
  const { q } = req.query;
  if (!q || q.trim().length === 0) {
    const users = db.prepare(
      "SELECT id, username, email, role, status, created_at FROM users ORDER BY id"
    ).all();
    return res.json({ users });
  }

  // Parameterized LIKE query — safe from SQL injection
  const searchTerm = `%${q.trim()}%`;
  const users = db.prepare(
    "SELECT id, username, email, role, status, created_at FROM users WHERE username LIKE ? OR email LIKE ? OR role LIKE ? ORDER BY id"
  ).all(searchTerm, searchTerm, searchTerm);

  auditLog(req.user.id, `SEARCH_USERS:${q}`, req.ip);
  res.json({ users });
});

// GET /me — protected
app.get("/me", authenticate, (req, res) => {
  const user = db.prepare(
    "SELECT id, username, email, role FROM users WHERE id = ?"
  ).get(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user });
});

// GET /audit — admin only
app.get("/audit", authenticate, requireRole("admin"), (req, res) => {
  const logs = db.prepare(
    "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100"
  ).all();
  res.json({ logs });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  // Never leak stack traces to clients (OWASP A05)
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: "Not found" }));

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅  Secure server running on port ${PORT}`));

module.exports = app;