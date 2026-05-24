import { Hono } from "hono";
import { cors } from "hono/cors";
import { sign, verify } from "hono/jwt";
import bcrypt from "bcryptjs";

const app = new Hono();
const BCRYPT_ROUNDS = 10;
const JWT_EXPIRES_IN = 3600;

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use("*", cors({
  origin: (origin) => origin || "*",
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

// ─── Payload Detection Engine (SQL Injection / XSS) ──────────────────────────
const ATTACK_PATTERNS = [
  { pattern: /OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /OR\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?\s*--/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /OR\s+\d+-\d+--/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /'\s*OR\s+/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /"\s*OR\s+/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /1\s*=\s*1/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /LIMIT\s+\d/i, type: "SQL Injection — Auth Bypass" },
  { pattern: /UNION\s+(ALL\s+)?SELECT/i, type: "SQL Injection — UNION Attack" },
  { pattern: /@@version/i, type: "SQL Injection — Data Extraction" },
  { pattern: /database\s*\(\s*\)/i, type: "SQL Injection — Data Extraction" },
  { pattern: /user\s*\(\s*\)/i, type: "SQL Injection — Data Extraction" },
  { pattern: /\/\*.*\*\//i, type: "SQL Injection — Comment Bypass" },
  { pattern: /--\s*$/m, type: "SQL Injection — Comment Injection" },
  { pattern: /%00/i, type: "Null Byte Injection" },
  { pattern: /AND\s+\d+-\d+--/i, type: "SQL Injection — Data Extraction" },
  { pattern: /SELECT\s+count\s*\(\s*\*\s*\)/i, type: "SQL Injection — Data Extraction" },
  { pattern: /substring\s*\(/i, type: "SQL Injection — Data Extraction" },
  { pattern: /SLEEP\s*\(/i, type: "SQL Injection — Time-Based" },
  { pattern: /BENCHMARK\s*\(/i, type: "SQL Injection — Time-Based" },
  { pattern: /WAITFOR\s+DELAY/i, type: "SQL Injection — Time-Based" },
  { pattern: /<\s*script/i, type: "XSS — Script Injection" },
  { pattern: /on(error|load|click|mouseover)\s*=/i, type: "XSS — Event Handler Injection" },
  { pattern: /javascript\s*:/i, type: "XSS — Protocol Injection" },
  { pattern: /eval\s*\(/i, type: "XSS — Eval Injection" },
  { pattern: /<\s*iframe/i, type: "XSS — IFrame Injection" },
  { pattern: /;\s*DROP\s+TABLE/i, type: "SQL Injection — DROP TABLE" },
  { pattern: /;\s*DELETE\s+FROM/i, type: "SQL Injection — DELETE" },
  { pattern: /xp_cmdshell/i, type: "SQL Injection — Command Execution" },
];

const scanObject = (obj) => {
  if (!obj || typeof obj !== "object") return null;
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === "string") {
      for (const { pattern, type } of ATTACK_PATTERNS) {
        if (pattern.test(val)) return { type, field: key, payload: val };
      }
    }
  }
  return null;
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
const getIP = (c) => c.req.header("cf-connecting-ip") || "unknown";

const auditLog = async (db, userId, action, ip, detail = null) => {
  await db.prepare("INSERT INTO audit_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)")
    .bind(userId, action, detail, ip).run();
};

const isAlphanumeric = (s) => /^[a-zA-Z0-9]+$/.test(s);
const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const isStrongPassword = (s) =>
  s.length >= 8 && /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s) && /[!@#$%^&*]/.test(s);

// ─── Seed Admin (runs once per Worker instance) ──────────────────────────────
let seeded = false;
app.use("*", async (c, next) => {
  if (!seeded) {
    const db = c.env.DB;
    const existing = await db.prepare("SELECT id FROM users WHERE username = ?").bind("admin").first();
    if (!existing) {
      const hash = await bcrypt.hash("Admin@123", BCRYPT_ROUNDS);
      await db.prepare("INSERT INTO users (username, email, password, role, status) VALUES (?, ?, ?, ?, ?)")
        .bind("admin", "admin@example.com", hash, "admin", "Active").run();
    }
    seeded = true;
  }
  await next();
});

// ─── Auth Middleware ─────────────────────────────────────────────────────────
const authenticate = async (c, next) => {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) return c.json({ error: "Missing token" }, 401);
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET);
    c.set("user", payload);
    await next();
  } catch {
    return c.json({ error: "Invalid or expired token" }, 401);
  }
};

const requireRole = (...roles) => async (c, next) => {
  const user = c.get("user");
  if (!roles.includes(user?.role)) return c.json({ error: "Insufficient permissions" }, 403);
  await next();
};

// ─── Rate Limiter (per Worker instance) ──────────────────────────────────────
const rateLimitMap = new Map();
const rateLimit = (max, windowMs) => async (c, next) => {
  const ip = getIP(c);
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.start > windowMs) {
    rateLimitMap.set(ip, { count: 1, start: now });
  } else {
    entry.count++;
    if (entry.count > max) {
      return c.json({ error: "Too many requests. Try again in 1 minute." }, 429);
    }
  }
  await next();
};

const authLimiter = rateLimit(10, 60000);

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// POST /auth/register
app.post("/auth/register", authLimiter, async (c) => {
  const body = await c.req.json();
  const { username, email, password } = body;

  const threat = scanObject({ username, email });
  if (threat) {
    await auditLog(c.env.DB, null, `ATTACK_BLOCKED:${threat.type}`, getIP(c), threat.payload);
    return c.json({ error: "Security alert", attackType: threat.type, blocked: true }, 400);
  }

  const errors = [];
  if (!username || !isAlphanumeric(username) || username.length < 3 || username.length > 30)
    errors.push({ msg: "Username must be alphanumeric, 3–30 chars" });
  if (!email || !isEmail(email))
    errors.push({ msg: "Invalid email" });
  if (!password || !isStrongPassword(password))
    errors.push({ msg: "Password not strong enough (8+ chars, upper, lower, number, symbol)" });
  if (errors.length) return c.json({ errors }, 400);

  try {
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await c.env.DB.prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
      .bind(username, email.toLowerCase(), hashed).run();
    await auditLog(c.env.DB, null, `REGISTER:${username}`, getIP(c));
    return c.json({ message: "Account created" }, 201);
  } catch (err) {
    if (err.message?.includes("UNIQUE")) return c.json({ error: "Username or email already exists" }, 409);
    return c.json({ error: "Registration failed" }, 500);
  }
});

// POST /auth/login
app.post("/auth/login", authLimiter, async (c) => {
  const body = await c.req.json();
  const { username, password } = body;

  const threat = scanObject({ username });
  if (threat) return c.json({ error: "Security alert", attackType: threat.type, blocked: true }, 400);
  if (!username || !password) return c.json({ error: "Invalid input" }, 400);

  const user = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  if (!user || !(await bcrypt.compare(password, user.password))) {
    await auditLog(c.env.DB, user?.id || null, `FAILED_LOGIN:${username}`, getIP(c));
    return c.json({ error: "Invalid credentials" }, 401);
  }

  const token = await sign(
    { sub: user.username, role: user.role, id: user.id, exp: Math.floor(Date.now() / 1000) + JWT_EXPIRES_IN },
    c.env.JWT_SECRET
  );
  await auditLog(c.env.DB, user.id, "LOGIN_SUCCESS", getIP(c));
  return c.json({ token, role: user.role });
});

// GET /users — admin only
app.get("/users", authenticate, requireRole("admin"), async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, username, email, role, status, created_at FROM users ORDER BY id"
  ).all();
  return c.json({ users: results });
});

// POST /users — admin only, create user
app.post("/users", authenticate, requireRole("admin"), async (c) => {
  const body = await c.req.json();
  const { username, email, password, role } = body;

  const threat = scanObject({ username, email });
  if (threat) return c.json({ error: "Security alert", attackType: threat.type, blocked: true }, 400);

  const errors = [];
  if (!username || !isAlphanumeric(username) || username.length < 3) errors.push({ msg: "Invalid username" });
  if (!email || !isEmail(email)) errors.push({ msg: "Invalid email" });
  if (!password || !isStrongPassword(password)) errors.push({ msg: "Weak password" });
  if (!["admin", "editor", "viewer"].includes(role)) errors.push({ msg: "Invalid role" });
  if (errors.length) return c.json({ errors }, 400);

  try {
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await c.env.DB.prepare(
      "INSERT INTO users (username, email, password, role, status) VALUES (?, ?, ?, ?, ?)"
    ).bind(username, email.toLowerCase(), hashed, role, "Active").run();

    await auditLog(c.env.DB, c.get("user").id, `CREATE_USER:${username}:${role}`, getIP(c));
    return c.json({
      message: "User created successfully",
      user: { id: result.meta.last_row_id, username, email, role, status: "Active" },
    }, 201);
  } catch (err) {
    if (err.message?.includes("UNIQUE")) return c.json({ error: "Username or email already exists" }, 409);
    return c.json({ error: "User creation failed" }, 500);
  }
});

// PUT /users/:id — admin only, update user
app.put("/users/:id", authenticate, requireRole("admin"), async (c) => {
  const userId = parseInt(c.req.param("id"), 10);
  if (isNaN(userId)) return c.json({ error: "Invalid user ID" }, 400);

  const body = await c.req.json();
  const threat = scanObject(body);
  if (threat) return c.json({ error: "Security alert", attackType: threat.type, blocked: true }, 400);

  const existing = await c.env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(userId).first();
  if (!existing) return c.json({ error: "User not found" }, 404);

  const { username, email, role, status } = body;
  const updates = [];
  const values = [];

  if (username) { updates.push("username = ?"); values.push(username); }
  if (email) { updates.push("email = ?"); values.push(email.toLowerCase()); }
  if (role && ["admin", "editor", "viewer"].includes(role)) { updates.push("role = ?"); values.push(role); }
  if (status && ["Active", "Inactive"].includes(status)) { updates.push("status = ?"); values.push(status); }
  if (!updates.length) return c.json({ error: "No fields to update" }, 400);

  values.push(userId);
  try {
    await c.env.DB.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).bind(...values).run();
    await auditLog(c.env.DB, c.get("user").id, `UPDATE_USER:${userId}`, getIP(c));
    const updated = await c.env.DB.prepare(
      "SELECT id, username, email, role, status, created_at FROM users WHERE id = ?"
    ).bind(userId).first();
    return c.json({ message: "User updated successfully", user: updated });
  } catch (err) {
    if (err.message?.includes("UNIQUE")) return c.json({ error: "Username or email already exists" }, 409);
    return c.json({ error: "Update failed" }, 500);
  }
});

// GET /users/search — admin only
app.get("/users/search", authenticate, requireRole("admin"), async (c) => {
  const q = c.req.query("q");
  if (!q || !q.trim()) {
    const { results } = await c.env.DB.prepare(
      "SELECT id, username, email, role, status, created_at FROM users ORDER BY id"
    ).all();
    return c.json({ users: results });
  }

  const threat = scanObject({ q });
  if (threat) return c.json({ error: "Security alert", attackType: threat.type, blocked: true }, 400);

  const term = `%${q.trim()}%`;
  const { results } = await c.env.DB.prepare(
    "SELECT id, username, email, role, status, created_at FROM users WHERE username LIKE ? OR email LIKE ? OR role LIKE ? ORDER BY id"
  ).bind(term, term, term).all();
  await auditLog(c.env.DB, c.get("user").id, `SEARCH_USERS:${q}`, getIP(c));
  return c.json({ users: results });
});

// GET /me — protected
app.get("/me", authenticate, async (c) => {
  const u = c.get("user");
  const user = await c.env.DB.prepare(
    "SELECT id, username, email, role FROM users WHERE id = ?"
  ).bind(u.id).first();
  if (!user) return c.json({ error: "User not found" }, 404);
  return c.json({ user });
});

// GET /audit — admin only
app.get("/audit", authenticate, requireRole("admin"), async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100"
  ).all();
  return c.json({ logs: results });
});

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.all("*", (c) => c.json({ error: "Not found" }, 404));

export default app;
