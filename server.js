const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET is not configured.");
  process.exit(1);
}

const allowedOrigins = (process.env.FRONTEND_URLS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Allow server-to-server tools/curl and local development.
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("CORS origin not allowed"));
    },
    credentials: true,
  })
);

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : undefined,
});

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    approved: user.approved,
    created_at: user.created_at,
  };
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Authentication required" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL DEFAULT '',
      email text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      role text NOT NULL DEFAULT 'user',
      approved boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS approved boolean NOT NULL DEFAULT false
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT ''
  `);

  // Keep the extension available for UUID generation on standard Supabase Postgres.
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "SentinelOps backend is running",
    health: "/health",
  });
});

app.get("/health", async (req, res) => {
  if (!process.env.DATABASE_URL) {
    return res.status(500).json({
      ok: false,
      error: "DATABASE_URL is not configured",
    });
  }

  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      message: "Backend and database are healthy",
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: "Database connection failed",
    });
  }
});

app.get("/alerts", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM alerts
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/incidents", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM incidents
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/assets", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM assets
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Register a new user. New accounts require admin approval.
app.post("/auth/register", async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  if (password.length < 8) {
    return res.status(400).json({
      message: "Password must be at least 8 characters",
    });
  }

  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Account already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, approved)
       VALUES ($1, $2, $3, 'user', false)
       RETURNING id, name, email, role, approved, created_at`,
      [name, email, passwordHash]
    );

    return res.status(201).json({
      message: "Account created. Waiting for admin approval.",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Unable to create account" });
  }
});

app.post("/auth/login", async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const result = await pool.query(
      `SELECT id, name, email, password_hash, role, approved, created_at
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.approved && user.role !== "admin") {
      return res.status(403).json({
        message: "Account is awaiting admin approval",
        code: "ACCOUNT_PENDING",
      });
    }

    const token = signToken(user);

    return res.json({
      token,
      user: publicUser(user),
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Login failed" });
  }
});

app.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, approved, created_at
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [req.user.sub]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "User no longer exists" });
    }

    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    res.status(500).json({ message: "Unable to load user" });
  }
});

// Admin: list users waiting for approval.
app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, email, role, approved, created_at
      FROM users
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Unable to load users" });
  }
});

// Admin: approve an account.
app.patch("/admin/users/:id/approve", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users
       SET approved = true
       WHERE id = $1
       RETURNING id, name, email, role, approved, created_at`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      message: "User approved",
      user: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ message: "Unable to approve user" });
  }
});


async function bootstrapAdminFromEnv(prefix) {
  const name = String(process.env[`${prefix}_NAME`] || "").trim();
  const email = String(process.env[`${prefix}_EMAIL`] || "").trim().toLowerCase();
  const password = String(process.env[`${prefix}_PASSWORD`] || "");

  // If none of the variables are configured, do nothing.
  if (!name && !email && !password) return;

  if (!name || !email || !password) {
    throw new Error(`${prefix}_NAME, ${prefix}_EMAIL and ${prefix}_PASSWORD must all be set`);
  }

  if (password.length < 8) {
    throw new Error(`${prefix}_PASSWORD must be at least 8 characters`);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await pool.query(
    `INSERT INTO users (name, email, password_hash, role, approved)
     VALUES ($1, $2, $3, 'admin', true)
     ON CONFLICT (email)
     DO UPDATE SET
       name = EXCLUDED.name,
       password_hash = EXCLUDED.password_hash,
       role = 'admin',
       approved = true`,
    [name, email, passwordHash]
  );

  console.log(`Admin account ready: ${email}`);
}

async function start() {
  try {
    await ensureSchema();
    await bootstrapAdminFromEnv("ADMIN1");
    await bootstrapAdminFromEnv("ADMIN2");
    console.log("Database schema ready.");
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (err) {
    console.error("Database initialization failed:", err);
    process.exit(1);
  }
}

start();
