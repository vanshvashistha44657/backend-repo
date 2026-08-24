const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, message: "Backend is healthy" });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/alerts", async (req, res) => {
  const result = await pool.query(`
    SELECT * FROM alerts
    ORDER BY created_at DESC
  `);
  res.json(result.rows);
});

app.get("/incidents", async (req, res) => {
  const result = await pool.query(`
    SELECT * FROM incidents
    ORDER BY created_at DESC
  `);
  res.json(result.rows);
});

app.get("/assets", async (req, res) => {
  const result = await pool.query(`
    SELECT * FROM assets
    ORDER BY created_at DESC
  `);
  res.json(result.rows);
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1 LIMIT 1",
    [email]
  );

  if (result.rows.length === 0) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  return res.json({
    token: "demo-token-for-now",
    user: result.rows[0],
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});