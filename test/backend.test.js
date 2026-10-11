const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const request = require("supertest");
const WebSocket = require("ws");
const { mailConfiguration } = require("../lib/mailer");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "test-only-secret";
const { app, pool, applyMigrations, __private } = require("../server");
const { setTestSender } = require("../lib/mailer");

let testUser;
let accessToken;
let refreshCookie;
const testPassword = process.env.TEST_ACCOUNT_PASSWORD;
const resetPassword = process.env.TEST_RESET_PASSWORD;
const demoSeedPassword = process.env.DEMO_SEED_PASSWORD;

test.before(async () => {
  if (!testPassword || !resetPassword || !demoSeedPassword) throw new Error("TEST_ACCOUNT_PASSWORD, TEST_RESET_PASSWORD and DEMO_SEED_PASSWORD must be supplied through the local test environment");
  await applyMigrations(pool);
  const passwordHash = await bcrypt.hash(testPassword, 4);
  const result = await pool.query("INSERT INTO users(name,email,password_hash,role,approved) VALUES($1,$2,$3,'admin',true) RETURNING *", ["Isolated Admin", "isolated-admin@example.test", passwordHash]);
  testUser = result.rows[0];
});

test.after(async () => {
  setTestSender(null);
  await pool.end();
});

test("migrations preserve existing user records and password hashes", async () => {
  const before = await pool.query("SELECT password_hash,role,approved FROM users WHERE id=$1", [testUser.id]);
  await applyMigrations(pool);
  const after = await pool.query("SELECT password_hash,role,approved FROM users WHERE id=$1", [testUser.id]);
  assert.deepEqual(after.rows[0], before.rows[0]);
});

test("SMTP configuration health exposes status without secret values", () => {
  const configured = mailConfiguration({ SMTP_HOST: "smtp.test", SMTP_PORT: "587", SMTP_USER: "user", SMTP_PASSWORD: "secret", MAIL_FROM: "soc@test", PASSWORD_RESET_ORIGIN: "https://app.test" });
  assert.equal(configured.configured, true);
  assert.deepEqual(Object.keys(configured).sort(), ["configured", "required"]);
  assert.equal(JSON.stringify(configured).includes("secret"), false);
});

test("login creates a persisted session and logout revokes it", async () => {
  const login = await request(app).post("/auth/login").send({ email: testUser.email, password: testPassword, remember: true }).expect(200);
  accessToken = login.body.token;
  refreshCookie = login.headers["set-cookie"][0];
  assert.ok(accessToken);
  const sessions = await request(app).get("/auth/sessions").set("Authorization", `Bearer ${accessToken}`).expect(200);
  assert.equal(sessions.body.length, 1);
  assert.equal(sessions.body[0].email, testUser.email);
  await request(app).post("/auth/heartbeat").set("Authorization", `Bearer ${accessToken}`).expect(200);
  await request(app).post("/auth/logout").set("Authorization", `Bearer ${accessToken}`).set("Cookie", refreshCookie).expect(200);
  await request(app).get("/auth/me").set("Authorization", `Bearer ${accessToken}`).expect(401);
  const persisted = await pool.query("SELECT status FROM sessions WHERE user_id=$1", [testUser.id]);
  assert.equal(persisted.rows[0].status, "revoked");
});

test("refresh rotates the refresh token", async () => {
  const login = await request(app).post("/auth/login").send({ email: testUser.email, password: testPassword }).expect(200);
  const firstCookie = login.headers["set-cookie"][0].split(";")[0];
  const rawRefresh = firstCookie.split("=")[1];
  const refreshed = await request(app).post("/auth/refresh").send({ refresh_token: rawRefresh }).expect(200);
  assert.ok(refreshed.body.token);
  assert.notEqual(refreshed.headers["set-cookie"][0], firstCookie);
  const active = await pool.query("SELECT count(*)::int AS count FROM sessions WHERE status='active' AND refresh_token_hash IS NOT NULL");
  assert.equal(active.rows[0].count, 1);
  const current = await pool.query("SELECT refresh_token_hash FROM sessions WHERE status='active'");
  assert.notEqual(current.rows[0].refresh_token_hash, __private.idHash(rawRefresh));
  const oldRefresh = await request(app).post("/auth/refresh").send({ refresh_token: rawRefresh });
  assert.equal(oldRefresh.status, 401, `old refresh unexpectedly returned ${oldRefresh.status}`);
});

test("password reset uses a local mail transport, expires after use, and revokes sessions", async () => {
  let message;
  setTestSender(async (next) => { message = next; });
  await request(app).post("/auth/forgot-password").send({ email: testUser.email }).expect(202);
  assert.match(message.text, /reset-password\?token=/);
  const token = new URL(message.text.match(/https?:\/\/\S+|\/reset-password\?token=\S+/)[0], "http://localhost").searchParams.get("token");
  await request(app).post("/auth/reset-password").send({ token, password: resetPassword }).expect(200);
  await request(app).post("/auth/reset-password").send({ token, password: resetPassword }).expect(400);
  await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
});

test("notifications are user-scoped and deduplicated", async () => {
  const first = await __private.notify(testUser.id, { title: "Demo event", body: "One event", severity: "low", category: "system", eventKey: "test-event-1" });
  const second = await __private.notify(testUser.id, { title: "Demo event", body: "One event", severity: "low", category: "system", eventKey: "test-event-1" });
  assert.ok(first);
  assert.equal(second, null);
  const login = await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
  const notifications = await request(app).get("/notifications").set("Authorization", `Bearer ${login.body.token}`).expect(200);
  assert.equal(notifications.body.filter((item) => item.id === String(first.id)).length, 1);
  await request(app).post(`/notifications/${first.id}/read`).set("Authorization", `Bearer ${login.body.token}`).expect(200);
  const read = await pool.query("SELECT read FROM notifications WHERE id=$1", [first.id]);
  assert.equal(read.rows[0].read, true);
});

test("resource endpoints return the existing frontend contract", async () => {
  const record = await __private.putRecord("alert", "contract-alert-1", { id: "contract-alert-1", title: "Contract alert", severity: "medium", status: "new", timestamp: new Date().toISOString(), notes: [], timeline: [] });
  const login = await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
  const auth = { Authorization: `Bearer ${login.body.token}` };
  const alerts = await request(app).get("/alerts").set(auth).expect(200);
  assert.equal(alerts.body.items[0].id, record.id);
  await request(app).get("/dashboard/metrics").set(auth).expect(200);
  await request(app).get("/system/health").set(auth).expect(200);
  await request(app).get("/admin/stats").set(auth).expect(200);
  await request(app).get("/alerts").expect(401);
});

test("authenticated websocket connections receive server events", async () => {
  const server = await require("../server").start(0);
  try {
    const login = await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
    const address = server.address();
    const socket = new WebSocket(`ws://127.0.0.1:${address.port}/ws?token=${encodeURIComponent(login.body.token)}`);
    const message = await new Promise((resolve, reject) => {
      socket.once("open", () => socket.send("ping"));
      socket.once("message", (value) => resolve(JSON.parse(value.toString())));
      socket.once("error", reject);
    });
    assert.equal(message.type, "pong");
    socket.close();
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("demo seed is repeatable and refuses production mode", () => {
  const seed = path.join(__dirname, "..", "scripts", "seed-demo.js");
  const env = { ...process.env, NODE_ENV: "test", ALLOW_DEMO_SEED: "true", DEMO_SEED_PASSWORD: demoSeedPassword };
  execFileSync(process.execPath, [seed], { env, stdio: "pipe" });
  const first = Number(execFileSync("docker", ["exec", "sentinelops-backend-test-pg", "psql", "-U", "sentinel", "-d", "sentinel_test", "-tAc", "SELECT count(*) FROM soc_records WHERE is_demo=true"], { encoding: "utf8" }).trim());
  execFileSync(process.execPath, [seed], { env, stdio: "pipe" });
  const second = Number(execFileSync("docker", ["exec", "sentinelops-backend-test-pg", "psql", "-U", "sentinel", "-d", "sentinel_test", "-tAc", "SELECT count(*) FROM soc_records WHERE is_demo=true"], { encoding: "utf8" }).trim());
  assert.equal(second, first);
});
