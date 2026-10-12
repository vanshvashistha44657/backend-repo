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

test("sensor enrollment authenticates, persists idempotent telemetry, and reports stale state", async () => {
  const login = await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
  const auth = { Authorization: `Bearer ${login.body.token}` };
  await request(app).post("/sensors/enroll").set(auth).send({ name: "Browser-like attempt" }).expect(403);
  const enrollment = await request(app).post("/sensors/enroll").set({ ...auth, "X-SentinelOps-Enrollment": "powershell" }).send({ name: "Isolated Windows Sensor", hostname: "TEST-WIN", platform: "windows", sensor_version: "test" }).expect(201);
  const sensor = enrollment.body.sensor;
  const credentials = enrollment.body.credentials;
  assert.equal(sensor.status, "never_reported");
  const secretHash = await pool.query("SELECT secret_hash FROM sensors WHERE id=$1", [sensor.id]);
  assert.notEqual(secretHash.rows[0].secret_hash, credentials.secret);
  const sensorHeaders = { "X-Sensor-ID": credentials.sensorId, "X-Sensor-Secret": credentials.secret };
  const heartbeat = await request(app).post("/sensor/v1/heartbeat").set(sensorHeaders).send({ hostname: "TEST-WIN", platform: "windows", sensor_version: "test", heartbeat_interval_seconds: 30, observed_at: new Date().toISOString(), collection_errors: [] }).expect(200);
  assert.equal(heartbeat.body.sensor.status, "active");
  const snapshot = { client_observation_id: "test-observation-1", observed_at: new Date().toISOString(), hostname: "TEST-WIN", sensor_version: "test", connection: { state: "connected", ssid: "Authorized-Test-WiFi", bssid: "aa-bb-cc-dd-ee-ff", local_ip: "192.0.2.10", subnet: "192.0.2.0/24", gateway: "192.0.2.1", dns: ["192.0.2.1"], signal: { percent: 82 } }, interfaces: [{ name: "Wi-Fi", alias: "Wi-Fi", state: "Up", connection_type: "802.11", mac: "aa-bb-cc-dd-ee-ff", local_ips: ["192.0.2.10"], collection_method: "test" }], devices: [{ ip: "192.0.2.20", mac: "11-22-33-44-55-66", hostname: "observed-host", vendor: null, state: "Reachable", services: [{ port: 443, protocol: "tcp", available: true, method: "test" }], collection_methods: ["test"] }], collection_methods: ["test"], collection_errors: [] };
  const inserted = await request(app).post("/sensor/v1/snapshots").set(sensorHeaders).send(snapshot).expect(201);
  assert.equal(inserted.body.devicesAccepted, 1);
  const duplicate = await request(app).post("/sensor/v1/snapshots").set(sensorHeaders).send(snapshot).expect(200);
  assert.equal(duplicate.body.duplicate, true);
  const changed = { ...snapshot, client_observation_id: "test-observation-2", observed_at: new Date().toISOString(), connection: { ...snapshot.connection, ssid: "Authorized-Test-WiFi-Changed" } };
  const changedResult = await request(app).post("/sensor/v1/snapshots").set(sensorHeaders).send(changed).expect(201);
  assert.match(changedResult.body.alertId, /^network-change-/);
  const devices = await request(app).get("/network/devices").set(auth).expect(200);
  assert.equal(devices.body[0].ip, "192.0.2.20");
  const alerts = await request(app).get("/alerts").set(auth).expect(200);
  assert.equal(alerts.body.items[0].ruleId, "network-context-change");
  const assets = await request(app).get("/assets").set(auth).expect(200);
  assert.equal(assets.body[0].source, "sensor");
  await pool.query("UPDATE sensors SET last_heartbeat_at=now()-interval '10 minutes' WHERE id=$1", [sensor.id]);
  const stale = await request(app).get("/sensors").set(auth).expect(200);
  assert.equal(stale.body.find((item) => item.id === sensor.id).status, "stale");
  await request(app).post(`/sensors/${sensor.id}/revoke`).set(auth).expect(200);
  await request(app).post("/sensor/v1/heartbeat").set(sensorHeaders).send({}).expect(401);
});

test("two-user network privacy isolates sensors, telemetry, alerts, notifications, and WebSockets", async () => {
  const aPassword = "IsolatedUserAPassword123!";
  const bPassword = "IsolatedUserBPassword123!";
  const managerPassword = "IsolatedManagerPassword123!";
  const bHash = await bcrypt.hash(bPassword, 4);
  const managerHash = await bcrypt.hash(managerPassword, 4);
  const aHash = await bcrypt.hash(aPassword, 4);
  const aUser = (await pool.query("INSERT INTO users(name,email,password_hash,role,approved) VALUES($1,$2,$3,'user',true) RETURNING *", ["Isolated User A", "isolated-user-a@example.test", aHash])).rows[0];
  const bUser = (await pool.query("INSERT INTO users(name,email,password_hash,role,approved) VALUES($1,$2,$3,'user',true) RETURNING *", ["Isolated User B", "isolated-user-b@example.test", bHash])).rows[0];
  const manager = (await pool.query("INSERT INTO users(name,email,password_hash,role,approved) VALUES($1,$2,$3,'manager',true) RETURNING *", ["Isolated Manager", "isolated-manager@example.test", managerHash])).rows[0];
  const loginA = await request(app).post("/auth/login").send({ email: aUser.email, password: aPassword }).expect(200);
  const loginB = await request(app).post("/auth/login").send({ email: bUser.email, password: bPassword }).expect(200);
  const loginAdmin = await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
  const loginManager = await request(app).post("/auth/login").send({ email: manager.email, password: managerPassword }).expect(200);
  const authA = { Authorization: `Bearer ${loginA.body.token}` };
  const authB = { Authorization: `Bearer ${loginB.body.token}` };
  const authAdmin = { Authorization: `Bearer ${loginAdmin.body.token}` };
  const authManager = { Authorization: `Bearer ${loginManager.body.token}` };
  const enroll = async (auth, name, ownerUserId) => {
    await request(app).post("/sensors/enroll").set({ ...auth, "X-SentinelOps-Enrollment": "powershell", "Sec-Fetch-Mode": "cors" }).send({ name }).expect(403);
    const response = await request(app).post("/sensors/enroll").set({ ...auth, "X-SentinelOps-Enrollment": "powershell" }).send({ name, hostname: name, platform: "windows", sensor_version: "isolation-test", owner_user_id: ownerUserId }).expect(201);
    assert.equal(Object.prototype.hasOwnProperty.call(response.body.credentials, "secret"), true);
    assert.equal(Object.prototype.hasOwnProperty.call(response.body.sensor, "secret"), false);
    return { sensor: response.body.sensor, headers: { "X-Sensor-ID": response.body.credentials.sensorId, "X-Sensor-Secret": response.body.credentials.secret } };
  };
  const sensorA = await enroll(authA, "Sensor-A", bUser.id);
  const sensorB = await enroll(authB, "Sensor-B", testUser.id);
  const owners = await pool.query("SELECT id,owner_user_id FROM sensors WHERE id IN($1,$2) ORDER BY id", [sensorA.sensor.id, sensorB.sensor.id]);
  assert.equal(String(owners.rows.find((row) => String(row.id) === sensorA.sensor.id).owner_user_id), String(aUser.id));
  assert.equal(String(owners.rows.find((row) => String(row.id) === sensorB.sensor.id).owner_user_id), String(bUser.id));

  const snapshot = (id, ssid, ip, deviceIp) => ({ client_observation_id: id, observed_at: new Date().toISOString(), hostname: id, sensor_version: "isolation-test", connection: { state: "connected", ssid, bssid: "aa-bb-cc-dd-ee-ff", local_ip: ip, subnet: "192.0.2.0/24", gateway: "192.0.2.1", dns: ["192.0.2.1"], signal: { percent: 80 } }, interfaces: [{ name: "Wi-Fi", state: "Up", connection_type: "802.11", mac: "aa-bb-cc-dd-ee-ff", local_ips: [ip], collection_method: "isolation-test" }], devices: [{ ip: deviceIp, mac: id === "b-1" ? "bb-bb-bb-bb-bb-bb" : "aa-aa-aa-aa-aa-aa", hostname: `${id}.local`, state: "observed", services: [], collection_methods: ["isolation-test"] }], collection_methods: ["isolation-test"], collection_errors: [] });
  await request(app).post("/sensor/v1/snapshots").set(sensorA.headers).send(snapshot("a-1", "WiFi-A", "192.0.2.10", "192.0.2.20")).expect(201);
  await request(app).post("/sensor/v1/snapshots").set(sensorB.headers).send(snapshot("b-1", "WiFi-B", "198.51.100.10", "198.51.100.20")).expect(201);
  const bChanged = snapshot("b-2", "WiFi-B-Changed", "198.51.100.10", "198.51.100.20");
  const bChangedResult = await request(app).post("/sensor/v1/snapshots").set(sensorB.headers).send(bChanged).expect(201);
  assert.match(bChangedResult.body.alertId, /^network-change-/);

  const aSensors = await request(app).get("/sensors").set(authA).expect(200);
  const bSensors = await request(app).get("/sensors").set(authB).expect(200);
  assert.deepEqual(aSensors.body.map((item) => item.id), [sensorA.sensor.id]);
  assert.deepEqual(bSensors.body.map((item) => item.id), [sensorB.sensor.id]);
  assert.equal((await request(app).get("/sensors").set(authManager).expect(200)).body.length, 0);
  assert.equal((await request(app).get("/sensors").set(authA).expect(200)).body[0].secret, undefined);

  const aOverview = await request(app).get("/network/overview").set(authA).expect(200);
  const bOverview = await request(app).get("/network/overview").set(authB).expect(200);
  assert.equal(aOverview.body.latestSnapshots[0].connection.ssid, "WiFi-A");
  assert.equal(aOverview.body.devices[0].ip, "192.0.2.20");
  assert.equal(bOverview.body.latestSnapshots[0].connection.ssid, "WiFi-B-Changed");
  assert.equal(bOverview.body.devices[0].ip, "198.51.100.20");
  assert.equal(JSON.stringify(aOverview.body).includes("WiFi-B"), false);
  assert.equal(JSON.stringify(bOverview.body).includes("WiFi-A"), false);
  assert.equal((await request(app).get("/network/snapshots").set(authA).expect(200)).body.every((item) => item.connection.ssid !== "WiFi-B"), true);
  assert.equal((await request(app).get("/network/interfaces").set(authB).expect(200)).body.every((item) => item.sensorId === sensorB.sensor.id), true);

  const sockets = await require("../server").start(0);
  const aEvents = []; const bEvents = [];
  let socketA; let socketB;
  try {
    const address = sockets.address();
    socketA = new WebSocket(`ws://127.0.0.1:${address.port}/ws?token=${encodeURIComponent(loginA.body.token)}`);
    socketB = new WebSocket(`ws://127.0.0.1:${address.port}/ws?token=${encodeURIComponent(loginB.body.token)}`);
    socketA.on("message", (value) => aEvents.push(JSON.parse(value.toString())));
    socketB.on("message", (value) => bEvents.push(JSON.parse(value.toString())));
    await Promise.all([new Promise((resolve, reject) => { socketA.once("open", resolve); socketA.once("error", reject); }), new Promise((resolve, reject) => { socketB.once("open", resolve); socketB.once("error", reject); })]);
    const changed = snapshot("a-2", "WiFi-A-Changed", "192.0.2.10", "192.0.2.20");
    const changedResult = await request(app).post("/sensor/v1/snapshots").set(sensorA.headers).send(changed).expect(201);
    assert.match(changedResult.body.alertId, /^network-change-/);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(aEvents.some((event) => event.kind === "alert" && event.detail === "Sensor-A"), true);
    assert.equal(bEvents.some((event) => event.kind === "alert" && event.detail === "Sensor-A"), false);
  } finally {
    socketA?.close(); socketB?.close();
    await new Promise((resolve) => sockets.close(resolve));
  }

  const aAlerts = await request(app).get("/alerts").set(authA).expect(200);
  const bAlerts = await request(app).get("/alerts").set(authB).expect(200);
  const bAlert = bAlerts.body.items.find((item) => item.ruleId === "network-context-change");
  assert.equal(aAlerts.body.items.some((item) => item.id === bAlert?.id), false);
  assert.equal((await request(app).get(`/alerts/${bAlert.id}`).set(authA)).status, 404);
  assert.equal((await request(app).patch(`/alerts/${bAlert.id}`).set(authA).send({ description: "cross-user" })).status, 404);
  assert.equal((await request(app).post(`/sensors/${sensorB.sensor.id}/revoke`).set(authA)).status, 403);
  assert.equal((await request(app).post(`/sensors/${sensorA.sensor.id}/revoke`).set(authB)).status, 403);

  const aNotifications = await request(app).get("/notifications").set(authA).expect(200);
  const bNotifications = await request(app).get("/notifications").set(authB).expect(200);
  assert.equal(aNotifications.body.some((item) => item.title === "Network context changed" && item.body.includes("Sensor-A")), true);
  assert.equal(bNotifications.body.some((item) => item.title === "Network context changed" && item.body.includes("Sensor-B")), true);
  assert.equal(bNotifications.body.some((item) => item.body.includes("Sensor-A")), false);
  const aNotificationId = aNotifications.body.find((item) => item.title === "Network context changed").id;
  assert.equal((await request(app).post(`/notifications/${aNotificationId}/read`).set(authB)).status, 404);
  assert.equal((await request(app).get("/network/overview").set(authManager).expect(200)).body.devices.length, 0);
  const adminSensors = await request(app).get("/sensors").set(authAdmin).expect(200);
  assert.equal(adminSensors.body.some((item) => item.id === sensorA.sensor.id), true);
  assert.equal(adminSensors.body.some((item) => item.id === sensorB.sensor.id), true);

  await request(app).post(`/sensors/${sensorB.sensor.id}/revoke`).set(authB).expect(200);
  await request(app).post("/sensor/v1/heartbeat").set(sensorB.headers).send({}).expect(401);

  const bSessions = await request(app).get("/auth/sessions").set(authB).expect(200);
  await pool.query("UPDATE sessions SET status='revoked',revoked_at=now() WHERE id=$1", [bSessions.body[0].id]);
  assert.equal((await request(app).get("/network/overview").set(authB)).status, 401);
});

test("demo seed is repeatable, interconnected, and isolated from production mode", async () => {
  const seed = path.join(__dirname, "..", "scripts", "seed-demo.js");
  const env = { ...process.env, NODE_ENV: "test", ALLOW_DEMO_SEED: "true", DEMO_SEED_PASSWORD: demoSeedPassword, DATABASE_URL: process.env.DATABASE_URL };
  await pool.query("INSERT INTO soc_records(id,kind,payload,is_demo) VALUES('demo-alert-sqli-001','alert','{}',false)");
  assert.throws(() => execFileSync(process.execPath, [seed], { env, stdio: "pipe" }));
  await pool.query("DELETE FROM soc_records WHERE id='demo-alert-sqli-001'");
  execFileSync(process.execPath, [seed], { env, stdio: "pipe" });
  const first = Number((await pool.query("SELECT count(*)::int AS count FROM soc_records WHERE is_demo=true")).rows[0].count);
  execFileSync(process.execPath, [seed], { env, stdio: "pipe" });
  const second = Number((await pool.query("SELECT count(*)::int AS count FROM soc_records WHERE is_demo=true")).rows[0].count);
  assert.equal(second, first);
  assert.ok(first >= 99);
  const linked = await pool.query("SELECT payload->>'relatedIncidentId' AS incident_id FROM soc_records WHERE id='demo-alert-sqli-001' AND is_demo=true");
  assert.equal(linked.rows[0].incident_id, "demo-incident-sqli-001");
  const sqliReport = await pool.query("SELECT payload->'summary' AS summary FROM soc_records WHERE id='demo-report-sqli-001' AND is_demo=true");
  assert.match(JSON.stringify(sqliReport.rows[0].summary), /Production requests sent/);
  const productionEnv = { ...env, NODE_ENV: "production" };
  assert.throws(() => execFileSync(process.execPath, [seed], { env: productionEnv, stdio: "pipe" }));
  const authorizedDryRunEnv = { ...productionEnv, ALLOW_PRODUCTION_DEMO_SEED: "true", DEMO_SEED_CONFIRMATION: "SENTINELOPS_PRODUCTION_DEMO_SEED_2026", DEMO_SEED_TARGET_HOST: "127.0.0.1", DEMO_SEED_TARGET_DATABASE: "sentinel_test" };
  execFileSync(process.execPath, [seed, "--dry-run"], { env: authorizedDryRunEnv, stdio: "pipe" });
  assert.throws(() => execFileSync(process.execPath, [seed, "--dry-run"], { env: { ...authorizedDryRunEnv, DEMO_SEED_TARGET_HOST: "wrong.supabase.example" }, stdio: "pipe" }));
});

test("generated reports use persisted SOC data and exports remain usable", async () => {
  const login = await request(app).post("/auth/login").send({ email: testUser.email, password: resetPassword }).expect(200);
  const auth = { Authorization: `Bearer ${login.body.token}` };
  const metrics = await request(app).get("/dashboard/metrics").set(auth).expect(200);
  assert.ok(metrics.body.criticalAlerts >= 1);
  assert.ok(metrics.body.openIncidents >= 1);
  assert.ok(metrics.body.activeCases >= 1);
  const reports = await request(app).get("/reports").set(auth).expect(200);
  const sqli = reports.body.find((report) => report.id === "demo-report-sqli-001");
  assert.equal(sqli.isDemo, true);
  const generated = await request(app).post("/reports").set(auth).send({ type: "incident" }).expect(201);
  assert.equal(generated.body.status, "ready");
  assert.ok(generated.body.summary.length >= 3);
  const csv = await request(app).get(`/reports/${generated.body.id}/export?format=csv`).set(auth).expect(200);
  assert.match(csv.headers["content-type"], /text\/csv/);
  assert.match(csv.text, /metric,value/);
  await request(app).get("/reports/demo-report-sqli-001/export?format=pdf").set(auth).expect(501);
  const alerts = await request(app).get("/alerts?search=SQL injection").set(auth).expect(200);
  assert.equal(alerts.body.items[0].id, "demo-alert-sqli-001");
  assert.equal(alerts.body.items[0].isDemo, true);
  const defaultWindowAlerts = await request(app).get("/alerts?hours=168&pageSize=100").set(auth).expect(200);
  assert.equal(defaultWindowAlerts.body.items.some((item) => item.id === "demo-alert-sqli-001"), true);
  assert.equal((await request(app).get("/incidents").set(auth).expect(200)).body.some((item) => item.id === "demo-incident-sqli-001"), true);
  assert.equal((await request(app).get("/cases").set(auth).expect(200)).body.some((item) => item.id === "demo-case-sqli-001"), true);
  assert.equal((await request(app).get("/iocs").set(auth).expect(200)).body.some((item) => item.id === "demo-ioc-sqli-001"), true);
  assert.equal((await request(app).get("/assets").set(auth).expect(200)).body.some((item) => item.name === "WEB-LAB-01" && item.isDemo === true), true);
  assert.equal((await request(app).get("/rules").set(auth).expect(200)).body.some((item) => item.id === "demo-rule-sqli-001"), true);
  assert.equal((await request(app).get("/intel/feeds").set(auth).expect(200)).body.length >= 4, true);
  assert.equal((await request(app).get("/intel/actors").set(auth).expect(200)).body.some((item) => item.isDemo === true), true);
  assert.equal((await request(app).get("/hunting/saved").set(auth).expect(200)).body.some((item) => item.id === "demo-hunt-sqli-001"), true);
  const hunt = await request(app).post("/hunting/search").set(auth).send({ field: "host", operator: "contains", value: "WEB-LAB-01", hours: 168 }).expect(200);
  assert.equal(hunt.body.some((item) => item.id === "demo-alert-sqli-001" && item.isDemo === true), true);
  assert.equal((await request(app).get("/admin/audit-logs?search=demo").set(auth).expect(200)).body.some((item) => item.isDemo === true), true);
  assert.equal((await request(app).get("/admin/sessions").set(auth).expect(200)).body.some((item) => item.isDemo === true), true);
});
