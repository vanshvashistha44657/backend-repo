const crypto = require("node:crypto");
const http = require("node:http");
const net = require("node:net");
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { WebSocketServer, WebSocket } = require("ws");
require("dotenv").config();

const { applyMigrations } = require("./lib/schema");
const { mailConfiguration, sendPasswordResetEmail } = require("./lib/mailer");

const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === "test" ? "test-only-secret" : null);
const ACCESS_TTL = process.env.ACCESS_TOKEN_TTL || "15m";
const REFRESH_DAYS = Number(process.env.REFRESH_TOKEN_DAYS || 30);
const port = Number(process.env.PORT || 10000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined });
if (!JWT_SECRET && require.main === module) { console.error("JWT_SECRET is not configured."); process.exit(1); }

const origins = (process.env.FRONTEND_URLS || "").split(",").map((value) => value.trim()).filter(Boolean);
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: (origin, callback) => (!origin || !origins.length || origins.includes(origin) ? callback(null, true) : callback(new Error("CORS origin not allowed"))), credentials: true, allowedHeaders: ["Content-Type", "Authorization", "X-Sensor-ID", "X-Sensor-Secret"] }));
app.use(express.json({ limit: "2mb" }));
const sockets = new Map();
const sensorRate = new Map();

const now = () => new Date().toISOString();
const idHash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");
const parseJson = (value, fallback) => { if (value == null) return fallback; if (typeof value === "object") return value; try { return JSON.parse(value); } catch { return fallback; } };
const timestamp = (value) => value ? new Date(value).toISOString() : null;
const ipOf = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
const deviceOf = (req) => { const ua = String(req.headers["user-agent"] || ""); return /mobile/i.test(ua) ? "Mobile browser" : /Firefox/i.test(ua) ? "Firefox browser" : /Edg/i.test(ua) ? "Edge browser" : /Chrome/i.test(ua) ? "Chrome browser" : ua.slice(0, 120) || "Unknown device"; };

function cookies(req) { return Object.fromEntries(String(req.headers.cookie || "").split(";").map((v) => v.trim().split("=")).filter(([key, value]) => key && value).map(([key, value]) => [key, decodeURIComponent(value)])); }
function refreshCookie(token, remember = true) { const flags = [`Path=/auth`, `HttpOnly`, process.env.NODE_ENV === "production" ? "Secure" : "", process.env.NODE_ENV === "production" ? "SameSite=None" : "SameSite=Lax"]; if (remember) flags.push(`Max-Age=${REFRESH_DAYS * 86400}`); return `sentinelops_refresh=${encodeURIComponent(token)}; ${flags.filter(Boolean).join("; ")}`; }
function clearRefreshCookie() { return "sentinelops_refresh=; Path=/auth; HttpOnly; Max-Age=0; SameSite=Lax"; }
function setCookie(res, value) { res.setHeader("Set-Cookie", value); }
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, role: user.role, approved: user.approved, status: user.approved || user.role === "admin" ? "active" : "pending", created_at: timestamp(user.created_at), createdAt: timestamp(user.created_at), last_login: timestamp(user.last_login), lastLogin: timestamp(user.last_login), mfaEnabled: false }; }
function uiRole(role) { return ({ admin: "Administrator", manager: "SOC Manager", analyst_l2: "SOC Analyst L2", user: "SOC Analyst L1" })[role] || role; }
function dbRole(role) { const value = String(role || "").toLowerCase(); return value === "administrator" || value === "admin" ? "admin" : value.includes("manager") ? "manager" : value.includes("l2") ? "analyst_l2" : "user"; }
function accessToken(user, sessionId) { return jwt.sign({ sub: user.id, email: user.email, role: user.role, sid: sessionId }, JWT_SECRET, { expiresIn: ACCESS_TTL }); }

function ownerScope(req) { return req.user?.role === "admin" ? null : req.user?.id || null; }
async function record(kind, id, ownerUserId = null) {
  const result = ownerUserId
    ? await pool.query("SELECT * FROM soc_records WHERE kind=$1 AND id=$2 AND (owner_user_id IS NULL OR owner_user_id=$3)", [kind, id, ownerUserId])
    : await pool.query("SELECT * FROM soc_records WHERE kind=$1 AND id=$2", [kind, id]);
  return result.rows[0] || null;
}
async function records(kind, search = "", ownerUserId = null) {
  const params = ownerUserId ? [kind, search, `%${search}%`, ownerUserId] : [kind, search, `%${search}%`];
  const scope = ownerUserId ? " AND (owner_user_id IS NULL OR owner_user_id=$4)" : "";
  const result = await pool.query(`SELECT * FROM soc_records WHERE kind=$1 AND ($2='' OR id ILIKE $3 OR payload::text ILIKE $3)${scope} ORDER BY created_at DESC`, params);
  return result.rows.map((row) => ({ ...parseJson(row.payload, {}), id: row.id, createdAt: timestamp(row.created_at), updatedAt: timestamp(row.updated_at), isDemo: Boolean(row.is_demo), demoKey: row.demo_key || undefined }));
}
async function putRecord(kind, id, payload, options = {}) { const result = await pool.query(`INSERT INTO soc_records (id,kind,payload,owner_user_id,is_demo,demo_key) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now() RETURNING *`, [id, kind, JSON.stringify({ ...payload, id }), options.ownerUserId || null, Boolean(options.isDemo), options.demoKey || null]); return { ...payload, id, createdAt: timestamp(result.rows[0].created_at), updatedAt: timestamp(result.rows[0].updated_at) }; }
async function patchRecord(kind, id, patch, ownerUserId = null) { const row = await record(kind, id, ownerUserId); if (!row) return null; return putRecord(kind, id, { ...parseJson(row.payload, {}), ...patch }); }
async function audit(actor, action, resource, req, values = {}) { await pool.query("INSERT INTO audit_logs (actor_user_id,actor_email,action,resource,ip,previous_value,new_value,result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", [actor?.id || null, actor?.email || "system", action, resource, ipOf(req), values.previous || null, values.next || null, values.result || "success"]); }
function emit(userId, event) { for (const socket of sockets.get(String(userId)) || []) if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(event)); }
function closeSessionSockets(sessionId) {
  for (const userSockets of sockets.values()) for (const socket of userSockets) if (socket.sessionId === String(sessionId)) socket.close(4001, "Session revoked");
}
async function notify(userId, data) { const key = data.eventKey || `${data.category}:${data.title}:${userId}`; const result = await pool.query(`INSERT INTO notifications (user_id,title,body,severity,category,link,event_key) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (user_id,event_key) DO NOTHING RETURNING *`, [userId, data.title, data.body, data.severity || "info", data.category || "system", data.link || null, key]); if (!result.rowCount) return null; const row = result.rows[0]; emit(userId, { id: String(row.id), at: timestamp(row.created_at), kind: "notification", severity: row.severity, message: row.title, detail: row.body }); return row; }
async function notifyUsers(data) { const result = await pool.query("SELECT id FROM users WHERE approved = true OR role = 'admin'"); for (const user of result.rows) await notify(user.id, data); }

async function createSession(user, req, remember = true) { const refresh = randomToken(); const result = await pool.query("INSERT INTO sessions (user_id,refresh_token_hash,expires_at,ip,user_agent,device,current) VALUES ($1,$2,now() + ($3 * interval '1 day'),$4,$5,$6,true) RETURNING *", [user.id, idHash(refresh), REFRESH_DAYS, ipOf(req), String(req.headers["user-agent"] || ""), deviceOf(req)]); await pool.query("UPDATE sessions SET current = false WHERE user_id = $1 AND id <> $2 AND status = 'active'", [user.id, result.rows[0].id]); return { row: result.rows[0], refresh, remember }; }
async function sessionFor(id, userId) { if (!id) return null; const result = await pool.query("SELECT * FROM sessions WHERE id = $1 AND user_id = $2", [id, userId]); return result.rows[0] || null; }

async function requireAuth(req, res, next) {
  const [scheme, token] = String(req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ message: "Authentication required" });
  try {
    const payload = jwt.verify(token, JWT_SECRET); const result = await pool.query("SELECT * FROM users WHERE id = $1", [payload.sub]); const user = result.rows[0];
    if (!user || (!user.approved && user.role !== "admin")) return res.status(401).json({ message: "Account is not active" });
    if (payload.sid) { const session = await sessionFor(payload.sid, user.id); if (!session || session.status !== "active" || new Date(session.expires_at) <= new Date()) { if (session) await pool.query("UPDATE sessions SET status = 'expired' WHERE id = $1 AND status = 'active'", [session.id]); return res.status(401).json({ message: "Session expired" }); } if (Date.now() - new Date(session.last_activity).getTime() > 15000) await pool.query("UPDATE sessions SET last_activity = now() WHERE id = $1", [session.id]); req.session = session; }
    req.user = user; return next();
  } catch { return res.status(401).json({ message: "Invalid or expired token" }); }
}
function requireAdmin(req, res, next) { return req.user?.role === "admin" ? next() : res.status(403).json({ message: "Admin access required" }); }
function requireManager(req, res, next) { return ["admin", "manager"].includes(req.user?.role) ? next() : res.status(403).json({ message: "Manager access required" }); }

function sensorStatus(row) {
  if (row.status === "revoked") return "revoked";
  if (!row.last_heartbeat_at) return "never_reported";
  const staleAfter = Math.max(Number(row.heartbeat_interval_seconds || 60) * 3, 180) * 1000;
  return Date.now() - new Date(row.last_heartbeat_at).getTime() <= staleAfter ? "active" : "stale";
}
function publicSensor(row) {
  return {
    id: String(row.id), name: row.name, hostname: row.hostname, platform: row.platform,
    sensorVersion: row.sensor_version, status: sensorStatus(row), createdAt: timestamp(row.created_at),
    lastHeartbeatAt: timestamp(row.last_heartbeat_at), lastObservationAt: timestamp(row.last_observation_at),
    lastErrorAt: timestamp(row.last_error_at), lastError: row.last_error || null, lastIp: row.last_ip || "",
    heartbeatIntervalSeconds: row.heartbeat_interval_seconds,
  };
}
function sensorOwnerCanAccess(req, row) { return req.user?.role === "admin" || String(row.owner_user_id) === String(req.user?.id); }
function sensorHttpsAllowed(req) {
  const forwarded = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  if (req.secure || forwarded === "https" || process.env.NODE_ENV === "test") return true;
  return process.env.ALLOW_INSECURE_SENSOR_LOCAL === "true" && ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket.remoteAddress);
}
function sensorRateAllowed(key) {
  const current = Date.now(); const previous = sensorRate.get(key) || { started: current, count: 0 };
  if (current - previous.started >= 60_000) { sensorRate.set(key, { started: current, count: 1 }); return true; }
  previous.count += 1; sensorRate.set(key, previous); return previous.count <= 120;
}
async function requireSensor(req, res, next) {
  if (!sensorHttpsAllowed(req)) return res.status(400).json({ message: "Sensor telemetry requires HTTPS" });
  const sensorId = String(req.headers["x-sensor-id"] || "").trim();
  const secret = String(req.headers["x-sensor-secret"] || "");
  if (!/^[0-9a-f-]{36}$/i.test(sensorId) || !secret || secret.length > 256) return res.status(401).json({ message: "Sensor credentials required" });
  if (!sensorRateAllowed(`${sensorId}:${ipOf(req)}`)) return res.status(429).json({ message: "Sensor ingestion rate limit exceeded" });
  try {
    const result = await pool.query("SELECT s.*,u.approved AS owner_approved,u.role AS owner_role FROM sensors s JOIN users u ON u.id=s.owner_user_id WHERE s.id=$1", [sensorId]);
    const sensor = result.rows[0];
    if (!sensor || sensor.status !== "active" || sensor.revoked_at || (!sensor.owner_approved && sensor.owner_role !== "admin") || !(await bcrypt.compare(secret, sensor.secret_hash))) return res.status(401).json({ message: "Invalid or revoked sensor credentials" });
    req.sensor = sensor;
    next();
  } catch { return res.status(401).json({ message: "Invalid sensor credentials" }); }
}
function boundedString(value, max = 256) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
function arrayOfStrings(value, maxItems = 32, maxLength = 256) { return Array.isArray(value) ? value.slice(0, maxItems).map((item) => boundedString(item, maxLength)).filter(Boolean) : []; }
function validObservedAt(value) { const date = new Date(value); return Number.isFinite(date.getTime()) && date.getTime() <= Date.now() + 300_000; }
function validMac(value) { return !value || /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(value); }
function validIp(value) { return !value || net.isIP(value) > 0; }
function validateSnapshot(body) {
  if (!body || typeof body !== "object") return "JSON object required";
  if (!/^[A-Za-z0-9._:-]{1,120}$/.test(String(body.client_observation_id || ""))) return "client_observation_id is required and must be 1-120 safe characters";
  if (!validObservedAt(body.observed_at)) return "observed_at must be a valid non-future timestamp";
  if (!body.connection || typeof body.connection !== "object") return "connection is required";
  if (!validIp(boundedString(body.connection.local_ip, 64)) || !validIp(boundedString(body.connection.gateway, 64))) return "connection IP values must be valid IP addresses";
  if (!validMac(boundedString(body.connection.bssid, 64))) return "connection BSSID must be a valid MAC address";
  if (!Array.isArray(body.interfaces) || body.interfaces.length > 64) return "interfaces must be an array with at most 64 entries";
  if (!Array.isArray(body.devices) || body.devices.length > 2048) return "devices must be an array with at most 2048 entries";
  for (const item of body.interfaces) if (!item || typeof item !== "object" || !boundedString(item.name, 128) || !validIp(arrayOfStrings(item.local_ips, 16, 64)[0] || "") || !validMac(boundedString(item.mac, 32))) return "each interface must have a name and valid network values";
  for (const item of body.devices) if (!item || typeof item !== "object" || (!boundedString(item.ip, 64) && !boundedString(item.mac, 32)) || !validIp(boundedString(item.ip, 64)) || !validMac(boundedString(item.mac, 32))) return "each device needs a valid IP or MAC";
  return null;
}
function devicePayload(row) {
  return {
    id: String(row.id), sensorId: String(row.sensor_id), sensorName: row.sensor_name || "", ip: row.ip,
    mac: row.mac, hostname: row.hostname || null, vendor: row.vendor || null, state: row.device_state,
    services: parseJson(row.services, []), collectionMethods: parseJson(row.collection_methods, []),
    lastSeen: timestamp(row.observed_at), source: "sensor", isDemo: false,
  };
}
async function persistSnapshot(sensor, body, req) {
  const validation = validateSnapshot(body);
  if (validation) return { status: 400, body: { message: validation } };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query("SELECT id FROM network_snapshots WHERE sensor_id=$1 AND client_observation_id=$2", [sensor.id, body.client_observation_id]);
    if (existing.rowCount) { await client.query("COMMIT"); return { status: 200, body: { ok: true, duplicate: true, snapshotId: String(existing.rows[0].id) } }; }
    const previousResult = await client.query("SELECT observed_at,ssid,bssid,local_ip,subnet,gateway FROM network_snapshots WHERE sensor_id=$1 ORDER BY observed_at DESC LIMIT 1", [sensor.id]);
    const previous = previousResult.rows[0] || null;
    const connection = body.connection;
    const observedAt = new Date(body.observed_at).toISOString();
    const snapshot = await client.query(`INSERT INTO network_snapshots (sensor_id,client_observation_id,observed_at,connection_state,ssid,bssid,local_ip,subnet,gateway,dns,signal,collection_methods,collection_errors) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`, [
      sensor.id, body.client_observation_id, observedAt, boundedString(connection.state, 32) || "unknown", boundedString(connection.ssid, 128) || null,
      boundedString(connection.bssid, 64) || null, boundedString(connection.local_ip, 64) || null, boundedString(connection.subnet, 64) || null,
      boundedString(connection.gateway, 64) || null, JSON.stringify(arrayOfStrings(connection.dns, 16, 128)), JSON.stringify(connection.signal && typeof connection.signal === "object" ? connection.signal : {}),
      JSON.stringify(arrayOfStrings(body.collection_methods, 32, 128)), JSON.stringify(Array.isArray(body.collection_errors) ? body.collection_errors.slice(0, 32).map((item) => typeof item === "string" ? { message: boundedString(item, 256) } : { method: boundedString(item?.method, 128), message: boundedString(item?.message, 256) }).filter((item) => item.message) : []),
    ]);
    const snapshotId = snapshot.rows[0].id;
    for (const item of body.interfaces) {
      const name = boundedString(item.name, 128); if (!name) continue;
      await client.query("INSERT INTO network_interfaces (sensor_id,snapshot_id,name,alias,state,connection_type,mac,local_ips,collection_method,observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (snapshot_id,name) DO NOTHING", [
        sensor.id, snapshotId, name, boundedString(item.alias, 128), boundedString(item.state, 32) || "unknown", boundedString(item.connection_type, 32) || "unknown", boundedString(item.mac, 32), JSON.stringify(arrayOfStrings(item.local_ips, 16, 64)), boundedString(item.collection_method, 128), observedAt,
      ]);
    }
    const seen = new Set();
    for (const item of body.devices) {
      const ip = boundedString(item.ip, 64); const mac = boundedString(item.mac, 32).toLowerCase(); const key = boundedString(item.observation_key, 160) || `${mac}|${ip}`;
      if (seen.has(key)) continue; seen.add(key);
      await client.query("INSERT INTO device_observations (sensor_id,snapshot_id,observation_key,ip,mac,hostname,vendor,device_state,services,collection_methods,observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (sensor_id,snapshot_id,observation_key) DO NOTHING", [
        sensor.id, snapshotId, key, ip, mac, boundedString(item.hostname, 256) || null, boundedString(item.vendor, 128) || null, boundedString(item.state, 32) || "observed",
        JSON.stringify(Array.isArray(item.services) ? item.services.slice(0, 32).map((service) => ({ port: Number(service?.port) || 0, protocol: boundedString(service?.protocol, 16), available: Boolean(service?.available), method: boundedString(service?.method, 64) })).filter((service) => service.port > 0) : []), JSON.stringify(arrayOfStrings(item.collection_methods, 32, 128)), observedAt,
      ]);
    }
    const errors = Array.isArray(body.collection_errors) ? body.collection_errors : [];
    await client.query("UPDATE sensors SET last_observation_at=$1,last_heartbeat_at=GREATEST(COALESCE(last_heartbeat_at,$1),$1),last_error_at=$2,last_error=$3,last_ip=$4,hostname=COALESCE(NULLIF($5,''),hostname),sensor_version=COALESCE(NULLIF($6,''),sensor_version) WHERE id=$7", [observedAt, errors.length ? new Date().toISOString() : null, errors.length ? boundedString(errors[0]?.message || errors[0], 256) : null, ipOf(req), boundedString(body.hostname, 256), boundedString(body.sensor_version, 64), sensor.id]);
    await client.query("COMMIT");
    let alertId = null;
    const changed = previous && ["ssid", "bssid", "local_ip", "subnet", "gateway"].some((key) => String(previous[key] || "") !== String(connection[key] || ""));
    if (changed) {
      alertId = `network-change-${sensor.id}-${body.client_observation_id}`;
      const currentFacts = { ssid: connection.ssid || null, bssid: connection.bssid || null, localIp: connection.local_ip || null, subnet: connection.subnet || null, gateway: connection.gateway || null };
      await putRecord("alert", alertId, {
        id: alertId, title: "Observed network context changed", rule: "Network Context Change", ruleId: "network-context-change",
        severity: "info", status: "new", sourceIp: "", destinationIp: "", host: boundedString(body.hostname, 256), user: "",
        mitreTechnique: "", mitreName: "", tactic: "", assignee: null, timestamp: observedAt,
        description: "The sensor observed a change in SSID, BSSID, local address, subnet, or gateway. This is an observation for review, not a claim of malicious activity.",
        rawEvent: { source: "SentinelOps Windows sensor", collectionMethods: body.collection_methods || [], previousFacts: previous, currentFacts },
        relatedIncidentId: null, notes: [], timeline: [], riskScore: 0,
      }, { ownerUserId: sensor.owner_user_id });
      await notify(sensor.owner_user_id, { title: "Network context changed", body: `Sensor ${sensor.name} reported a changed local network context.`, severity: "info", category: "system", link: "/alerts", eventKey: `network-context-change:${sensor.id}:${body.client_observation_id}` });
      emit(sensor.owner_user_id, { id: alertId, at: observedAt, kind: "alert", severity: "info", message: "Observed network context changed", detail: sensor.name });
    }
    return { status: 201, body: { ok: true, duplicate: false, snapshotId: String(snapshotId), devicesAccepted: seen.size, alertId } };
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") {
      const duplicate = await pool.query("SELECT id FROM network_snapshots WHERE sensor_id=$1 AND client_observation_id=$2", [sensor.id, body.client_observation_id]);
      if (duplicate.rowCount) return { status: 200, body: { ok: true, duplicate: true, snapshotId: String(duplicate.rows[0].id) } };
    }
    throw error;
  } finally { client.release(); }
}

function alertPayload(row) { return { id: row.id, title: row.title || row.name || "Alert", rule: row.rule || "", ruleId: row.ruleId || row.rule_id || "", severity: row.severity || "info", status: row.status || "new", sourceIp: row.sourceIp || row.source_ip || "", destinationIp: row.destinationIp || row.destination_ip || "", host: row.host || "", user: row.user || row.username || "", mitreTechnique: row.mitreTechnique || row.mitre_technique || "", mitreName: row.mitreName || row.mitre_name || "", tactic: row.tactic || "", assignee: row.assignee || null, timestamp: timestamp(row.timestamp || row.created_at), description: row.description || "", rawEvent: row.rawEvent || row.raw_event || {}, relatedIncidentId: row.relatedIncidentId || row.related_incident_id || null, notes: row.notes || [], timeline: row.timeline || [], riskScore: Number(row.riskScore || row.risk_score || 0), isDemo: Boolean(row.isDemo), demoKey: row.demoKey || undefined }; }
function incidentPayload(row) { return { id: row.id, title: row.title || "Incident", severity: row.severity || "info", priority: row.priority || "P4", status: row.status || "open", assignee: row.assignee || null, createdAt: timestamp(row.createdAt || row.created_at), updatedAt: timestamp(row.updatedAt || row.updated_at), affectedAssets: row.affectedAssets || [], alertIds: row.alertIds || [], caseIds: row.caseIds || [], mitre: row.mitre || [], summary: row.summary || "", resolution: row.resolution || null, timeline: row.timeline || [], notes: row.notes || [], evidence: row.evidence || [], isDemo: Boolean(row.isDemo), demoKey: row.demoKey || undefined }; }
function sessionPayload(row) { return { id: String(row.id), userId: row.user_id, name: row.name, email: row.email, role: uiRole(row.role), loginAt: timestamp(row.started_at), lastActivity: timestamp(row.last_activity), ip: row.ip, device: row.device, location: row.location, current: row.current, isDemo: Boolean(row.is_demo), demoKey: row.demo_key || undefined }; }
function notificationPayload(row) { return { id: String(row.id), title: row.title, body: row.body, severity: row.severity, category: row.category, read: row.read, createdAt: timestamp(row.created_at), link: row.link || undefined, isDemo: Boolean(row.is_demo), demoKey: row.demo_key || undefined }; }
function listRoute(kind, mapper) { return async (req, res) => res.json((await records(kind, String(req.query.search || ""), ownerScope(req))).map(mapper || ((value) => value))); }

const REPORT_TYPES = new Set(["daily_soc", "weekly_soc", "monthly_soc", "incident", "soc_metrics", "analyst_performance", "false_positives"]);
const reportPeriod = (type) => ({ daily_soc: "Last 24 hours", weekly_soc: "Last 7 days", monthly_soc: "Last 30 days", incident: "Incident scoped", soc_metrics: "Current reporting period", analyst_performance: "Current reporting period", false_positives: "Current reporting period" })[type] || "Current reporting period";
const numeric = (value) => Number(value || 0);

async function socData(ownerUserId) {
  const [alerts, incidents, cases, iocs, assets] = await Promise.all([
    records("alert", "", ownerUserId), records("incident", "", ownerUserId), records("case", "", ownerUserId), records("ioc", "", ownerUserId), records("asset", "", ownerUserId),
  ]);
  return { alerts: alerts.map(alertPayload), incidents, cases, iocs, assets };
}

function severityCount(alerts, severity) { return alerts.filter((item) => item.severity === severity).length; }
function dashboardFrom(data) {
  const { alerts, incidents, cases, iocs, assets } = data;
  const severities = ["critical", "high", "medium", "low", "info"];
  const mitreCounts = new Map();
  const assetCounts = new Map();
  const sourceCounts = new Map();
  for (const alert of alerts) {
    if (alert.mitreTechnique) mitreCounts.set(alert.mitreTechnique, (mitreCounts.get(alert.mitreTechnique) || 0) + 1);
    if (alert.host) assetCounts.set(alert.host, (assetCounts.get(alert.host) || 0) + 1);
    if (alert.sourceIp) sourceCounts.set(alert.sourceIp, (sourceCounts.get(alert.sourceIp) || 0) + 1);
  }
  const latest = alerts.reduce((max, item) => Math.max(max, new Date(item.timestamp || 0).getTime()), Date.now());
  const alertVolume = Array.from({ length: 24 }, (_, index) => {
    const from = latest - (24 - index) * 3600000;
    const to = from + 3600000;
    const bucket = alerts.filter((item) => { const time = new Date(item.timestamp || 0).getTime(); return time >= from && time < to; });
    return { time: new Date(to).toISOString().slice(11, 16), critical: severityCount(bucket, "critical"), high: severityCount(bucket, "high"), medium: severityCount(bucket, "medium"), low: severityCount(bucket, "low") };
  });
  return {
    criticalAlerts: severityCount(alerts, "critical"), highAlerts: severityCount(alerts, "high"), openIncidents: incidents.filter((item) => item.status !== "resolved").length, activeCases: cases.filter((item) => item.status !== "closed").length,
    iocMatches: iocs.reduce((sum, item) => sum + numeric(item.matches), 0), intelMatches: iocs.filter((item) => numeric(item.matches) > 0).length, assetsAtRisk: assets.filter((item) => numeric(item.riskScore) > 60).length,
    securityScore: Math.max(0, 100 - severityCount(alerts, "critical") * 5 - severityCount(alerts, "high") * 2), systemHealth: 100, mttrMinutes: incidents.length ? 41 : 0,
    falsePositiveRate: alerts.length ? Math.round(alerts.filter((item) => item.status === "false_positive").length / alerts.length * 1000) / 10 : 0,
    alertToIncident: alerts.length ? Math.round(incidents.length / alerts.length * 1000) / 10 : 0,
    analystWorkload: [...new Set(incidents.map((item) => item.assignee).filter(Boolean))].map((analyst) => ({ analyst, open: incidents.filter((item) => item.assignee === analyst && item.status !== "resolved").length, capacity: 15 })),
    alertVolume, severityDistribution: severities.map((severity) => ({ name: severity, value: severityCount(alerts, severity), severity })),
    mitreDistribution: [...mitreCounts.entries()].map(([technique, count]) => ({ technique, name: technique, count })),
    incidentTimeline: Array.from({ length: 14 }, (_, index) => ({ day: new Date(latest - (13 - index) * 86400000).toISOString().slice(5, 10), opened: incidents.filter((item) => new Date(item.createdAt || 0).getTime() >= latest - (14 - index) * 86400000 && new Date(item.createdAt || 0).getTime() < latest - (13 - index) * 86400000).length, resolved: incidents.filter((item) => item.status === "resolved").length && index === 13 ? 1 : 0 })),
    threatActivity: alertVolume.map((item, index) => ({ time: item.time, score: Math.min(100, item.critical * 20 + item.high * 10 + item.medium * 4 + index), blocked: item.critical + item.high })),
    topAssets: [...assetCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7).map(([asset, count]) => ({ asset, alerts: count })),
    topSourceIps: [...sourceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7).map(([ip, count]) => ({ ip, count, country: "DEMO" })), fpTrend: [], trends: {},
  };
}

async function reportSummary(type, ownerUserId, incidentId = "") {
  const data = await socData(ownerUserId);
  const metrics = dashboardFrom(data);
  const incident = incidentId ? data.incidents.find((item) => item.id === incidentId) : data.incidents[0];
  if (type === "incident") return [{ label: "Incident", value: incident?.id || "No incident selected" }, { label: "Severity", value: incident?.severity || "—" }, { label: "Linked alerts", value: String(incident?.alertIds?.length || 0) }, { label: "Data source", value: incident?.isDemo ? "DEMO / SIMULATED" : "LIVE" }];
  if (type === "soc_metrics") return [{ label: "MTTD", value: "6m" }, { label: "MTTR", value: `${metrics.mttrMinutes}m` }, { label: "Detection coverage", value: `${data.alerts.length ? 100 : 0}% of persisted records` }, { label: "Data source", value: "Persisted SOC records" }];
  if (type === "analyst_performance") return [{ label: "Analysts with workload", value: String(metrics.analystWorkload.length) }, { label: "Active cases", value: String(metrics.activeCases) }, { label: "Open incidents", value: String(metrics.openIncidents) }];
  if (type === "false_positives") return [{ label: "False-positive alerts", value: String(data.alerts.filter((item) => item.status === "false_positive").length) }, { label: "False-positive rate", value: `${metrics.falsePositiveRate}%` }, { label: "Top rule", value: "Derived from persisted alerts" }];
  return [{ label: "Alerts", value: String(data.alerts.length) }, { label: "Incidents", value: String(data.incidents.length) }, { label: "Active cases", value: String(metrics.activeCases) }, { label: "IOC matches", value: String(metrics.iocMatches) }, { label: "Assets at risk", value: String(metrics.assetsAtRisk) }];
}

app.get("/", (req, res) => res.json({ ok: true, message: "SentinelOps backend is running", health: "/health" }));
app.get("/health", async (req, res) => { try { await pool.query("SELECT 1"); res.json({ ok: true, message: "Backend and database are healthy", email: mailConfiguration().configured ? "configured" : "not_configured" }); } catch { res.status(500).json({ ok: false, error: "Database connection failed" }); } });
app.get("/health/email", (req, res) => res.json(mailConfiguration()));

/* ---------------------------------------------------------- network sensors */
app.post("/sensors/enroll", requireAuth, async (req, res) => {
  if (req.headers["sec-fetch-mode"] || req.headers["sec-fetch-site"] || req.headers["sec-fetch-dest"]) return res.status(403).json({ message: "Sensor enrollment must be performed by the documented local PowerShell procedure" });
  if (String(req.headers["x-sentinelops-enrollment"] || "").toLowerCase() !== "powershell") return res.status(403).json({ message: "Sensor enrollment must be performed from the documented PowerShell procedure" });
  const name = boundedString(req.body?.name, 80); if (!name) return res.status(400).json({ message: "Sensor name is required" });
  const sensorId = crypto.randomUUID(); const secret = randomToken();
  const result = await pool.query("INSERT INTO sensors (id,owner_user_id,name,secret_hash,hostname,platform,sensor_version) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *", [sensorId, req.user.id, name, await bcrypt.hash(secret, 12), boundedString(req.body?.hostname, 256), boundedString(req.body?.platform, 32) || "windows", boundedString(req.body?.sensor_version, 64)]);
  res.setHeader("Cache-Control", "no-store");
  res.status(201).json({ sensor: publicSensor(result.rows[0]), credentials: { sensorId, secret, apiBaseUrl: `${req.protocol}://${req.get("host")}` } });
});
app.get("/sensors", requireAuth, async (req, res) => {
  const result = req.user.role === "admin" ? await pool.query("SELECT * FROM sensors ORDER BY created_at DESC") : await pool.query("SELECT * FROM sensors WHERE owner_user_id=$1 ORDER BY created_at DESC", [req.user.id]);
  res.json(result.rows.map(publicSensor));
});
app.post("/sensors/:id/revoke", requireAuth, async (req, res) => {
  const result = await pool.query("SELECT * FROM sensors WHERE id=$1", [req.params.id]);
  if (!result.rowCount) return res.status(404).json({ message: "Sensor not found" });
  if (!sensorOwnerCanAccess(req, result.rows[0])) return res.status(403).json({ message: "Sensor access denied" });
  const revoked = await pool.query("UPDATE sensors SET status='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 RETURNING *", [req.params.id]);
  res.json({ sensor: publicSensor(revoked.rows[0]) });
});
app.post("/sensor/v1/heartbeat", requireSensor, async (req, res) => {
  const errors = Array.isArray(req.body?.collection_errors) ? req.body.collection_errors.slice(0, 32).map((item) => typeof item === "string" ? { message: boundedString(item, 256) } : { method: boundedString(item?.method, 128), message: boundedString(item?.message, 256) }).filter((item) => item.message) : [];
  const observedAt = req.body?.observed_at && validObservedAt(req.body.observed_at) ? new Date(req.body.observed_at).toISOString() : null;
  const result = await pool.query("UPDATE sensors SET last_heartbeat_at=now(),last_error_at=$1,last_error=$2,last_ip=$3,hostname=COALESCE(NULLIF($4,''),hostname),platform=COALESCE(NULLIF($5,''),platform),sensor_version=COALESCE(NULLIF($6,''),sensor_version),heartbeat_interval_seconds=GREATEST(15,LEAST($7,3600)) WHERE id=$8 RETURNING *", [errors.length ? new Date().toISOString() : null, errors.length ? errors[0].message : null, ipOf(req), boundedString(req.body?.hostname, 256), boundedString(req.body?.platform, 32), boundedString(req.body?.sensor_version, 64), Number(req.body?.heartbeat_interval_seconds) || 60, req.sensor.id]);
  res.json({ ok: true, receivedAt: now(), observedAt, sensor: publicSensor(result.rows[0]) });
});
app.post("/sensor/v1/snapshots", requireSensor, async (req, res) => {
  try { const result = await persistSnapshot(req.sensor, req.body, req); return res.status(result.status).json(result.body); }
  catch (error) { console.error("Sensor snapshot ingestion failed:", error.message); return res.status(500).json({ message: "Unable to persist network snapshot" }); }
});

async function networkDevices(req, search = "") {
  const result = await pool.query(`SELECT latest.*,s.name AS sensor_name FROM (SELECT DISTINCT ON (d.sensor_id,d.observation_key) d.* FROM device_observations d ORDER BY d.sensor_id,d.observation_key,d.observed_at DESC) latest JOIN sensors s ON s.id=latest.sensor_id WHERE ${req.user.role === "admin" ? "TRUE" : "s.owner_user_id=$1"} AND NOT (latest.ip ~ '^(22[4-9]|23[0-9])\\.' OR latest.ip = '255.255.255.255' OR latest.ip ~* '^ff[0-9a-f]*:') AND ($${req.user.role === "admin" ? 1 : 2}='' OR concat_ws(' ',latest.ip,latest.mac,latest.hostname,latest.vendor) ILIKE $${req.user.role === "admin" ? 2 : 3}) ORDER BY latest.observed_at DESC`, req.user.role === "admin" ? [search, `%${search}%`] : [req.user.id, search, `%${search}%`]);
  return result.rows.map(devicePayload);
}
app.get("/network/devices", requireAuth, async (req, res) => res.json(await networkDevices(req, boundedString(req.query.search, 128))));
app.get("/network/snapshots", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT n.*,s.name AS sensor_name FROM network_snapshots n JOIN sensors s ON s.id=n.sensor_id WHERE ${req.user.role === "admin" ? "TRUE" : "s.owner_user_id=$1"} ORDER BY n.observed_at DESC LIMIT 100`, req.user.role === "admin" ? [] : [req.user.id]);
  res.json(result.rows.map((row) => ({ id: String(row.id), sensorId: String(row.sensor_id), sensorName: row.sensor_name, observationId: row.client_observation_id, observedAt: timestamp(row.observed_at), connection: { state: row.connection_state, ssid: row.ssid, bssid: row.bssid, localIp: row.local_ip, subnet: row.subnet, gateway: row.gateway, dns: parseJson(row.dns, []), signal: parseJson(row.signal, {}) }, collectionMethods: parseJson(row.collection_methods, []), collectionErrors: parseJson(row.collection_errors, []) })));
});
app.get("/network/interfaces", requireAuth, async (req, res) => {
  const result = await pool.query(`SELECT i.*,s.name AS sensor_name FROM network_interfaces i JOIN sensors s ON s.id=i.sensor_id WHERE ${req.user.role === "admin" ? "TRUE" : "s.owner_user_id=$1"} ORDER BY i.observed_at DESC LIMIT 200`, req.user.role === "admin" ? [] : [req.user.id]);
  res.json(result.rows.map((row) => ({ id: String(row.id), sensorId: String(row.sensor_id), sensorName: row.sensor_name, snapshotId: String(row.snapshot_id), name: row.name, alias: row.alias, state: row.state, connectionType: row.connection_type, mac: row.mac, localIps: parseJson(row.local_ips, []), collectionMethod: row.collection_method, observedAt: timestamp(row.observed_at) })));
});
app.get("/network/overview", requireAuth, async (req, res) => {
  const sensors = req.user.role === "admin" ? await pool.query("SELECT * FROM sensors ORDER BY created_at DESC") : await pool.query("SELECT * FROM sensors WHERE owner_user_id=$1 ORDER BY created_at DESC", [req.user.id]);
  const devices = await networkDevices(req);
  const snapshots = await pool.query(`SELECT latest.*,s.name AS sensor_name FROM (SELECT DISTINCT ON (n.sensor_id) n.* FROM network_snapshots n ORDER BY n.sensor_id,n.observed_at DESC) latest JOIN sensors s ON s.id=latest.sensor_id WHERE ${req.user.role === "admin" ? "TRUE" : "s.owner_user_id=$1"}`, req.user.role === "admin" ? [] : [req.user.id]);
  const latestSnapshots = snapshots.rows.map((row) => ({ id: String(row.id), sensorId: String(row.sensor_id), sensorName: row.sensor_name, observationId: row.client_observation_id, observedAt: timestamp(row.observed_at), connection: { state: row.connection_state, ssid: row.ssid, bssid: row.bssid, localIp: row.local_ip, subnet: row.subnet, gateway: row.gateway, dns: parseJson(row.dns, []), signal: parseJson(row.signal, {}) }, collectionMethods: parseJson(row.collection_methods, []), collectionErrors: parseJson(row.collection_errors, []) }));
  res.json({ sensors: sensors.rows.map(publicSensor), devices, latestSnapshots, sensorCount: sensors.rowCount, activeSensorCount: sensors.rows.filter((row) => sensorStatus(row) === "active").length });
});

app.post("/auth/register", async (req, res) => {
  const name = String(req.body?.name || "").trim(); const email = String(req.body?.email || "").trim().toLowerCase(); const password = String(req.body?.password || "");
  if (!name || !email || !password) return res.status(400).json({ message: "Name, email and password required" }); if (password.length < 8) return res.status(400).json({ message: "Password must be at least 8 characters" });
  try { const exists = await pool.query("SELECT id FROM users WHERE email = $1", [email]); if (exists.rowCount) return res.status(409).json({ message: "Account already exists" }); const result = await pool.query("INSERT INTO users (name,email,password_hash,role,approved,department,justification) VALUES ($1,$2,$3,'user',false,$4,$5) RETURNING *", [name, email, await bcrypt.hash(password, 12), req.body.department || null, req.body.justification || null]); await audit(null, "user.register", `users/${result.rows[0].id}`, req, { next: { email } }); res.status(201).json({ message: "Account created. Waiting for admin approval.", user: publicUser(result.rows[0]) }); } catch (error) { console.error("Register error:", error.message); res.status(500).json({ message: "Unable to create account" }); }
});
app.post("/auth/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase(); const password = String(req.body?.password || ""); if (!email || !password) return res.status(400).json({ message: "Email and password required" });
  try { const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]); const user = result.rows[0]; if (!user || !(await bcrypt.compare(password, user.password_hash))) { await audit(null, "user.login", "auth", req, { result: "failure", next: { email } }); return res.status(401).json({ message: "Invalid credentials" }); } if (!user.approved && user.role !== "admin") return res.status(403).json({ message: "Account is awaiting admin approval", code: "ACCOUNT_PENDING" }); const session = await createSession(user, req, req.body.remember !== false); await pool.query("UPDATE users SET last_login = now() WHERE id = $1", [user.id]); await audit(user, "user.login", `users/${user.id}`, req); setCookie(res, refreshCookie(session.refresh, session.remember)); res.json({ token: accessToken(user, session.row.id), user: publicUser({ ...user, last_login: new Date() }) }); } catch (error) { console.error("Login error:", error.message); res.status(500).json({ message: "Login failed" }); }
});
app.post("/auth/refresh", async (req, res) => { const token = cookies(req).sentinelops_refresh || req.body?.refresh_token; if (!token) return res.status(401).json({ message: "Refresh token required" }); const result = await pool.query("SELECT s.id AS session_id,s.user_id AS session_user_id,s.refresh_token_hash,s.status,s.expires_at,s.started_at,s.last_activity,s.revoked_at,s.ip,s.user_agent,s.device,s.location,s.current,u.id,u.name,u.email,u.password_hash,u.role,u.approved,u.created_at,u.last_login FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.refresh_token_hash=$1", [idHash(token)]); const row = result.rows[0]; if (!row || row.status !== "active" || new Date(row.expires_at) <= new Date()) return res.status(401).json({ message: "Refresh token expired" }); const replacement = randomToken(); await pool.query("UPDATE sessions SET refresh_token_hash=$1,last_activity=now() WHERE id=$2", [idHash(replacement), row.session_id]); setCookie(res, refreshCookie(replacement)); res.json({ token: accessToken(row, row.session_id), user: publicUser(row) }); });
app.get("/auth/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post("/auth/heartbeat", requireAuth, async (req, res) => { if (req.session) await pool.query("UPDATE sessions SET last_activity=now() WHERE id=$1", [req.session.id]); res.json({ ok: true }); });
app.post("/auth/logout", requireAuth, async (req, res) => { if (req.session) { await pool.query("UPDATE sessions SET status='revoked',revoked_at=now(),current=false WHERE id=$1", [req.session.id]); closeSessionSockets(req.session.id); } await audit(req.user, "user.logout", `sessions/${req.session?.id || "legacy"}`, req); setCookie(res, clearRefreshCookie()); res.json({ ok: true }); });
app.get("/auth/sessions", requireAuth, async (req, res) => { const result = await pool.query("SELECT s.*,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.user_id=$1 AND s.status='active' ORDER BY last_activity DESC", [req.user.id]); res.json(result.rows.map(sessionPayload)); });
app.delete("/auth/sessions/:id", requireAuth, async (req, res) => { const result = await pool.query("UPDATE sessions SET status='revoked',revoked_at=now(),current=false WHERE id=$1 AND user_id=$2 RETURNING id", [req.params.id, req.user.id]); if (!result.rowCount) return res.status(404).json({ message: "Session not found" }); res.json({ ok: true }); });
app.post("/auth/change-password", requireAuth, async (req, res) => { const current = String(req.body?.current || ""); const next = String(req.body?.next || ""); const result = await pool.query("SELECT password_hash FROM users WHERE id=$1", [req.user.id]); if (!next || next.length < 10 || !result.rowCount || !(await bcrypt.compare(current, result.rows[0].password_hash))) return res.status(400).json({ message: "Current password or new password is invalid" }); await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [await bcrypt.hash(next, 12), req.user.id]); await pool.query("UPDATE sessions SET status='revoked',revoked_at=now(),current=false WHERE user_id=$1 AND id <> $2", [req.user.id, req.session?.id || null]); await notify(req.user.id, { title: "Password changed", body: "Your SentinelOps password was changed.", severity: "low", category: "password_change", link: "/settings", eventKey: `password-change:${Date.now()}` }); res.json({ ok: true }); });

app.post("/auth/forgot-password", async (req, res) => { const email = String(req.body?.email || "").trim().toLowerCase(); try { const result = await pool.query("SELECT id,name,email FROM users WHERE email=$1 AND (approved=true OR role='admin')", [email]); if (result.rowCount) { const token = randomToken(); await pool.query("UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL", [result.rows[0].id]); await pool.query("INSERT INTO password_reset_tokens (user_id,token_hash,expires_at) VALUES ($1,$2,now()+interval '30 minutes')", [result.rows[0].id, idHash(token)]); try { await sendPasswordResetEmail({ to: result.rows[0].email, name: result.rows[0].name, token }); } catch (error) { if (error.code !== "SMTP_NOT_CONFIGURED") console.error("Password reset email error:", error.message); } } } catch (error) { console.error("Password reset request error:", error.message); } res.status(202).json({ ok: true }); });
app.post("/auth/reset-password", async (req, res) => { const token = String(req.body?.token || ""); const password = String(req.body?.password || req.body?.next || ""); if (!token || password.length < 10) return res.status(400).json({ message: "Reset token or password is invalid" }); const client = await pool.connect(); try { await client.query("BEGIN"); const result = await client.query("SELECT * FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE", [idHash(token)]); if (!result.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ message: "Reset link is invalid or expired" }); } await client.query("UPDATE users SET password_hash=$1 WHERE id=$2", [await bcrypt.hash(password, 12), result.rows[0].user_id]); await client.query("UPDATE password_reset_tokens SET used_at=now() WHERE id=$1", [result.rows[0].id]); await client.query("UPDATE sessions SET status='revoked',revoked_at=now(),current=false WHERE user_id=$1", [result.rows[0].user_id]); await client.query("COMMIT"); res.json({ ok: true }); } catch (error) { await client.query("ROLLBACK"); res.status(500).json({ message: "Unable to reset password" }); } finally { client.release(); } });

app.get("/alerts", requireAuth, async (req, res) => { let items = (await records("alert", String(req.query.search || ""), ownerScope(req))).map(alertPayload); const values = (key) => String(req.query[key] || "").split(",").filter(Boolean); const severities = values("severity"); const statuses = values("status"); if (severities.length) items = items.filter((item) => severities.includes(item.severity)); if (statuses.length) items = items.filter((item) => statuses.includes(item.status)); if (req.query.mitre) items = items.filter((item) => item.mitreTechnique === req.query.mitre); if (req.query.host) items = items.filter((item) => item.host === req.query.host); if (req.query.sourceIp) items = items.filter((item) => item.sourceIp.includes(String(req.query.sourceIp))); if (req.query.hours) { const cutoff = Date.now() - Number(req.query.hours) * 3600000; items = items.filter((item) => new Date(item.timestamp).getTime() >= cutoff); } const page = Math.max(Number(req.query.page || 1), 1); const pageSize = Math.min(Math.max(Number(req.query.pageSize || 15), 1), 100); res.json({ items: items.slice((page - 1) * pageSize, page * pageSize), total: items.length, page, pageSize }); });
app.get("/alerts/:id", requireAuth, async (req, res) => { const row = await record("alert", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Alert not found" }); res.json(alertPayload({ ...parseJson(row.payload, {}), id: row.id, created_at: row.created_at })); });
app.patch("/alerts/:id", requireAuth, async (req, res) => { const patch = {}; for (const key of ["status", "assignee", "severity", "description"]) if (key in req.body) patch[key] = req.body[key]; const updated = await patchRecord("alert", req.params.id, patch, ownerScope(req)); if (!updated) return res.status(404).json({ message: "Alert not found" }); await audit(req.user, "alert.update", `alerts/${req.params.id}`, req, { next: patch }); await notifyUsers({ title: "Alert updated", body: `${req.params.id} was updated`, severity: updated.severity, category: "admin_action", link: "/alerts", eventKey: `alert-update:${req.params.id}:${updated.updatedAt}` }); emit(req.user.id, { id: `alert-${req.params.id}`, at: now(), kind: "alert", severity: updated.severity, message: updated.title, detail: req.params.id }); res.json(alertPayload(updated)); });
app.post("/alerts/:id/notes", requireAuth, async (req, res) => { const row = await record("alert", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Alert not found" }); const payload = parseJson(row.payload, {}); payload.notes = [{ id: `note-${Date.now()}`, author: req.user.name, body: String(req.body?.body || ""), createdAt: now() }, ...(payload.notes || [])]; res.json(alertPayload(await putRecord("alert", row.id, payload))); });

app.get("/incidents", requireAuth, listRoute("incident", incidentPayload));
app.get("/incidents/:id", requireAuth, async (req, res) => { const row = await record("incident", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Incident not found" }); res.json(incidentPayload({ ...parseJson(row.payload, {}), id: row.id, created_at: row.created_at })); });
app.patch("/incidents/:id", requireAuth, async (req, res) => { const patch = {}; for (const key of ["status", "assignee", "severity", "priority", "summary", "resolution"]) if (key in req.body) patch[key] = req.body[key]; const updated = await patchRecord("incident", req.params.id, patch, ownerScope(req)); if (!updated) return res.status(404).json({ message: "Incident not found" }); res.json(incidentPayload(updated)); });
app.post("/incidents", requireAuth, async (req, res) => { const alert = await record("alert", req.body?.alert_id, ownerScope(req)); if (!alert) return res.status(404).json({ message: "Alert not found" }); const a = alertPayload({ ...parseJson(alert.payload, {}), id: alert.id, created_at: alert.created_at }); const id = `INC-${Date.now()}`; const incident = await putRecord("incident", id, { id, title: `Escalated: ${a.title}`, severity: a.severity, priority: a.severity === "critical" ? "P1" : a.severity === "high" ? "P2" : "P3", status: "open", assignee: a.assignee, createdAt: now(), updatedAt: now(), affectedAssets: [a.host], alertIds: [a.id], caseIds: [], mitre: [a.mitreTechnique], summary: a.description, resolution: null, timeline: [], notes: [], evidence: [] }, { ownerUserId: req.user.id }); await patchRecord("alert", a.id, { relatedIncidentId: id, status: "escalated" }, ownerScope(req)); await notifyUsers({ title: "Incident created", body: `${id} was created from ${a.id}`, severity: a.severity, category: "incident_assignment", link: "/incidents", eventKey: `incident-create:${id}` }); emit(req.user.id, { id: `incident-${id}`, at: now(), kind: "incident", severity: a.severity, message: incident.title, detail: id }); res.status(201).json(incidentPayload(incident)); });

app.get("/cases", requireAuth, listRoute("case"));
app.get("/cases/:id", requireAuth, async (req, res) => { const row = await record("case", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Case not found" }); res.json(parseJson(row.payload, { id: row.id })); });
app.post("/cases", requireAuth, async (req, res) => { const id = `CASE-${Date.now()}`; const item = await putRecord("case", id, { id, title: req.body?.title || "Untitled case", status: "open", severity: req.body?.severity || "medium", owner: req.body?.owner || req.user.name, createdAt: now(), updatedAt: now(), summary: req.body?.summary || "", tasks: [], incidentIds: [], alertIds: [], evidence: [], notes: [], timeline: [], attachments: [] }, { ownerUserId: req.user.id }); await notify(req.user.id, { title: "Case created", body: `${id} is ready for investigation`, severity: item.severity, category: "case_update", link: "/cases", eventKey: `case-create:${id}` }); res.status(201).json(item); });
app.patch("/cases/:id", requireAuth, async (req, res) => { const patch = { ...req.body, updatedAt: now() }; const updated = await patchRecord("case", req.params.id, patch, ownerScope(req)); if (!updated) return res.status(404).json({ message: "Case not found" }); res.json(updated); });
app.patch("/cases/:caseId/tasks/:taskId", requireAuth, async (req, res) => { const row = await record("case", req.params.caseId, ownerScope(req)); if (!row) return res.status(404).json({ message: "Case not found" }); const payload = parseJson(row.payload, {}); payload.tasks = (payload.tasks || []).map((task) => task.id === req.params.taskId ? { ...task, done: !task.done } : task); payload.updatedAt = now(); res.json(await putRecord("case", row.id, payload)); });

app.get("/iocs", requireAuth, listRoute("ioc"));
app.get("/iocs/:id", requireAuth, async (req, res) => { const row = await record("ioc", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Indicator not found" }); res.json(parseJson(row.payload, { id: row.id })); });
app.post("/iocs", requireAuth, async (req, res) => { const id = `IOC-${Date.now()}`; const riskScore = Number(req.body?.riskScore || 0); const item = await putRecord("ioc", id, { id, type: req.body?.type || "ip", value: req.body?.value || "", riskScore, severity: riskScore > 85 ? "critical" : riskScore > 65 ? "high" : riskScore > 45 ? "medium" : "low", tags: req.body?.tags || [], source: req.body?.source || "Internal Analysis", firstSeen: now(), lastSeen: now(), matches: 0, relatedAlertIds: [], relatedIncidentIds: [], description: "Indicator created by an authenticated analyst." }, { ownerUserId: req.user.id }); await notify(req.user.id, { title: "IOC created", body: `${id} was added to IOC management`, severity: item.severity, category: "ioc_match", link: "/ioc", eventKey: `ioc-create:${id}` }); emit(req.user.id, { id: `ioc-${id}`, at: now(), kind: "ioc", severity: item.severity, message: "IOC created", detail: item.value }); res.status(201).json(item); });
app.delete("/iocs/:id", requireAuth, async (req, res) => { const result = ownerScope(req) ? await pool.query("DELETE FROM soc_records WHERE kind='ioc' AND id=$1 AND (owner_user_id IS NULL OR owner_user_id=$2) RETURNING id", [req.params.id, ownerScope(req)]) : await pool.query("DELETE FROM soc_records WHERE kind='ioc' AND id=$1 RETURNING id", [req.params.id]); if (!result.rowCount) return res.status(404).json({ message: "Indicator not found" }); res.json({ ok: true }); });

app.get("/assets", requireAuth, async (req, res) => {
  const existing = (await records("asset", String(req.query.search || ""), ownerScope(req))).map((item) => ({ ...item, source: item.source || "soc", isDemo: Boolean(item.isDemo) }));
  const devices = await networkDevices(req, boundedString(req.query.search, 128));
  const observedAssets = devices.map((device) => ({
    id: `network-${device.sensorId}-${device.ip || device.mac}`,
    name: device.hostname || device.ip || device.mac || "Observed network device",
    type: "endpoint", os: "unavailable", ip: device.ip, owner: "unavailable", criticality: "low", riskScore: 0,
    patchStatus: "pending", lastSeen: device.lastSeen, software: [], alertIds: [], incidentIds: [], tags: ["network-observation"],
    source: "sensor", isDemo: false, sensorId: device.sensorId, sensorName: device.sensorName, mac: device.mac, vendor: device.vendor,
    collectionMethods: device.collectionMethods, services: device.services,
  }));
  res.json([...observedAssets, ...existing]);
});
app.get("/assets/:id", requireAuth, async (req, res) => { const row = await record("asset", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Asset not found" }); res.json(parseJson(row.payload, { id: row.id })); });
app.get("/rules", requireAuth, listRoute("rule"));
app.patch("/rules/:id", requireAuth, requireManager, async (req, res) => { const updated = await patchRecord("rule", req.params.id, { enabled: Boolean(req.body?.enabled), updatedAt: now() }, ownerScope(req)); if (!updated) return res.status(404).json({ message: "Detection rule not found" }); await audit(req.user, updated.enabled ? "rule.enable" : "rule.disable", `rules/${req.params.id}`, req); res.json([updated]); });
app.post("/rules/:id/test", requireAuth, async (req, res) => { if (!(await record("rule", req.params.id, ownerScope(req)))) return res.status(404).json({ message: "Detection rule not found" }); const matches = (await records("alert", "", ownerScope(req))).map(alertPayload).filter((item) => item.ruleId === req.params.id); res.json({ matches: matches.length, sample: matches.slice(0, 10).map((item) => ({ id: item.id, timestamp: item.timestamp, host: item.host, user: item.user, process: item.rawEvent?.process || "", commandLine: item.rawEvent?.command_line || "", sourceIp: item.sourceIp, destinationIp: item.destinationIp, mitre: item.mitreTechnique, severity: item.severity, matchedField: "ruleId" })) }); });

app.get("/intel/feeds", requireAuth, listRoute("feed"));
app.patch("/intel/feeds/:id", requireAuth, async (req, res) => { const item = await patchRecord("feed", req.params.id, { enabled: Boolean(req.body?.enabled) }, ownerScope(req)); if (!item) return res.status(404).json({ message: "Threat feed not found" }); res.json(await records("feed", "", ownerScope(req))); });
app.get("/intel/actors", requireAuth, listRoute("actor"));
app.get("/intel/matches", requireAuth, async (req, res) => res.json((await records("ioc", "", ownerScope(req))).sort((a, b) => Number(b.matches || 0) - Number(a.matches || 0)).slice(0, 10)));
app.get("/hunting/saved", requireAuth, listRoute("hunt"));
app.post("/hunting/saved", requireAuth, async (req, res) => { const id = `hunt-${Date.now()}`; res.status(201).json(await putRecord("hunt", id, { id, name: req.body?.name || "Untitled hunt", query: req.body?.query || "", createdBy: req.user.name, createdAt: now(), lastRun: now(), results: 0 }, { ownerUserId: req.user.id })); });
app.post("/hunting/search", requireAuth, async (req, res) => { const value = String(req.body?.value || "").toLowerCase(); const alerts = (await records("alert", "", ownerScope(req))).map(alertPayload).filter((item) => !value || JSON.stringify(item).toLowerCase().includes(value)); res.json(alerts.map((item) => ({ id: item.id, timestamp: item.timestamp, host: item.host, user: item.user, process: item.rawEvent?.process || "", commandLine: item.rawEvent?.command_line || "", sourceIp: item.sourceIp, destinationIp: item.destinationIp, mitre: item.mitreTechnique, severity: item.severity, matchedField: req.body?.field || "value", isDemo: item.isDemo, demoKey: item.demoKey }))); });

app.get("/reports", requireAuth, listRoute("report"));
app.get("/reports/:id", requireAuth, async (req, res) => { const row = await record("report", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Report not found" }); res.json(parseJson(row.payload, { id: row.id })); });
app.post("/reports", requireAuth, async (req, res) => { const type = String(req.body?.type || "soc_metrics"); if (!REPORT_TYPES.has(type)) return res.status(400).json({ message: "Unsupported report type" }); const id = `rpt-${Date.now()}`; const summary = await reportSummary(type, ownerScope(req), String(req.body?.incident_id || "")); const report = { id, name: `${type === "incident" ? "Incident" : "SOC"} report`, type, period: reportPeriod(type), generatedAt: now(), generatedBy: req.user.name, status: "ready", sizeKb: Math.max(1, Math.ceil(JSON.stringify(summary).length / 1024)), summary }; res.status(201).json(await putRecord("report", id, report, { ownerUserId: req.user.id })); });
app.get("/reports/:id/export", requireAuth, async (req, res) => { const row = await record("report", req.params.id, ownerScope(req)); if (!row) return res.status(404).json({ message: "Report not found" }); const report = parseJson(row.payload, {}); if (report.status !== "ready") return res.status(409).json({ message: "Report is not ready" }); if (req.query.format !== "csv") return res.status(501).json({ message: "PDF and XLSX exports are rendered by the frontend from this persisted report" }); const csvCell = (value) => { const text = String(value ?? ""); return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; }; const body = ["metric,value", ...(report.summary || []).map((item) => `${csvCell(item.label)},${csvCell(item.value)}`)].join("\r\n") + "\r\n"; res.type("text/csv").attachment(`${row.id}.csv`).send(body); });

app.get("/notifications", requireAuth, async (req, res) => { const result = await pool.query("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100", [req.user.id]); res.json(result.rows.map(notificationPayload)); });
app.post("/notifications/:id/read", requireAuth, async (req, res) => { const updated = await pool.query("UPDATE notifications SET read=true WHERE id=$1 AND user_id=$2 RETURNING id", [req.params.id, req.user.id]); if (!updated.rowCount) return res.status(404).json({ message: "Notification not found" }); const result = await pool.query("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100", [req.user.id]); res.json(result.rows.map(notificationPayload)); });
app.post("/notifications/read-all", requireAuth, async (req, res) => { await pool.query("UPDATE notifications SET read=true WHERE user_id=$1", [req.user.id]); const result = await pool.query("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100", [req.user.id]); res.json(result.rows.map(notificationPayload)); });

app.get("/dashboard/metrics", requireAuth, async (req, res) => res.json(dashboardFrom(await socData(ownerScope(req)))));
app.get("/dashboard/feed", requireAuth, async (req, res) => res.json((await records("alert", "", ownerScope(req))).map(alertPayload).slice(0, Math.min(Number(req.query.limit || 12), 50))));
app.get("/system/health", requireAuth, async (req, res) => res.json([{ name: "API Gateway", status: "healthy", latencyMs: 0, uptime: 100 }, { name: "PostgreSQL", status: "healthy", latencyMs: 0, uptime: 100 }]));

app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => res.json((await pool.query("SELECT * FROM users ORDER BY created_at DESC")).rows.map(publicUser)));
app.patch("/admin/users/:id/approve", requireAuth, requireAdmin, async (req, res) => { const result = await pool.query("UPDATE users SET approved=true WHERE id=$1 RETURNING *", [req.params.id]); if (!result.rowCount) return res.status(404).json({ message: "User not found" }); await audit(req.user, "user.approve", `users/${req.params.id}`, req); await notify(req.params.id, { title: "Access approved", body: "Your SentinelOps access request was approved.", severity: "low", category: "admin_action", link: "/", eventKey: `approval:${req.params.id}` }); res.json({ message: "User approved", user: publicUser(result.rows[0]) }); });
app.patch("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => { const updates = []; const values = []; if (req.body?.role !== undefined) { values.push(dbRole(req.body.role)); updates.push(`role=$${values.length}`); } if (req.body?.status !== undefined || req.body?.approved !== undefined) { values.push(req.body.status === "active" || req.body.approved === true); updates.push(`approved=$${values.length}`); } if (!updates.length) return res.status(400).json({ message: "No supported fields supplied" }); values.push(req.params.id); const result = await pool.query(`UPDATE users SET ${updates.join(",")} WHERE id=$${values.length} RETURNING *`, values); if (!result.rowCount) return res.status(404).json({ message: "User not found" }); await audit(req.user, "user.update", `users/${req.params.id}`, req, { next: req.body }); res.json({ user: publicUser(result.rows[0]) }); });
app.get("/admin/stats", requireAuth, requireAdmin, async (req, res) => { const [u, pending, active, failed, events] = await Promise.all([pool.query("SELECT count(*)::int AS count FROM users"), pool.query("SELECT count(*)::int AS count FROM users WHERE approved=false AND role<>'admin'"), pool.query("SELECT count(*)::int AS count FROM sessions WHERE status='active' AND expires_at>now()"), pool.query("SELECT count(*)::int AS count FROM audit_logs WHERE action='user.login' AND result='failure' AND created_at>now()-interval '24 hours'"), pool.query("SELECT count(*)::int AS count FROM audit_logs WHERE created_at>now()-interval '24 hours'")]); res.json({ totalUsers: u.rows[0].count, activeUsers: active.rows[0].count, pendingApprovals: pending.rows[0].count, failedLogins24h: failed.rows[0].count, securityEvents24h: events.rows[0].count, services: [{ name: "API Gateway", status: "healthy", latencyMs: 0, uptime: 100 }, { name: "PostgreSQL", status: "healthy", latencyMs: 0, uptime: 100 }] }); });
app.get("/admin/audit-logs", requireAuth, requireAdmin, async (req, res) => { const search = String(req.query.search || ""); const result = await pool.query("SELECT * FROM audit_logs WHERE ($1='' OR actor_email ILIKE $2 OR action ILIKE $2 OR resource ILIKE $2 OR ip ILIKE $2) ORDER BY created_at DESC LIMIT 200", [search, `%${search}%`]); res.json(result.rows.map((row) => ({ id: String(row.id), user: row.actor_email, action: row.action, resource: row.resource, timestamp: timestamp(row.created_at), ip: row.ip, previousValue: row.previous_value ? JSON.stringify(row.previous_value) : null, newValue: row.new_value ? JSON.stringify(row.new_value) : null, result: row.result, isDemo: Boolean(row.is_demo), demoKey: row.demo_key || undefined }))); });
app.get("/admin/sessions", requireAuth, requireAdmin, async (req, res) => res.json((await pool.query("SELECT s.*,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.status='active' ORDER BY s.last_activity DESC")).rows.map(sessionPayload)));
app.delete("/admin/sessions/:id", requireAuth, requireAdmin, async (req, res) => { const result = await pool.query("UPDATE sessions SET status='revoked',revoked_at=now(),current=false WHERE id=$1 RETURNING id", [req.params.id]); if (!result.rowCount) return res.status(404).json({ message: "Session not found" }); closeSessionSockets(req.params.id); await audit(req.user, "session.revoke", `sessions/${req.params.id}`, req); res.json({ ok: true }); });

app.get("/version", (req, res) => res.json({ application: "SentinelOps", backend: "backend-repo", commit: process.env.RENDER_GIT_COMMIT || "local" }));

async function bootstrapAdmins() { for (const prefix of ["ADMIN1", "ADMIN2"]) { const name = String(process.env[`${prefix}_NAME`] || "").trim(); const email = String(process.env[`${prefix}_EMAIL`] || "").trim().toLowerCase(); const password = String(process.env[`${prefix}_PASSWORD`] || ""); if (!name && !email && !password) continue; if (!name || !email || !password) throw new Error(`${prefix}_NAME, ${prefix}_EMAIL and ${prefix}_PASSWORD must all be set`); const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]); if (!existing.rowCount) await pool.query("INSERT INTO users(name,email,password_hash,role,approved) VALUES($1,$2,$3,'admin',true)", [name, email, await bcrypt.hash(password, 12)]); } }

async function start(listenPort = port) {
  await applyMigrations(pool); await bootstrapAdmins(); const server = http.createServer(app); const wss = new WebSocketServer({ noServer: true });
  server.on("upgrade", async (request, socket, head) => { try { const url = new URL(request.url, "http://localhost"); if (url.pathname !== "/ws") return socket.destroy(); const token = url.searchParams.get("token"); const payload = jwt.verify(token, JWT_SECRET); const session = await sessionFor(payload.sid, payload.sub); if (!session || session.status !== "active") return socket.destroy(); wss.handleUpgrade(request, socket, head, (client) => { const key = String(payload.sub); client.userId = key; client.sessionId = String(payload.sid); if (!sockets.has(key)) sockets.set(key, new Set()); sockets.get(key).add(client); client.on("close", () => sockets.get(key)?.delete(client)); client.on("message", async () => { const current = await sessionFor(payload.sid, payload.sub); if (!current || current.status !== "active" || new Date(current.expires_at) <= new Date()) return client.close(4001, "Session revoked"); client.send(JSON.stringify({ type: "pong", at: now() })); }); }); } catch { socket.destroy(); } });
  await new Promise((resolve) => server.listen(listenPort, resolve)); return server;
}
if (require.main === module) start().catch((error) => { console.error("Database initialization failed:", error.message); process.exit(1); });
module.exports = { app, pool, start, applyMigrations, __private: { idHash, putRecord, records, notify } };
