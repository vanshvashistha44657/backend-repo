const bcrypt = require("bcryptjs");
const { pool, applyMigrations } = require("../server");

const SEED_PASSWORD = process.env.DEMO_SEED_PASSWORD;
const BASE = "2026-01-15T09:00:00.000Z";
const PEOPLE = [
  ["demo-tushar", "Tushar", "tushar.demo@sentinelops.local", "SOC Manager"],
  ["demo-deepanshu", "Deepanshu", "deepanshu.demo@sentinelops.local", "SOC Analyst L2"],
  ["demo-suraj", "Suraj", "suraj.demo@sentinelops.local", "SOC Analyst L2"],
  ["demo-aditya", "Aditya", "aditya.demo@sentinelops.local", "SOC Analyst L1"],
  ["demo-vansh", "Vansh", "vansh.demo@sentinelops.local", "Administrator"],
];

function at(minutes) { return new Date(new Date(BASE).getTime() - minutes * 60000).toISOString(); }

async function insertUser(client, [demoKey, name, email, role], passwordHash) {
  const existing = await client.query("SELECT id,is_demo FROM users WHERE email=$1 OR demo_key=$2", [email, demoKey]);
  if (existing.rowCount) {
    if (!existing.rows[0].is_demo) throw new Error(`Refusing to touch non-demo user ${email}`);
    return existing.rows[0].id;
  }
  const result = await client.query("INSERT INTO users(name,email,password_hash,role,approved,created_at,is_demo,demo_key) VALUES($1,$2,$3,$4,true,$5,true,$6) RETURNING id", [name, email, passwordHash, role === "Administrator" ? "admin" : role === "SOC Manager" ? "manager" : role === "SOC Analyst L2" ? "analyst_l2" : "user", BASE, demoKey]);
  return result.rows[0].id;
}

async function insertRecord(client, kind, id, payload, demoKey) {
  const existing = await client.query("SELECT is_demo FROM soc_records WHERE id=$1 OR (kind=$2 AND demo_key=$3)", [id, kind, demoKey]);
  if (existing.rowCount) {
    if (!existing.rows[0].is_demo) throw new Error(`Refusing to touch non-demo ${kind} record ${id}`);
    return;
  }
  await client.query("INSERT INTO soc_records(id,kind,payload,created_at,updated_at,is_demo,demo_key) VALUES($1,$2,$3,$4,$4,true,$5)", [id, kind, JSON.stringify({ ...payload, id }), BASE, demoKey]);
}

async function run() {
  if (process.env.NODE_ENV === "production" || process.env.ALLOW_DEMO_SEED !== "true") throw new Error("Demo seeding is disabled. Set ALLOW_DEMO_SEED=true only for an isolated database.");
  if (!SEED_PASSWORD || SEED_PASSWORD.length < 10) throw new Error("DEMO_SEED_PASSWORD must be supplied through the environment and contain at least 10 characters.");
  await applyMigrations(pool);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const passwordHash = await bcrypt.hash(SEED_PASSWORD, 12);
    const users = {};
    for (const person of PEOPLE) users[person[0]] = await insertUser(client, person, passwordHash);

    await insertRecord(client, "alert", "demo-alert-001", { title: "Encoded PowerShell on finance endpoint", rule: "Encoded PowerShell Command Execution", ruleId: "DR-DEMO-001", severity: "high", status: "investigating", sourceIp: "203.0.113.44", destinationIp: "10.20.4.18", host: "FIN-WKS-2214", user: "svc_backup", mitreTechnique: "T1059.001", mitreName: "PowerShell", tactic: "Execution", assignee: "Deepanshu", timestamp: at(12), description: "Demonstration alert linked to the finance endpoint investigation.", rawEvent: { provider: "Demo telemetry", process: "powershell.exe", command_line: "powershell -enc DEMO_ONLY" }, relatedIncidentId: "demo-incident-001", notes: [], timeline: [{ id: "demo-timeline-001", at: at(12), actor: "Detection Engine", action: "Detection triggered" }], riskScore: 78 }, "demo-alert-001");
    await insertRecord(client, "alert", "demo-alert-002", { title: "RDP password spray against VPN gateway", rule: "Password Spray Against Azure AD", ruleId: "DR-DEMO-002", severity: "critical", status: "new", sourceIp: "198.51.100.27", destinationIp: "10.20.0.5", host: "VPN-GW-01", user: "administrator", mitreTechnique: "T1110.003", mitreName: "Password Spraying", tactic: "Credential Access", assignee: null, timestamp: at(38), description: "Demonstration credential-access alert; no live telemetry is implied.", rawEvent: { provider: "Demo telemetry", attempts: 17 }, relatedIncidentId: null, notes: [], timeline: [], riskScore: 91 }, "demo-alert-002");
    await insertRecord(client, "incident", "demo-incident-001", { title: "Finance endpoint credential access investigation", severity: "high", priority: "P2", status: "investigating", assignee: "Deepanshu", createdAt: at(30), updatedAt: at(8), affectedAssets: ["FIN-WKS-2214"], alertIds: ["demo-alert-001"], caseIds: ["demo-case-001"], mitre: ["T1059.001"], summary: "Controlled demonstration investigation correlating one marked demo alert.", resolution: null, timeline: [], notes: [], evidence: [] }, "demo-incident-001");
    await insertRecord(client, "case", "demo-case-001", { title: "Review finance endpoint activity", status: "in_progress", severity: "high", owner: "Deepanshu", createdAt: at(28), updatedAt: at(7), summary: "Demo case for validating linked alerts, incidents and analyst activity.", tasks: [{ id: "demo-task-001", title: "Review marked event context", done: true, owner: "Deepanshu" }, { id: "demo-task-002", title: "Document containment decision", done: false, owner: "Suraj" }], incidentIds: ["demo-incident-001"], alertIds: ["demo-alert-001"], evidence: [], notes: [], timeline: [], attachments: [] }, "demo-case-001");
    await insertRecord(client, "ioc", "demo-ioc-001", { type: "ip", value: "203.0.113.44", riskScore: 82, severity: "high", tags: ["demo", "credential-access"], source: "SentinelOps demonstration feed", firstSeen: at(120), lastSeen: at(12), matches: 2, relatedAlertIds: ["demo-alert-001"], relatedIncidentIds: ["demo-incident-001"], description: "Reserved documentation IP used only for demonstration data." }, "demo-ioc-001");
    await insertRecord(client, "asset", "demo-asset-001", { name: "FIN-WKS-2214", type: "endpoint", os: "Windows 11", ip: "10.20.4.18", owner: "Finance", criticality: "high", riskScore: 74, patchStatus: "pending", lastSeen: at(4), software: [], alertIds: ["demo-alert-001"], incidentIds: ["demo-incident-001"], tags: ["demo", "finance"] }, "demo-asset-001");
    await insertRecord(client, "rule", "demo-rule-001", { name: "Encoded PowerShell Command Execution", description: "Demonstration detection rule.", severity: "high", enabled: true, mitre: "T1059.001", mitreName: "PowerShell", source: "Custom", logic: "demo-only", lastTriggered: at(12), triggers30d: 1, falsePositiveRate: 0, author: "Tushar", updatedAt: at(12) }, "demo-rule-001");
    await insertRecord(client, "feed", "demo-feed-001", { name: "SentinelOps Demonstration Feed", provider: "Internal demo", enabled: true, indicators: 1, lastSync: at(5), reliability: "A" }, "demo-feed-001");
    await insertRecord(client, "actor", "demo-actor-001", { name: "Demo Operator", aliases: [], origin: "Controlled dataset", motivation: "Training", activity: 20, lastSeen: at(12), techniques: ["T1059.001"], targetSectors: ["Finance"], summary: "Marked demonstration actor; not a live threat attribution." }, "demo-actor-001");
    await insertRecord(client, "hunt", "demo-hunt-001", { name: "Demo PowerShell review", query: "process.name:powershell.exe", createdBy: "Tushar", createdAt: at(70), lastRun: at(10), results: 1 }, "demo-hunt-001");
    await insertRecord(client, "report", "demo-report-001", { name: "Demo SOC Report", type: "daily_soc", period: "Controlled demonstration period", generatedAt: at(3), generatedBy: "Vansh", status: "ready", sizeKb: 1, summary: [{ label: "Marked demo alerts", value: "2" }, { label: "Marked demo incidents", value: "1" }] }, "demo-report-001");

    for (const [key, userId] of Object.entries(users)) await client.query("INSERT INTO audit_logs(actor_user_id,actor_email,action,resource,ip,created_at,is_demo,demo_key) VALUES($1,$2,'demo.seed', $3,'203.0.113.10',$4,true,$5) ON CONFLICT DO NOTHING", [userId, `${key}@sentinelops.local`, `demo/${key}`, BASE, `demo-audit-${key}`]);
    for (const [key, userId] of Object.entries(users)) await client.query("INSERT INTO notifications(user_id,title,body,severity,category,link,event_key,created_at,is_demo,demo_key) VALUES($1,'Demo notification','Marked demonstration notification for controlled SOC data.','medium','system','/notifications',$2,$3,true,$4) ON CONFLICT DO NOTHING", [userId, `demo-notification-${key}`, BASE, `demo-notification-${key}`]);
    await client.query("COMMIT");
    console.log(JSON.stringify({ seeded: true, demoUsers: PEOPLE.length, records: 12, baseTimestamp: BASE }));
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); await pool.end(); }
}

if (require.main === module) run().catch((error) => { console.error(error.message); process.exit(1); });
module.exports = { run, PEOPLE, BASE };
