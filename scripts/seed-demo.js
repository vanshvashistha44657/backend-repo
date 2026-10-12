const { BASE, PEOPLE, ANALYSTS, buildRecords, at } = require("../lib/demo-fixtures");

const SEED_PASSWORD = process.env.DEMO_SEED_PASSWORD;
const DRY_RUN = process.argv.includes("--dry-run") || process.env.DEMO_SEED_DRY_RUN === "true";
let bcrypt;
let pool;
let applyMigrations;
if (!DRY_RUN) {
  bcrypt = require("bcryptjs");
  ({ pool, applyMigrations } = require("../server"));
}

function recordDate(value) {
  const parsed = value ? new Date(value) : new Date(BASE);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : BASE;
}

async function insertUser(client, [demoKey, name, email, role], passwordHash) {
  const existing = await client.query("SELECT id,is_demo FROM users WHERE email=$1 OR demo_key=$2", [email, demoKey]);
  if (existing.rowCount) {
    if (!existing.rows[0].is_demo) throw new Error(`Refusing to touch non-demo user ${email}`);
    await client.query("UPDATE users SET name=$1,role=$2,approved=true WHERE id=$3", [name, role === "Administrator" ? "admin" : role === "SOC Manager" ? "manager" : role === "SOC Analyst L2" ? "analyst_l2" : "user", existing.rows[0].id]);
    return existing.rows[0].id;
  }
  const result = await client.query("INSERT INTO users(name,email,password_hash,role,approved,created_at,is_demo,demo_key) VALUES($1,$2,$3,$4,true,$5,true,$6) RETURNING id", [name, email, passwordHash, role === "Administrator" ? "admin" : role === "SOC Manager" ? "manager" : role === "SOC Analyst L2" ? "analyst_l2" : "user", BASE, demoKey]);
  return result.rows[0].id;
}

async function upsertRecord(client, record) {
  const existing = await client.query("SELECT id,is_demo FROM soc_records WHERE id=$1 OR (kind=$2 AND demo_key=$3)", [record.id, record.kind, record.demoKey]);
  if (existing.rowCount && !existing.rows[0].is_demo) throw new Error(`Refusing to touch non-demo ${record.kind} record ${record.id}`);
  const payload = { ...record.payload, id: record.id };
  const createdAt = recordDate(payload.createdAt || payload.timestamp || payload.generatedAt);
  const updatedAt = recordDate(payload.updatedAt || createdAt);
  if (existing.rowCount) {
    await client.query("UPDATE soc_records SET kind=$1,payload=$2,created_at=$3,updated_at=$4,is_demo=true,demo_key=$5 WHERE id=$6", [record.kind, JSON.stringify(payload), createdAt, updatedAt, record.demoKey, existing.rows[0].id]);
    return;
  }
  await client.query("INSERT INTO soc_records(id,kind,payload,created_at,updated_at,is_demo,demo_key) VALUES($1,$2,$3,$4,$5,true,$6)", [record.id, record.kind, JSON.stringify(payload), createdAt, updatedAt, record.demoKey]);
}

async function upsertSession(client, userId, index) {
  const id = `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;
  const demoKey = `demo-session-${String(index + 1).padStart(3, "0")}`;
  const existing = await client.query("SELECT id,is_demo FROM sessions WHERE id=$1 OR demo_key=$2", [id, demoKey]);
  if (existing.rowCount && !existing.rows[0].is_demo) throw new Error(`Refusing to touch non-demo session ${demoKey}`);
  const startedAt = at(60 + index * 30);
  const lastActivity = at(index * 4);
  const expiresAt = new Date(new Date(BASE).getTime() + 30 * 86400000).toISOString();
  await client.query(`INSERT INTO sessions(id,user_id,refresh_token_hash,status,started_at,last_activity,expires_at,ip,user_agent,device,location,current,is_demo,demo_key)
    VALUES($1,$2,NULL,'active',$3,$4,$5,$6,$7,$8,$9,$10,true,$11)
    ON CONFLICT(id) DO UPDATE SET user_id=EXCLUDED.user_id,status='active',started_at=EXCLUDED.started_at,last_activity=EXCLUDED.last_activity,expires_at=EXCLUDED.expires_at,ip=EXCLUDED.ip,user_agent=EXCLUDED.user_agent,device=EXCLUDED.device,location=EXCLUDED.location,current=EXCLUDED.current,is_demo=true,demo_key=EXCLUDED.demo_key`, [id, userId, startedAt, lastActivity, expiresAt, `10.20.0.${20 + index}`, "SentinelOps demo browser", index === 0 ? "Chrome browser" : "Firefox browser", ["Delhi, IN", "Pune, IN", "Bengaluru, IN", "Mumbai, IN", "Hyderabad, IN"][index], index === 0, demoKey]);
}

async function upsertAudit(client, userId, email, index, action, resource) {
  const demoKey = `demo-audit-${String(index + 1).padStart(3, "0")}`;
  await client.query(`INSERT INTO audit_logs(actor_user_id,actor_email,action,resource,ip,previous_value,new_value,result,created_at,is_demo,demo_key)
    VALUES($1,$2,$3,$4,$5,$6,$7,'success',$8,true,$9)
    ON CONFLICT (demo_key) WHERE demo_key IS NOT NULL DO UPDATE SET actor_user_id=EXCLUDED.actor_user_id,actor_email=EXCLUDED.actor_email,action=EXCLUDED.action,resource=EXCLUDED.resource,ip=EXCLUDED.ip,previous_value=EXCLUDED.previous_value,new_value=EXCLUDED.new_value,result='success',created_at=EXCLUDED.created_at,is_demo=true`, [userId, email, action, resource, `10.20.0.${40 + index}`, index % 3 === 0 ? JSON.stringify({ status: "new" }) : null, index % 3 === 0 ? JSON.stringify({ status: "investigating", isDemo: true }) : null, at(5 + index * 5), demoKey]);
}

async function upsertNotification(client, userId, index, record) {
  const demoKey = `demo-notification-${String(index + 1).padStart(3, "0")}`;
  await client.query(`INSERT INTO notifications(user_id,title,body,severity,category,read,link,event_key,created_at,is_demo,demo_key)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,true,$10)
    ON CONFLICT (demo_key) WHERE demo_key IS NOT NULL DO UPDATE SET user_id=EXCLUDED.user_id,title=EXCLUDED.title,body=EXCLUDED.body,severity=EXCLUDED.severity,category=EXCLUDED.category,read=EXCLUDED.read,link=EXCLUDED.link,event_key=EXCLUDED.event_key,created_at=EXCLUDED.created_at,is_demo=true`, [userId, record.title, record.body, record.severity, record.category, index > 1, record.link, demoKey, at(3 + index * 4), demoKey]);
}

function proposedRecords(records) {
  return Object.values(records).flat().map((record) => ({ kind: record.kind, id: record.id, demoKey: record.demoKey, label: record.payload.title || record.payload.name || record.payload.value || record.payload.type || record.id }));
}

async function run() {
  if (!DRY_RUN && (process.env.NODE_ENV === "production" || process.env.ALLOW_DEMO_SEED !== "true")) throw new Error("Demo seeding is disabled. Set ALLOW_DEMO_SEED=true only for an isolated database.");
  if (!DRY_RUN && (!SEED_PASSWORD || SEED_PASSWORD.length < 10)) throw new Error("DEMO_SEED_PASSWORD must be supplied through the environment and contain at least 10 characters.");

  const records = buildRecords();
  const summary = {
    baseTimestamp: BASE,
    people: PEOPLE.map(([demoKey, name, email, role]) => ({ demoKey, name, email, role })),
    counts: Object.fromEntries(Object.entries(records).map(([kind, items]) => [kind, items.length])),
    totalRecords: Object.values(records).reduce((sum, items) => sum + items.length, 0),
    sqlInjectionScenario: {
      alertId: "demo-alert-sqli-001",
      incidentId: "demo-incident-sqli-001",
      caseId: "demo-case-sqli-001",
      reportId: "demo-report-sqli-001",
      sourceIp: "198.51.100.42",
      target: "WEB-LAB-01",
      authorizedLab: true,
      productionRequestsSent: 0,
    },
  };
  if (DRY_RUN) {
    console.log(JSON.stringify({ dryRun: true, ...summary, proposedRecords: proposedRecords(records) }, null, 2));
    return summary;
  }

  await applyMigrations(pool);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const passwordHash = await bcrypt.hash(SEED_PASSWORD, 12);
    const users = {};
    for (const person of PEOPLE) users[person[0]] = await insertUser(client, person, passwordHash);
    for (const collection of Object.values(records)) for (const record of collection) await upsertRecord(client, record);
    for (let index = 0; index < PEOPLE.length; index += 1) await upsertSession(client, users[PEOPLE[index][0]], index);

    const notificationTemplates = [
      { title: "Demo alert requires review", body: "A marked demonstration alert is ready in the SOC queue.", severity: "high", category: "critical_alert", link: "/alerts" },
      { title: "Simulated SQL injection recorded", body: "Authorized-lab SQL injection simulation is linked to demo-incident-sqli-001; no production request was sent.", severity: "high", category: "incident_assignment", link: "/incidents" },
      { title: "Demo report generated", body: "The deterministic SOC demonstration report set is ready for review.", severity: "low", category: "admin_action", link: "/reports" },
    ];
    for (let userIndex = 0; userIndex < PEOPLE.length; userIndex += 1) {
      const [demoKey, , email] = PEOPLE[userIndex];
      for (let templateIndex = 0; templateIndex < notificationTemplates.length; templateIndex += 1) await upsertNotification(client, users[demoKey], userIndex * notificationTemplates.length + templateIndex, notificationTemplates[templateIndex]);
      for (let auditIndex = 0; auditIndex < 8; auditIndex += 1) await upsertAudit(client, users[demoKey], email, userIndex * 8 + auditIndex, ["demo.seed", "alert.triage", "incident.assign", "case.update", "ioc.enrich", "report.generate", "rule.enable", "session.review"][auditIndex], ["demo/dataset", "alerts/demo-alert-sqli-001", "incidents/demo-incident-sqli-001", "cases/demo-case-sqli-001", "iocs/demo-ioc-sqli-001", "reports/demo-report-sqli-001", "rules/demo-rule-sqli-001", `sessions/demo-${userIndex + 1}`][auditIndex]);
    }
    await client.query("COMMIT");
    console.log(JSON.stringify({ seeded: true, ...summary }, null, 2));
    return summary;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

if (require.main === module) run().catch((error) => { console.error(error.message); process.exit(1); });

module.exports = { run, PEOPLE, BASE, buildRecords, ANALYSTS };
