const BASE = "2026-01-15T09:00:00.000Z";

const PEOPLE = [
  ["demo-tushar", "Tushar", "tushar.demo@sentinelops.local", "SOC Manager"],
  ["demo-deepanshu", "Deepanshu", "deepanshu.demo@sentinelops.local", "SOC Analyst L2"],
  ["demo-suraj", "Suraj", "suraj.demo@sentinelops.local", "SOC Analyst L2"],
  ["demo-aditya", "Aditya", "aditya.demo@sentinelops.local", "SOC Analyst L1"],
  ["demo-vansh", "Vansh", "vansh.demo@sentinelops.local", "Administrator"],
];

const ANALYSTS = ["Deepanshu", "Suraj", "Aditya", "Tushar"];
const SEVERITIES = ["critical", "high", "medium", "low"];
const MITRE = [
  ["T1059.001", "PowerShell", "Execution"],
  ["T1110.003", "Password Spraying", "Credential Access"],
  ["T1071.001", "Web Protocols", "Command and Control"],
  ["T1021.001", "Remote Desktop Protocol", "Lateral Movement"],
  ["T1190", "Exploit Public-Facing Application", "Initial Access"],
  ["T1566.001", "Spearphishing Attachment", "Initial Access"],
  ["T1486", "Data Encrypted for Impact", "Impact"],
];

function at(minutesAgo) {
  return new Date(new Date(BASE).getTime() - minutesAgo * 60000).toISOString();
}

function note(id, author, body, minutesAgo) {
  return { id, author, body, createdAt: at(minutesAgo) };
}

function event(id, minutesAgo, actor, action, detail = "") {
  return { id, at: at(minutesAgo), actor, action, detail, severity: "info" };
}

function evidence(id, name, type, collectedBy, minutesAgo) {
  return {
    id,
    name,
    type,
    hash: `${"0123456789abcdef".repeat(4)}${id.slice(-2).padStart(2, "0")}`.slice(0, 64),
    collectedAt: at(minutesAgo),
    collectedBy,
  };
}

function demoPayload(payload) {
  return { isDemo: true, dataSource: "DEMO", ...payload };
}

function buildAlerts() {
  const ordinary = Array.from({ length: 24 }, (_, index) => {
    const number = String(index + 1).padStart(3, "0");
    const [technique, mitreName, tactic] = MITRE[index % 4];
    const severity = SEVERITIES[index % SEVERITIES.length];
    const host = ["FIN-WKS-2214", "VPN-GW-01", "SRV-FILE-02", "HR-WKS-1108"][index % 4];
    const sourceIp = `203.0.113.${20 + index}`;
    const id = `demo-alert-${number}`;
    return {
      kind: "alert",
      id,
      demoKey: id,
      payload: demoPayload({
        title: [
          "Encoded PowerShell on finance endpoint",
          "RDP password spray against VPN gateway",
          "Suspicious outbound beaconing",
          "New service installed on file server",
        ][index % 4],
        rule: `Demo ${mitreName} detection`,
        ruleId: `demo-rule-${String((index % 8) + 1).padStart(3, "0")}`,
        severity,
        status: ["new", "investigating", "escalated", "false_positive", "closed"][index % 5],
        sourceIp,
        destinationIp: `10.20.${index % 8}.${10 + index}`,
        host,
        user: ["svc_backup", "administrator", "j.doe", "a.tyagi"][index % 4],
        mitreTechnique: technique,
        mitreName,
        tactic,
        assignee: index % 5 === 0 ? null : ANALYSTS[index % ANALYSTS.length],
        timestamp: at(18 + index * 19),
        description: `Controlled demonstration alert on ${host}; this record does not represent live telemetry.`,
        rawEvent: {
          provider: "SentinelOps demonstration generator",
          simulation: true,
          process: ["powershell.exe", "rundll32.exe", "wmic.exe"][index % 3],
          command_line: "DEMO_ONLY event content",
          source_ip: sourceIp,
        },
        relatedIncidentId: `demo-incident-${String((index % 6) + 2).padStart(3, "0")}`,
        notes: [note(`demo-note-alert-${number}`, ANALYSTS[index % ANALYSTS.length], "Reviewed as marked demonstration data.", 20 + index)],
        timeline: [event(`demo-timeline-alert-${number}`, 18 + index * 19, "Detection Engine", "Detection triggered", "DEMO/SIMULATED")],
        riskScore: 35 + ((index * 7) % 60),
      }),
    };
  });

  const sqliId = "demo-alert-sqli-001";
  const sqli = {
    kind: "alert",
    id: sqliId,
    demoKey: sqliId,
    payload: demoPayload({
      title: "Simulated SQL injection attempt against training web application",
      rule: "SQL Injection Attempt in Authorized Lab",
      ruleId: "demo-rule-sqli-001",
      severity: "high",
      status: "investigating",
      sourceIp: "198.51.100.42",
      destinationIp: "10.20.8.44",
      host: "WEB-LAB-01",
      user: "lab-user",
      mitreTechnique: "T1190",
      mitreName: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      assignee: "Deepanshu",
      timestamp: at(7),
      description: "Authorized-lab SQL injection simulation recorded for detection and reporting validation. SentinelOps did not execute the request and no production target is involved.",
      rawEvent: {
        provider: "Authorized SentinelOps lab generator",
        simulation: true,
        authorized_lab: true,
        execution: "not performed by SentinelOps",
        request_path: "/training/search",
        signature: "boolean-based SQL injection test marker",
        payload: "REDACTED_SAFE_TEST_MARKER",
      },
      relatedIncidentId: "demo-incident-sqli-001",
      notes: [note("demo-note-sqli-001", "Deepanshu", "Confirmed this is a synthetic lab event; requested WAF/application-log ingestion design for future real detections.", 6)],
      timeline: [
        event("demo-timeline-sqli-001", 7, "Detection Engine", "SQL injection simulation detected", "DEMO/SIMULATED authorized lab event"),
        event("demo-timeline-sqli-002", 5, "Deepanshu", "Alert triaged", "No production request was sent"),
      ],
      riskScore: 76,
    }),
  };
  return [sqli, ...ordinary];
}

function buildRecords() {
  const alerts = buildAlerts();
  const incidents = [
    {
      kind: "incident", id: "demo-incident-sqli-001", demoKey: "demo-incident-sqli-001",
      payload: demoPayload({
        title: "Authorized-lab SQL injection investigation",
        severity: "high", priority: "P2", status: "investigating", assignee: "Deepanshu",
        createdAt: at(10), updatedAt: at(4), affectedAssets: ["WEB-LAB-01"], alertIds: ["demo-alert-sqli-001"], caseIds: ["demo-case-sqli-001"],
        mitre: ["T1190"], summary: "Controlled SQL injection simulation correlated with the marked web-application alert.", resolution: null,
        timeline: [event("demo-timeline-incident-sqli-001", 4, "Deepanshu", "Investigation opened", "Synthetic authorized-lab scenario")],
        notes: [note("demo-note-incident-sqli-001", "Tushar", "Keep simulation labels visible in all downstream reports.", 3)], evidence: [evidence("demo-evidence-sqli-001", "authorized-lab-request.log", "Log", "Deepanshu", 6)],
      }),
    },
    ...Array.from({ length: 7 }, (_, index) => {
      const number = String(index + 2).padStart(3, "0");
      const id = `demo-incident-${number}`;
      const linked = alerts.slice(index * 3 + 1, index * 3 + 4).map((item) => item.id);
      return {
        kind: "incident", id, demoKey: id,
        payload: demoPayload({
          title: ["Finance endpoint credential-access review", "VPN password-spray investigation", "Suspicious file-server activity", "HR workstation phishing review"][index % 4],
          severity: SEVERITIES[(index + 1) % SEVERITIES.length], priority: index % 3 === 0 ? "P1" : "P2", status: ["open", "investigating", "containment", "resolved"][index % 4], assignee: ANALYSTS[index % ANALYSTS.length],
          createdAt: at(40 + index * 60), updatedAt: at(12 + index * 20), affectedAssets: [["FIN-WKS-2214"], ["VPN-GW-01"], ["SRV-FILE-02"], ["HR-WKS-1108"]][index % 4], alertIds: linked, caseIds: index % 2 ? [] : [`demo-case-${String(index + 1).padStart(3, "0")}`], mitre: [MITRE[(index + 1) % MITRE.length][0]],
          summary: "Interconnected demonstration investigation built from marked alert, asset and IOC records.", resolution: index % 4 === 3 ? "Demonstration investigation closed after simulated containment." : null,
          timeline: [event(`demo-timeline-incident-${number}`, 12 + index * 20, "Detection Engine", "Correlation completed", "DEMO/SIMULATED")], notes: [], evidence: [evidence(`demo-evidence-incident-${number}`, "correlation-summary.json", "Log", ANALYSTS[index % ANALYSTS.length], 15 + index)],
        }),
      };
    }),
  ];
  for (const incident of incidents) for (const alertId of incident.payload.alertIds) {
    const linkedAlert = alerts.find((alert) => alert.id === alertId);
    if (linkedAlert) linkedAlert.payload.relatedIncidentId = incident.id;
  }

  const cases = [
    {
      kind: "case", id: "demo-case-sqli-001", demoKey: "demo-case-sqli-001",
      payload: demoPayload({
        title: "SQL injection simulation reporting validation", status: "in_progress", severity: "high", owner: "Deepanshu", createdAt: at(9), updatedAt: at(3),
        summary: "Tracks the authorized-lab SQL injection alert through incident review and report generation.", tasks: [{ id: "demo-task-sqli-001", title: "Validate simulated event labeling", done: true, owner: "Deepanshu" }, { id: "demo-task-sqli-002", title: "Document future WAF log ingestion", done: false, owner: "Suraj" }],
        incidentIds: ["demo-incident-sqli-001"], alertIds: ["demo-alert-sqli-001"], evidence: [evidence("demo-evidence-case-sqli-001", "sqli-lab-correlation.json", "Log", "Deepanshu", 5)], notes: [], timeline: [event("demo-timeline-case-sqli-001", 3, "Deepanshu", "Case updated", "Report chain verified")], attachments: [{ id: "demo-attachment-sqli-001", name: "sqli-lab-report.csv", size: "8 KB", addedAt: at(2) }],
      }),
    },
    ...Array.from({ length: 7 }, (_, index) => {
      const number = String(index + 1).padStart(3, "0");
      const id = `demo-case-${number}`;
      return {
        kind: "case", id, demoKey: id,
        payload: demoPayload({ title: ["Finance endpoint review", "Identity anomaly review", "File-server activity review", "Phishing response review"][index % 4], status: ["open", "in_progress", "pending_review", "closed"][index % 4], severity: SEVERITIES[(index + 2) % SEVERITIES.length], owner: ANALYSTS[index % ANALYSTS.length], createdAt: at(90 + index * 80), updatedAt: at(15 + index * 12), summary: "Structured demonstration case linking alerts, incidents, evidence and analyst tasks.", tasks: [{ id: `demo-task-${number}-001`, title: "Review linked alert context", done: index % 2 === 0, owner: ANALYSTS[index % ANALYSTS.length] }, { id: `demo-task-${number}-002`, title: "Record containment decision", done: false, owner: ANALYSTS[(index + 1) % ANALYSTS.length] }], incidentIds: [`demo-incident-${String((index % 7) + 2).padStart(3, "0")}`], alertIds: alerts.slice(index * 2 + 1, index * 2 + 3).map((item) => item.id), evidence: [evidence(`demo-evidence-case-${number}`, "investigation-notes.txt", "Log", ANALYSTS[index % ANALYSTS.length], 20 + index)], notes: [], timeline: [event(`demo-timeline-case-${number}`, 15 + index, ANALYSTS[index % ANALYSTS.length], "Case reviewed", "DEMO/SIMULATED")], attachments: [] }),
      };
    }),
  ];

  const iocs = [
    { kind: "ioc", id: "demo-ioc-sqli-001", demoKey: "demo-ioc-sqli-001", payload: demoPayload({ type: "ip", value: "198.51.100.42", riskScore: 76, severity: "high", tags: ["demo", "simulated", "sqli", "authorized-lab"], source: "SentinelOps authorized lab", firstSeen: at(8), lastSeen: at(7), matches: 1, relatedAlertIds: ["demo-alert-sqli-001"], relatedIncidentIds: ["demo-incident-sqli-001"], description: "Documentation-range source address attached to an authorized SQL injection simulation; not a live threat attribution." }) },
    ...Array.from({ length: 23 }, (_, index) => { const id = `demo-ioc-${String(index + 1).padStart(3, "0")}`; const value = index % 2 ? `203.0.113.${60 + index}` : `demo-${index + 1}.sentinelops.local`; return { kind: "ioc", id, demoKey: id, payload: demoPayload({ type: index % 2 ? "ip" : "domain", value, riskScore: 25 + ((index * 11) % 70), severity: SEVERITIES[(index + 1) % SEVERITIES.length], tags: ["demo", index % 3 === 0 ? "credential-access" : "monitoring"], source: "SentinelOps demonstration feed", firstSeen: at(300 + index * 20), lastSeen: at(20 + index), matches: index % 6, relatedAlertIds: [alerts[(index + 1) % alerts.length].id], relatedIncidentIds: index % 3 === 0 ? [incidents[(index % 7) + 1].id] : [], description: "Marked demonstration indicator used to validate enrichment and correlation views." }) }; }),
  ];

  const assets = [
    ["WEB-LAB-01", "server", "10.20.8.44", "Application Engineering", "high"], ["FIN-WKS-2214", "endpoint", "10.20.4.18", "Finance", "high"], ["VPN-GW-01", "network", "10.20.0.5", "Network Operations", "critical"], ["SRV-FILE-02", "server", "10.20.2.22", "IT Infrastructure", "medium"], ["HR-WKS-1108", "endpoint", "10.20.6.18", "HR", "medium"], ["AZ-STORAGE-PRD", "cloud", "10.20.9.10", "Cloud Platform", "critical"], ["AWS-EKS-PROD", "cloud", "10.20.9.11", "Cloud Platform", "high"], ["NET-CORE-SW1", "network", "10.20.0.2", "Network Operations", "critical"],
  ].map(([name, type, ip, owner, criticality], index) => { const id = `demo-asset-${String(index + 1).padStart(3, "0")}`; const linkedAlerts = alerts.filter((item) => item.payload.host === name).map((item) => item.id); const linkedIncidents = incidents.filter((item) => item.payload.affectedAssets.includes(name)).map((item) => item.id); return { kind: "asset", id, demoKey: id, payload: demoPayload({ name, type, os: type === "cloud" ? "Linux (managed)" : type === "network" ? "Network appliance" : "Windows Server 2022", ip, owner, criticality, riskScore: criticality === "critical" ? 88 : criticality === "high" ? 74 : 52, patchStatus: index % 3 === 0 ? "pending" : "up_to_date", lastSeen: at(5 + index * 7), software: [{ name: "SentinelOps Demo Agent", version: "1.0.0", vulnerable: false }], alertIds: linkedAlerts, incidentIds: linkedIncidents, tags: ["demo", type === "server" ? "production-like" : "controlled-lab"], source: "soc" }) }; });

  const rules = [
    ["demo-rule-sqli-001", "SQL Injection Attempt in Authorized Lab", "high", "T1190", "Exploit Public-Facing Application"],
    ["demo-rule-001", "Encoded PowerShell Command Execution", "high", "T1059.001", "PowerShell"],
    ["demo-rule-002", "Password Spray Against VPN Gateway", "critical", "T1110.003", "Password Spraying"],
    ["demo-rule-003", "Suspicious Outbound Beaconing", "medium", "T1071.001", "Web Protocols"],
    ["demo-rule-004", "RDP Brute Force Attempt", "medium", "T1021.001", "Remote Desktop Protocol"],
    ["demo-rule-005", "Malicious Attachment Detonated", "critical", "T1566.001", "Spearphishing Attachment"],
    ["demo-rule-006", "Mass File Encryption Behaviour", "critical", "T1486", "Data Encrypted for Impact"],
    ["demo-rule-007", "New Service Installed on Domain Controller", "high", "T1543.003", "Windows Service"],
  ].map(([id, name, severity, mitre, mitreName], index) => ({ kind: "rule", id, demoKey: id, payload: demoPayload({ id, name, description: `Controlled demonstration rule for ${name.toLowerCase()}.`, severity, enabled: true, mitre, mitreName, source: "Custom", logic: "demo-only; no production query execution", lastTriggered: at(7 + index * 15), triggers30d: index === 0 ? 1 : 3 + index, falsePositiveRate: index === 0 ? 0 : index + 2, author: ANALYSTS[index % ANALYSTS.length], updatedAt: at(30 + index * 10) }) }));

  const feeds = [
    ["demo-feed-001", "SentinelOps Demonstration Feed", "Internal demo", 24, "A", true], ["demo-feed-002", "Authorized Lab Application Logs", "SentinelOps lab", 8, "A", true], ["demo-feed-003", "Reserved Documentation Indicators", "IANA documentation ranges", 16, "B", true], ["demo-feed-004", "Training Enrichment Feed", "Internal training", 42, "B", false],
  ].map(([id, name, provider, indicators, reliability, enabled], index) => ({ kind: "feed", id, demoKey: id, payload: demoPayload({ id, name, provider, enabled, indicators, lastSync: at(5 + index * 12), reliability }) }));

  const actors = [
    ["demo-actor-001", "Demo Operator", "Controlled dataset", "Training", ["T1059.001", "T1190"]], ["demo-actor-002", "Authorized Lab Client", "Internal lab", "Validation", ["T1190"]], ["demo-actor-003", "Simulation Generator", "SentinelOps", "Testing", ["T1059.001", "T1110.003"]],
  ].map(([id, name, origin, motivation, techniques], index) => ({ kind: "actor", id, demoKey: id, payload: demoPayload({ id, name, aliases: [], origin, motivation, activity: 20 + index * 15, lastSeen: at(8 + index * 20), techniques, targetSectors: ["Training"], summary: "Marked demonstration actor; not a live threat attribution." }) }));

  const hunts = [
    ["demo-hunt-sqli-001", "Authorized lab SQL injection review", "alert.ruleId:demo-rule-sqli-001", 1], ["demo-hunt-001", "Encoded PowerShell review", "process.name:powershell.exe", 5], ["demo-hunt-002", "Password spray review", "ruleId:demo-rule-002", 4], ["demo-hunt-003", "Demo IOC correlation", "isDemo:true", 12],
  ].map(([id, name, query, results], index) => ({ kind: "hunt", id, demoKey: id, payload: demoPayload({ id, name, query, createdBy: ANALYSTS[index % ANALYSTS.length], createdAt: at(240 + index * 60), lastRun: at(8 + index * 10), results }) }));

  const reports = [
    ["demo-report-daily-001", "DEMO Daily SOC Report", "daily_soc", "Controlled demonstration period", [["Marked demo alerts", String(alerts.length)], ["Marked demo incidents", String(incidents.length)], ["Open incidents", String(incidents.filter((item) => item.payload.status !== "resolved").length)], ["Simulation events", "1"]]],
    ["demo-report-weekly-001", "DEMO Weekly SOC Report", "weekly_soc", "Controlled demonstration week", [["Alerts", String(alerts.length)], ["Incidents", String(incidents.length)], ["IOC matches", String(iocs.reduce((sum, item) => sum + Number(item.payload.matches || 0), 0))]]],
    ["demo-report-monthly-001", "DEMO Monthly Executive Report", "monthly_soc", "Controlled demonstration month", [["Assets", String(assets.length)], ["Detection rules", String(rules.length)], ["Feeds", String(feeds.length)]]],
    ["demo-report-sqli-001", "DEMO SQL Injection Investigation Report", "incident", "Authorized lab scenario", [["Simulation alerts", "1"], ["Affected demo asset", "WEB-LAB-01"], ["Production requests sent", "0"], ["Evidence status", "Synthetic / authorized"]]],
    ["demo-report-metrics-001", "DEMO SOC Metrics", "soc_metrics", "Controlled demonstration period", [["MTTD", "6m"], ["MTTR", "41m"], ["Coverage", "100% of seeded modules"]]],
    ["demo-report-analyst-001", "DEMO Analyst Performance", "analyst_performance", "Controlled demonstration period", [["Analysts", String(ANALYSTS.length)], ["Cases reviewed", String(cases.length)], ["Generated records", "deterministic"]]],
    ["demo-report-fp-001", "DEMO False Positive Analysis", "false_positives", "Controlled demonstration period", [["False-positive alerts", String(alerts.filter((item) => item.payload.status === "false_positive").length)], ["Top rule", "demo-rule-003"], ["Simulation records", "excluded from live rate"]]],
  ].map(([id, name, type, period, summary], index) => ({ kind: "report", id, demoKey: id, payload: demoPayload({ id, name, type, period, generatedAt: at(3 + index * 6), generatedBy: "Vansh", status: "ready", sizeKb: 1, summary: summary.map(([label, value]) => ({ label, value })) }) }));

  return { alerts, incidents, cases, iocs, assets, rules, feeds, actors, hunts, reports };
}

module.exports = { BASE, PEOPLE, ANALYSTS, buildRecords, at };
