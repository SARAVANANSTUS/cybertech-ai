const { execFile } = require("child_process");
const { promisify } = require("util");
const xml2js = require("xml2js");

const execFileAsync = promisify(execFile);
const parser = new xml2js.Parser({ explicitArray: false, mergeAttrs: true });

const OPENVAS_TRANSPORT = process.env.OPENVAS_TRANSPORT || "tls";
const OPENVAS_HOST = process.env.OPENVAS_HOST || "127.0.0.1";
const OPENVAS_PORT = process.env.OPENVAS_PORT || "9390";
const OPENVAS_USER = process.env.OPENVAS_USER || "admin";
const OPENVAS_PASSWORD = process.env.OPENVAS_PASSWORD || "admin";
const OPENVAS_SOCKET_PATH = process.env.OPENVAS_SOCKET_PATH || "/run/gvmd/gvmd.sock";
const OPENVAS_SCAN_CONFIG = process.env.OPENVAS_SCAN_CONFIG || "Full and fast";
const OPENVAS_PORT_LIST = process.env.OPENVAS_PORT_LIST || "All IANA assigned TCP";

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function toArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

async function parseXml(xmlText) {
  return parser.parseStringPromise(xmlText);
}

function getRoot(xmlObject) {
  const key = Object.keys(xmlObject)[0];
  return xmlObject[key] || {};
}

async function runGmpCommand(xmlPayload) {
  const args = [
    "--gmp-username",
    OPENVAS_USER,
    "--gmp-password",
    OPENVAS_PASSWORD
  ];

  if (OPENVAS_TRANSPORT === "socket") {
    args.push("socket", "--socketpath", OPENVAS_SOCKET_PATH, "--xml", xmlPayload);
  } else {
    args.push("tls", "--hostname", OPENVAS_HOST, "--port", String(OPENVAS_PORT), "--xml", xmlPayload);
  }

  try {
    const { stdout } = await execFileAsync("gvm-cli", args, { timeout: 120000, maxBuffer: 20 * 1024 * 1024 });
    return stdout;
  } catch (err) {
    const message = err?.stderr || err?.stdout || err?.message || "gvm-cli call failed";
    const commandNameMatch = String(xmlPayload || "").match(/^\s*<\s*([a-z_]+)/i);
    const commandName = commandNameMatch?.[1] || "unknown_command";
    throw new Error("OpenVAS command failed (" + commandName + "): " + message);
  }
}

async function getScanConfigIdByName(configName) {
  const xml = await runGmpCommand('<get_configs config_type="scan"/>');
  const parsed = await parseXml(xml);
  const root = getRoot(parsed);
  const configs = toArray(root?.config || root?.scan_config);

  const match = configs.find(cfg => String(cfg?.name || "").toLowerCase() === String(configName).toLowerCase());
  if (!match?.id) {
    throw new Error(`OpenVAS scan config not found: ${configName}`);
  }

  return match.id;
}


async function getPortListId() {
  const xml = await runGmpCommand('<get_port_lists/>');
  const parsed = await parseXml(xml);
  const root = getRoot(parsed);
  const lists = toArray(root?.port_list);

  if (!lists.length) {
    throw new Error("No OpenVAS port lists found");
  }

  const preferredNames = [
    OPENVAS_PORT_LIST,
    "All IANA assigned TCP and UDP",
    "All IANA assigned TCP"
  ];

  for (const name of preferredNames) {
    const wanted = String(name || "").trim().toLowerCase();
    if (!wanted) continue;

    const match = lists.find(item => String(item?.name || "").toLowerCase() === wanted);
    if (match?.id) {
      return match.id;
    }
  }

  return lists[0].id;
}
async function getLatestReportId(taskId) {
  const xml = await runGmpCommand(`<get_tasks task_id="${escapeXml(taskId)}" details="0"/>`);
  const parsed = await parseXml(xml);
  const root = getRoot(parsed);
  const task = toArray(root?.task)[0];
  const reportId = task?.last_report?.report?.id;
  return reportId || null;
}

function normalizeStatus(status) {
  const value = String(status || "").toLowerCase();
  if (value.includes("done") || value.includes("finished") || value.includes("completed")) {
    return "completed";
  }
  if (value.includes("running") || value.includes("requested") || value.includes("queued")) {
    return "running";
  }
  return value || "unknown";
}

function threatToSeverity(threat) {
  const value = String(threat || "").toLowerCase();
  if (value === "critical") return 4;
  if (value === "high") return 3;
  if (value === "medium") return 2;
  if (value === "low") return 1;
  return 0;
}

function extractSolutionFromTags(tags) {
  const text = String(tags || "");
  const match = text.match(/solution=([^|]+)/i);
  return match ? match[1].trim() : "";
}

function extractCveFromTags(tags) {
  const text = String(tags || "");
  const match = text.match(/cve=([^|]+)/i);
  return match ? match[1].trim() : "";
}

async function getNessusHealth() {
  try {
    const xml = await runGmpCommand("<get_version/>");
    const parsed = await parseXml(xml);
    const root = getRoot(parsed);
    const version = root?.version || "unknown";

    return {
      available: true,
      checks: {
        scanner_status: { ok: true, status: "ready" },
        gmp_api: { ok: true, version }
      },
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    return {
      available: false,
      checks: {
        scanner_status: { ok: false, status: "unavailable" },
        gmp_api: { ok: false, error: err.message }
      },
      timestamp: new Date().toISOString()
    };
  }
}

async function waitForReady(timeoutMs = 10 * 60 * 1000) {
  const start = Date.now();

  while (true) {
    const health = await getNessusHealth();
    if (health.available) {
      return;
    }

    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for OpenVAS API to become ready");
    }

    await sleep(5000);
  }
}

async function createScan(target) {
  const configId = await getScanConfigIdByName(OPENVAS_SCAN_CONFIG);
  const portListId = await getPortListId();
  const scanSuffix = new Date().toISOString().replace(/[:.]/g, "-");
  const targetName = `CyberTech Target - ${target} - ${scanSuffix}`;
  const taskName = `CyberTech Scan - ${target} - ${scanSuffix}`;

  const createTargetXml =
    `<create_target>` +
    `<name>${escapeXml(targetName)}</name>` +
    `<hosts>${escapeXml(target)}</hosts>` +
    `<port_list id="${escapeXml(portListId)}"/>` +
    `</create_target>`;

  const createTargetRaw = await runGmpCommand(createTargetXml);
  const createTargetParsed = await parseXml(createTargetRaw);
  const targetResponse = getRoot(createTargetParsed);
  const targetId = targetResponse?.id;

  if (!targetId) {
    throw new Error("Failed to create OpenVAS target");
  }

  const createTaskXml =
    `<create_task>` +
    `<name>${escapeXml(taskName)}</name>` +
    `<config id="${escapeXml(configId)}"/>` +
    `<target id="${escapeXml(targetId)}"/>` +
    `</create_task>`;

  const createTaskRaw = await runGmpCommand(createTaskXml);
  const createTaskParsed = await parseXml(createTaskRaw);
  const taskResponse = getRoot(createTaskParsed);
  const taskId = taskResponse?.id;

  if (!taskId) {
    throw new Error("Failed to create OpenVAS task");
  }

  return taskId;
}

async function launchScan(taskId) {
  const xml = `<start_task task_id="${escapeXml(taskId)}"/>`;
  await runGmpCommand(xml);
}

async function getScanStatus(taskId) {
  let lastError = null;

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      const xml = await runGmpCommand(`<get_tasks task_id="${escapeXml(taskId)}" details="0"/>`);
      const parsed = await parseXml(xml);
      const root = getRoot(parsed);
      const task = toArray(root?.task)[0];
      return normalizeStatus(task?.status);
    } catch (err) {
      lastError = err;
      if (attempt < 5) {
        await sleep(3000);
        continue;
      }
    }
  }

  throw new Error(`OpenVAS get_tasks failed after retries: ${lastError?.message || lastError}`);
}

async function waitForCompletion(taskId) {
  while (true) {
    const status = await getScanStatus(taskId);
    if (status === "completed") {
      return;
    }
    await sleep(15000);
  }
}

async function getVulnerabilities(taskId) {
  const reportId = await getLatestReportId(taskId);
  if (!reportId) {
    return { tool: "openvas", vulnerabilities: [] };
  }

  const xml = await runGmpCommand(
    `<get_reports report_id="${escapeXml(reportId)}" details="1" ignore_pagination="1"/>`
  );
  const parsed = await parseXml(xml);
  const root = getRoot(parsed);

  const report = toArray(root?.report)[0] || root?.report;
  const results = toArray(report?.results?.result);

  const vulnerabilities = results.map(item => {
    const cvssRaw = item?.severity || item?.nvt?.cvss_base || "0";
    const cvss = Number.parseFloat(cvssRaw);

    return {
      tool: "openvas",
      name: item?.name || item?.nvt?.name || "Unknown vulnerability",
      severity: threatToSeverity(item?.threat),
      cvss: Number.isFinite(cvss) ? cvss : 0,
      plugin: item?.nvt?.oid || null,
      oid: item?.nvt?.oid || null,
      cve: extractCveFromTags(item?.nvt?.tags),
      description: item?.description || "",
      solution: extractSolutionFromTags(item?.nvt?.tags),
      port: item?.port || null
    };
  });

  return {
    tool: "openvas",
    vulnerabilities
  };
}

module.exports = {
  getNessusHealth,
  waitForReady,
  createScan,
  launchScan,
  waitForCompletion,
  getScanStatus,
  getVulnerabilities
};
