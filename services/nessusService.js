const axios = require("axios");
const https = require("https");
const util = require("util");

const NESSUS_URL = "https://localhost:8834";
const ACCESS_KEY = "d67b8be0626cb1ecfc62d5647394c7af483987d66a360f26bb0ce8fce56c24eb";
const SECRET_KEY = "30e0fc1a0631cd91d623a396e6d67dfb572347e941c823a70131b504deb7cc6c";

const httpsAgent = new https.Agent({
  rejectUnauthorized: false
});

const api = axios.create({
  baseURL: NESSUS_URL,
  httpsAgent,
  headers: {
    "X-ApiKeys": `accessKey=${ACCESS_KEY}; secretKey=${SECRET_KEY}`,
    "Content-Type": "application/json"
  }
});

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isApiUnavailableError(err) {
  return (
    err?.response?.status === 412 &&
    String(err?.response?.data?.error || "").toLowerCase().includes("api is not available")
  );
}

function summarizeError(err, fallback) {
  return {
    ok: false,
    code: err?.response?.status || null,
    error: err?.response?.data || err?.message || fallback
  };
}

async function fetchNessusStateSnapshot() {
  const checks = await Promise.allSettled([
    api.get("/server/status", { timeout: 5000 }),
    api.get("/scanners", { timeout: 5000 }),
    api.get("/folders", { timeout: 5000 })
  ]);

  const [serverStatusCheck, scannersCheck, foldersCheck] = checks;

  return {
    server_status:
      serverStatusCheck.status === "fulfilled"
        ? {
            ok: true,
            data: serverStatusCheck.value.data
          }
        : summarizeError(serverStatusCheck.reason, "server status check failed"),
    scanners:
      scannersCheck.status === "fulfilled"
        ? {
            ok: true,
            data: scannersCheck.value.data
          }
        : summarizeError(scannersCheck.reason, "scanners check failed"),
    folders:
      foldersCheck.status === "fulfilled"
        ? {
            ok: true,
            data: foldersCheck.value.data
          }
        : summarizeError(foldersCheck.reason, "folders check failed")
  };
}

async function checkScanApiCapability() {
  const res = await api.get("/scanners");
  const scanners = Array.isArray(res.data?.scanners) ? res.data.scanners : [];
  const scanner = scanners[0];
  const enabled = Boolean(scanner?.license?.features?.scan_api);

  return {
    enabled,
    scannerName: scanner?.name || "unknown",
    licenseType: scanner?.license?.type || "unknown"
  };
}

async function getNessusHealth() {
  const checks = await Promise.allSettled([
    api.get("/server/status", { timeout: 5000 }),
    api.get("/scans", { timeout: 5000 }),
    api.get("/editor/scan/templates", { timeout: 5000 })
  ]);

  const [statusCheck, scansCheck, templatesCheck] = checks;

  const statusData = statusCheck.status === "fulfilled"
    ? {
        ok: true,
        status: statusCheck.value.data?.nessus_service_status || statusCheck.value.data?.status || "unknown"
      }
    : {
        ok: false,
        code: statusCheck.reason?.response?.status || null,
        error: statusCheck.reason?.response?.data || statusCheck.reason?.message || "status check failed"
      };

  const scansData = scansCheck.status === "fulfilled"
    ? { ok: true }
    : {
        ok: false,
        code: scansCheck.reason?.response?.status || null,
        error: scansCheck.reason?.response?.data || scansCheck.reason?.message || "scan api check failed"
      };

  const templatesData = templatesCheck.status === "fulfilled"
    ? {
        ok: true,
        count: Array.isArray(templatesCheck.value.data?.templates)
          ? templatesCheck.value.data.templates.length
          : 0
      }
    : {
        ok: false,
        code: templatesCheck.reason?.response?.status || null,
        error: templatesCheck.reason?.response?.data || templatesCheck.reason?.message || "templates check failed"
      };

  const capability = await checkScanApiCapability().catch(() => ({
    enabled: false,
    scannerName: "unknown",
    licenseType: "unknown"
  }));

  return {
    available: statusData.ok && scansData.ok && templatesData.ok && capability.enabled,
    checks: {
      server_status: statusData,
      scans_api: scansData,
      templates_api: templatesData,
      scan_api_capability: {
        ok: capability.enabled,
        scanner: capability.scannerName,
        license: capability.licenseType
      }
    },
    timestamp: new Date().toISOString()
  };
}

async function waitForReady(timeoutMs = 10 * 60 * 1000) {
  console.log("Waiting for Nessus API...");

  const start = Date.now();

  while (true) {
    try {
      const statusRes = await api.get("/server/status");
      const rawStatus =
        statusRes.data?.nessus_service_status ||
        statusRes.data?.status ||
        "unknown";
      const status = String(rawStatus).toLowerCase();

      if (["ready", "running"].includes(status)) {
        // Guard against false-ready states where status is up but scan API still unavailable.
        await api.get("/scans");
        console.log("Nessus API ready");
        return;
      }

      console.log(`Nessus status: ${rawStatus}`);
    } catch (err) {
      if (isApiUnavailableError(err)) {
        console.log("Nessus reports API unavailable, retrying...");
      } else {
        const msg = err?.response?.data || err.message;
        console.log("Nessus readiness check failed:", msg);
      }
    }

    if (Date.now() - start > timeoutMs) {
      throw new Error("Timed out waiting for Nessus API to become ready");
    }

    await sleep(5000);
  }
}

async function getBasicPolicyUUID() {
  const res = await api.get("/editor/scan/templates");

  const basic = res.data.templates.find(
    t => t.title === "Basic Network Scan"
  );

  if (!basic) {
    throw new Error("Basic Network Scan template not found");
  }

  console.log("Using Policy UUID:", basic.uuid);

  return basic.uuid;
}

async function getDefaultScannerId() {
  const res = await api.get("/scanners");
  const scanners = Array.isArray(res.data?.scanners) ? res.data.scanners : [];

  if (scanners.length === 0) {
    throw new Error("No scanners available in Nessus");
  }

  const preferred = scanners.find(s =>
    ["on", "online", "ready", "connected"].includes(String(s?.status || "").toLowerCase())
  );

  return Number(preferred?.id || scanners[0]?.id);
}

async function getDefaultFolderId() {
  const res = await api.get("/folders");
  const folders = Array.isArray(res.data?.folders) ? res.data.folders : [];

  if (folders.length === 0) {
    return undefined;
  }

  const myScans = folders.find(f =>
    String(f?.name || "").toLowerCase() === "my scans"
  );

  return Number(myScans?.id || folders[0]?.id);
}

async function createScan(target, maxAttempts = 12) {
  console.log("Creating Nessus scan for:", target);

  const capability = await checkScanApiCapability();
  if (!capability.enabled) {
    throw new Error(
      `Nessus license does not allow scan creation via API (features.scan_api=false). Scanner: ${capability.scannerName}, license: ${capability.licenseType}.`
    );
  }

  const uuid = await getBasicPolicyUUID();
  const scannerId = await getDefaultScannerId();
  const folderId = await getDefaultFolderId();

  const requestBody = {
    uuid,
    settings: {
      name: `CyberTech Scan - ${target}`,
      description: "Automated scan from CyberTech",
      text_targets: target,
      launch_now: false,
      scanner_id: scannerId
    }
  };
  if (folderId !== undefined && !Number.isNaN(folderId)) {
    requestBody.settings.folder_id = folderId;
  }

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await api.post("/scans", requestBody);

      const scanId = res.data.scan.id;
      console.log("Scan created. ID:", scanId);
      return scanId;
    } catch (err) {
      const errorDetails = err?.response?.data || err.message || err;
      console.log(`createScan failed on attempt ${attempt}/${maxAttempts}:`, errorDetails);
      console.log("createScan request body:", requestBody);
      if (isApiUnavailableError(err)) {
        const snapshot = await fetchNessusStateSnapshot();
        console.log(
          "Nessus state snapshot during createScan 412:\n",
          util.inspect(snapshot, { depth: null, colors: false })
        );
      }

      if (!isApiUnavailableError(err) || attempt === maxAttempts) {
        throw err;
      }

      console.log(`Scan creation attempt ${attempt}/${maxAttempts} hit 412 API unavailable, retrying...`);
      await sleep(5000);
    }
  }

  throw new Error(
    "Unable to create Nessus scan after retries. Nessus returned 'API is not available'. Open the Nessus web UI and complete initialization/update/licensing."
  );
}

async function launchScan(scanId) {
  console.log("Launching scan:", scanId);
  await api.post(`/scans/${scanId}/launch`);
}

async function getScanStatus(scanId) {
  const res = await api.get(`/scans/${scanId}`);
  return res.data.info.status;
}

async function waitForCompletion(scanId) {
  console.log("Waiting for scan completion...");

  while (true) {
    const status = await getScanStatus(scanId);
    console.log("Scan status:", status);

    if (status === "completed") {
      console.log("Scan completed");
      break;
    }

    await sleep(15000);
  }
}

async function getVulnerabilities(scanId) {
  console.log("Fetching vulnerabilities...");

  const res = await api.get(`/scans/${scanId}`);
  const vulns = res.data.vulnerabilities || [];

  const formatted = [];

  for (const v of vulns) {
    try {
      const detail = await api.get(
        `/scans/${scanId}/plugins/${v.plugin_id}`
      );

      formatted.push({
        tool: "nessus",
        name: v.plugin_name,
        severity: v.severity,
        cvss: detail.data.attributes?.cvss_base_score || 0,
        description: detail.data.attributes?.description || "",
        solution: detail.data.attributes?.solution || "",
        port: v.port || null
      });
    } catch (err) {
      console.log("Plugin fetch error:", v.plugin_id);
    }
  }

  console.log(`Total Vulnerabilities: ${formatted.length}`);

  return {
    tool: "nessus",
    vulnerabilities: formatted
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
