const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");

const SEVERITY_ORDER = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const SEVERITY_STYLES = {
  critical: { label: "CRITICAL", color: "#8f2140" },
  high: { label: "HIGH", color: "#df4c54" },
  medium: { label: "MEDIUM", color: "#ec8c3f" },
  low: { label: "LOW", color: "#ebc151" },
  info: { label: "INFO", color: "#66a2d3" }
};

function sanitizeReportText(text) {
  const value = String(text || "");
  return value
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/\*(.*?)\*/g, "$1")
    .replace(/[ \t]+\n/g, "\n")
    .trim();
}

function detectSeverityKey(vulnerability) {
  const raw = vulnerability?.severity;

  if (typeof raw === "string") {
    const value = raw.trim().toLowerCase();
    if (value.includes("critical")) return "critical";
    if (value.includes("high")) return "high";
    if (value.includes("medium")) return "medium";
    if (value.includes("low")) return "low";
    if (value.includes("info")) return "info";
  }

  const num = Number(raw);
  if (Number.isFinite(num)) {
    if (num >= 4) return "critical";
    if (num === 3) return "high";
    if (num === 2) return "medium";
    if (num === 1) return "low";
  }

  return "info";
}

function formatScore(value, decimals = 1) {
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(decimals) : "N/A";
}

function formatEpss(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(4) : "N/A";
}

function getPluginId(vulnerability, fallbackIndex) {
  const directCandidates = [
    vulnerability?.plugin,
    vulnerability?.plugin_id,
    vulnerability?.pluginId,
    vulnerability?.oid,
    vulnerability?.nvtOid
  ];

  for (const candidate of directCandidates) {
    if (!candidate) continue;
    const text = String(candidate).trim();
    if (text) return text;
  }

  const id = vulnerability?.id;
  if (id !== undefined && id !== null) {
    const idText = String(id).trim();
    if (idText) return idText;
  }

  return `N/A-${fallbackIndex}`;
}

function sortedFindings(vulnerabilities) {
  const list = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  return [...list].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[detectSeverityKey(b)] - SEVERITY_ORDER[detectSeverityKey(a)];
    if (sevDiff !== 0) return sevDiff;

    const cvssDiff = Number(b?.cvss ?? 0) - Number(a?.cvss ?? 0);
    if (cvssDiff !== 0) return cvssDiff;

    return String(a?.name || "").localeCompare(String(b?.name || ""));
  });
}

function withPageGuard(doc, minSpace) {
  const bottomLimit = doc.page.height - doc.page.margins.bottom;
  if (doc.y + minSpace > bottomLimit) {
    doc.addPage();
  }
}

function drawLegacyHeader(doc, scanId) {
  doc
    .font("Helvetica-Bold")
    .fontSize(22)
    .fillColor("#0b3d91")
    .text("CYBER TECH AI", { align: "center" });

  doc.moveDown(0.35);
  doc
    .font("Helvetica")
    .fontSize(11)
    .fillColor("#444444")
    .text(`id: ${scanId}`, { align: "center" });

  doc.moveDown(0.6);
  doc
    .font("Helvetica-Bold")
    .fontSize(14)
    .fillColor("#222222")
    .text("heading", { align: "left" });

  doc.moveDown(0.8);
}

function drawLegacyEnding(doc) {
  withPageGuard(doc, 80);
  doc.moveDown(0.8);
  doc
    .font("Helvetica-Bold")
    .fontSize(12)
    .fillColor("#222222")
    .text("ending", { align: "left" });
}

function drawSeverityTiles(doc, counts) {
  const keys = ["critical", "high", "medium", "low", "info"];
  const sectionTop = doc.y;
  const totalWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const tileWidth = totalWidth / keys.length;
  const tileHeight = 56;

  keys.forEach((key, index) => {
    const style = SEVERITY_STYLES[key];
    const x = doc.page.margins.left + index * tileWidth;
    const y = sectionTop;
    const count = counts[key] || 0;

    doc.rect(x, y, tileWidth, tileHeight).fill(style.color);

    doc
      .fillColor("white")
      .font("Helvetica")
      .fontSize(24)
      .text(String(count), x, y + 16, {
        width: tileWidth,
        align: "center"
      });

    doc
      .fillColor("#777777")
      .fontSize(10)
      .text(style.label, x, y + tileHeight + 6, {
        width: tileWidth,
        align: "center"
      });
  });

  doc.y = sectionTop + tileHeight + 24;
}

function drawTableHeader(doc, columns) {
  const tableX = doc.page.margins.left;
  const tableWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const headerY = doc.y;

  doc.rect(tableX, headerY, tableWidth, 26).fill("#efefef");

  doc.font("Helvetica-Bold").fontSize(10).fillColor("#333333");
  columns.forEach(col => {
    doc.text(col.label, col.x, headerY + 8, {
      width: col.width,
      align: "left"
    });
  });

  doc.y = headerY + 32;
}

function drawSummaryTable(doc, findings) {
  const columns = [
    { label: "SEVERITY", x: 32, width: 62 },
    { label: "CVSS V3.0", x: 103, width: 56 },
    { label: "VPR SCORE", x: 169, width: 56 },
    { label: "EPSS SCORE", x: 235, width: 64 },
    { label: "PLUGIN", x: 309, width: 70 },
    { label: "NAME", x: 385, width: 180 }
  ];

  drawTableHeader(doc, columns);

  findings.forEach((finding, index) => {
    withPageGuard(doc, 30);

    const rowY = doc.y;
    const severityKey = detectSeverityKey(finding);
    const sev = SEVERITY_STYLES[severityKey];

    doc.rect(columns[0].x, rowY + 2, columns[0].width, 20).fill(sev.color);

    doc
      .font("Helvetica")
      .fontSize(9)
      .fillColor("white")
      .text(sev.label, columns[0].x, rowY + 8, {
        width: columns[0].width,
        align: "center"
      });

    doc.fillColor("#333333").fontSize(9);
    doc.text(formatScore(finding?.cvss, 1), columns[1].x, rowY + 8, { width: columns[1].width });
    doc.text(formatScore(finding?.vprScore ?? finding?.vpr, 1), columns[2].x, rowY + 8, { width: columns[2].width });
    doc.text(formatEpss(finding?.epssScore ?? finding?.epss), columns[3].x, rowY + 8, { width: columns[3].width });
    doc.text(getPluginId(finding, index + 1), columns[4].x, rowY + 8, { width: columns[4].width });
    doc.text(String(finding?.name || "Unknown vulnerability"), columns[5].x, rowY + 8, {
      width: columns[5].width,
      ellipsis: true
    });

    doc
      .strokeColor("#e8e8e8")
      .moveTo(doc.page.margins.left, rowY + 26)
      .lineTo(doc.page.width - doc.page.margins.right, rowY + 26)
      .stroke();

    doc.y = rowY + 30;
  });
}

function drawDetailSection(doc, finding, index) {
  withPageGuard(doc, 250);

  const tableX = doc.page.margins.left;
  const tableWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const severityKey = detectSeverityKey(finding);
  const sev = SEVERITY_STYLES[severityKey];
  const barY = doc.y;
  const title = `${getPluginId(finding, index)} - ${String(finding?.name || "Unknown vulnerability")}`;

  doc.rect(tableX, barY, tableWidth, 26).fill(sev.color);
  doc
    .fillColor("white")
    .font("Helvetica-Bold")
    .fontSize(14)
    .text(title, tableX + 10, barY + 6, {
      width: tableWidth - 20,
      ellipsis: true
    });

  doc.y = barY + 42;
  doc.fillColor("#111111").font("Helvetica-Bold").fontSize(11).text("Risk Factor");
  doc.moveDown(0.4);
  doc.fillColor("#111111").font("Helvetica").fontSize(10).text(sev.label.charAt(0) + sev.label.slice(1).toLowerCase(), {
    indent: 20
  });

  doc.moveDown(1.1);
  doc.fillColor("#111111").font("Helvetica-Bold").fontSize(11).text("CVSS Score");
  doc.moveDown(0.5);
  doc.fillColor("#111111").font("Helvetica").fontSize(10).text(
    `Base Score: ${formatScore(finding?.cvss, 1)}    VPR: ${formatScore(finding?.vprScore ?? finding?.vpr, 1)}    EPSS: ${formatEpss(finding?.epssScore ?? finding?.epss)}`,
    { indent: 20 }
  );

  const description = sanitizeReportText(
    finding?.description ||
    "No detailed description is available from the scanner for this finding."
  );
  doc.moveDown(0.6);
  doc.text(description, {
    indent: 20
  });

  const solution = sanitizeReportText(
    finding?.solution ||
    "Follow vendor guidance, patch affected components, and validate with a re-scan."
  );
  doc.moveDown(1.1);
  doc.fillColor("#111111").font("Helvetica-Bold").fontSize(11).text("Recommended Fix");
  doc.moveDown(0.5);
  doc.fillColor("#111111").font("Helvetica").fontSize(10).text(solution, {
    indent: 20
  });

  doc.moveDown(1.2);
  doc
    .strokeColor("#b5b5b5")
    .lineWidth(1)
    .moveTo(doc.page.margins.left, doc.y)
    .lineTo(doc.page.width - doc.page.margins.right, doc.y)
    .stroke();

  doc.moveDown(1.2);
}

async function createPDF(report, scanId, vulnerabilities = []) {
  const reportsDir = path.join(__dirname, "../reports");

  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir);
  }

  const filePath = path.join(reportsDir, `report_${scanId}.pdf`);

  const doc = new PDFDocument({
    margin: 24
  });

  doc.pipe(fs.createWriteStream(filePath));

  const findings = sortedFindings(vulnerabilities);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  findings.forEach(finding => {
    counts[detectSeverityKey(finding)] += 1;
  });

  drawLegacyHeader(doc, scanId);
  drawSeverityTiles(doc, counts);

  doc.font("Helvetica").fillColor("#333333").fontSize(11);
  doc.text("Vulnerabilities", doc.page.margins.left, doc.y + 8);
  doc.text(`Total: ${findings.length}`, doc.page.width - doc.page.margins.right - 130, doc.y, {
    width: 130,
    align: "right"
  });
  doc.moveDown(1.2);

  drawSummaryTable(doc, findings);

  if (findings.length > 0) {
    doc.addPage();
    findings.forEach((finding, index) => {
      drawDetailSection(doc, finding, index + 1);
    });
  }

  const cleanedReport = sanitizeReportText(report);
  if (cleanedReport) {
    doc.addPage();
    doc.font("Helvetica-Bold").fontSize(16).fillColor("#111111").text("AI Narrative Summary");
    doc.moveDown(0.8);
    doc.font("Helvetica").fontSize(10).fillColor("#111111").text(cleanedReport, {
      align: "left"
    });
  }

  drawLegacyEnding(doc);

  doc.end();

  return filePath;
}

module.exports = { createPDF };
