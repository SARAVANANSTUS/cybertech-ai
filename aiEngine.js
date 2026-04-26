const axios = require("axios");

const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "phi3:mini";
const OLLAMA_TIMEOUT_MS = Number(process.env.OLLAMA_TIMEOUT_MS || 300000);

function toCompactVulns(vulnerabilities) {
  const list = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  // Keep only the most important findings to reduce token/time pressure.
  const prioritized = [...list].sort((a, b) => {
    const sevA = Number(a?.severity ?? 0);
    const sevB = Number(b?.severity ?? 0);
    if (sevB !== sevA) return sevB - sevA;

    const cvssA = Number(a?.cvss ?? 0);
    const cvssB = Number(b?.cvss ?? 0);
    return cvssB - cvssA;
  });

  return prioritized.slice(0, 40).map(v => ({
    name: v?.name || "Unknown",
    severity: v?.severity,
    cvss: v?.cvss,
    port: v?.port,
    description: v?.description,
    solution: v?.solution
  }));
}

function buildFallbackReport(vulnerabilities, reason) {
  const list = Array.isArray(vulnerabilities) ? vulnerabilities : [];
  const severityCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const v of list) {
    const sev = Number(v?.severity ?? -1);
    if (sev >= 4) severityCount.critical += 1;
    else if (sev === 3) severityCount.high += 1;
    else if (sev === 2) severityCount.medium += 1;
    else if (sev === 1) severityCount.low += 1;
    else severityCount.info += 1;
  }

  const topFindings = [...list]
    .sort((a, b) => {
      const sevDiff = Number(b?.severity ?? 0) - Number(a?.severity ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return Number(b?.cvss ?? 0) - Number(a?.cvss ?? 0);
    })
    .slice(0, 5)
    .map((v, idx) => `${idx + 1}. ${v?.name || "Unknown"} (severity ${v?.severity ?? "n/a"}, cvss ${v?.cvss ?? "n/a"})`)
    .join("\n");

  return `
CyberTech AI Security Report (Fallback)

1. Executive Summary
Scan completed. AI narrative timed out, so this fallback summary was generated.

2. Risk Overview
Total findings: ${list.length}
Critical: ${severityCount.critical}
High: ${severityCount.high}
Medium: ${severityCount.medium}
Low: ${severityCount.low}
Info: ${severityCount.info}

3. Top Critical Vulnerabilities
${topFindings || "No findings available."}

4. Exploitation Possibilities
Prioritize externally reachable high/critical findings for immediate validation.

5. Recommended Remediation
Patch critical/high findings first, harden exposed services, and re-scan after fixes.

6. Security Best Practices
Use least privilege, continuous patching, and periodic authenticated scans.

7. Conclusion
Generated fallback because AI engine was unavailable or timed out.
Reason: ${reason}
`;
}

async function generateAIReport(vulnerabilities) {
  try {
    const compactVulns = toCompactVulns(vulnerabilities);

    const prompt = `
You are an expert cybersecurity penetration tester.

Generate a professional security assessment report based on the vulnerabilities provided.

STRICT FORMAT:

1. Executive Summary
2. Risk Overview
3. Top Critical Vulnerabilities
4. Exploitation Possibilities
5. Recommended Remediation
6. Security Best Practices
7. Conclusion

Vulnerability Data:
${JSON.stringify(compactVulns, null, 2)}
`;

    const response = await axios.post(
      `${OLLAMA_BASE_URL}/api/generate`,
      {
        model: OLLAMA_MODEL,
        prompt,
        stream: false
      },
      {
        timeout: OLLAMA_TIMEOUT_MS
      }
    );

    return response.data.response || "AI report generation failed.";
  } catch (err) {
    const detail = err?.response?.data?.error || err?.response?.data || err.message;
    console.error("AI Engine Error:", detail);
    return buildFallbackReport(vulnerabilities, String(detail));
  }
}

module.exports = { generateAIReport };
