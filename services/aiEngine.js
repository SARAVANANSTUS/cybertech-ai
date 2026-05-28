const axios = require("axios");

function cleanReportText(text) {
  if (!text) {
    return "";
  }

  return String(text)
    .replace(/\*\*/g, "")
    .replace(/\*/g, "")
    .replace(/^\s*#+\s*/gm, "")
    .trim();
}

function pickTopFindings(vulnerabilities, maxCount = 25) {
  if (!Array.isArray(vulnerabilities)) {
    return [];
  }

  return [...vulnerabilities]
    .sort((a, b) => (Number(b?.cvss || 0) - Number(a?.cvss || 0)))
    .slice(0, maxCount)
    .map((v) => ({
      name: v?.name || "Unknown",
      severity: v?.severity,
      category: v?.category,
      cvss: v?.cvss,
      port: v?.port,
      description: v?.description,
      solution: v?.solution
    }));
}

async function generateAIReport(vulnerabilities) {
  const model = process.env.OLLAMA_MODEL || "phi3:mini";
  const baseUrl = process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434";
  const timeoutMs = Number(process.env.OLLAMA_TIMEOUT_MS || 180000);
  const topFindings = pickTopFindings(vulnerabilities, Number(process.env.AI_MAX_FINDINGS || 25));

  try {
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

Output rules:
- Plain text only
- Do not use markdown
- Do not use *, **, #, -, or _ for headings
- Keep the report concise and actionable

Vulnerability Data (top prioritized findings):
${JSON.stringify(topFindings, null, 2)}
`;

    const response = await axios.post(
      `${baseUrl}/api/generate`,
      {
        model,
        prompt,
        stream: false
      },
      {
        timeout: timeoutMs
      }
    );

    return cleanReportText(response.data.response) || "AI report generation failed.";
  } catch (err) {
    console.error("AI Engine Error:", err.message);

    return `
CyberTech AI Report

AI engine failed to generate full report.

Possible causes:
- Ollama not running
- Model not installed
- Timeout occurred

Please verify system configuration.
`;
  }
}

module.exports = { generateAIReport };
