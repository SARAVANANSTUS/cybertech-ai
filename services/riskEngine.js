function calculateRisk(v) {

    const cvssWeight = 0.35;
    const exploitWeight = 0.25;
    const exposureWeight = 0.15;
    const assetWeight = 0.15;
    const confidenceWeight = 0.10;

    const cvss = v.cvss || 0;
    const exploit = v.validated ? 10 : 4;
    const exposure = [80, 443].includes(v.port) ? 9 : 5;
    const assetValue = 5;
    const confidence = v.validated ? 9 : 6;

    let score =
        cvss * cvssWeight +
        exploit * exploitWeight +
        exposure * exposureWeight +
        assetValue * assetWeight +
        confidence * confidenceWeight;

    let normalized = 5 - (score / 10) * 4;

    return Number(Math.max(1, Math.min(5, normalized)).toFixed(2));
}

module.exports = { calculateRisk };