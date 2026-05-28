function categorize(cvss) {

    if (cvss >= 7) return "High";
    if (cvss >= 4) return "Medium";
    return "Low";
}

module.exports = { categorize };