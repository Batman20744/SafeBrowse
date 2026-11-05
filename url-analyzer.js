
function analyzeURL(inputURL) {
    const findings = [];
    const indicators = [];
    let riskScore = 0;

    function addFinding(points, code, message) {
        riskScore += points;
        indicators.push(code);
        findings.push(message);
    }

    // Validate input
    if (typeof inputURL !== "string" || !inputURL.trim()) {
        return {
            valid: false,
            hostname: "",
            riskScore: 100,
            severity: "INVALID",
            findings: ["URL is empty or invalid"],
            indicators: ["INVALID_INPUT"]
        };
    }

    const rawURL = inputURL.trim();
    let url;

    try {
        url = new URL(rawURL);
    } catch {
        return {
            valid: false,
            hostname: "",
            riskScore: 100,
            severity: "INVALID",
            findings: ["Invalid URL format"],
            indicators: ["INVALID_URL"]
        };
    }

    // Validate protocol
    if (!["http:", "https:"].includes(url.protocol)) {
        return {
            valid: false,
            hostname: url.hostname,
            riskScore: 100,
            severity: "INVALID",
            findings: ["Unsupported URL protocol"],
            indicators: ["UNSUPPORTED_PROTOCOL"]
        };
    }

    const hostname = url.hostname.toLowerCase();
    const labels = hostname.split(".");

    const ipv4Pattern =
        /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

    const isIPv4 = ipv4Pattern.test(hostname);
    const isIPv6 = hostname.startsWith("[") && hostname.endsWith("]");

    // 1. HTTP connection — increased from 15 to 30
    if (url.protocol === "http:") {
        addFinding(
            30,
            "HTTP_CONNECTION",
            "Website uses insecure HTTP instead of HTTPS"
        );
    }

    // 2. IP address hostname
    if (isIPv4 || isIPv6) {
        addFinding(
            25,
            "IP_ADDRESS_HOST",
            "Website uses an IP address as its hostname"
        );
    }

    // 3. Long URL
    if (rawURL.length > 100) {
        addFinding(
            10,
            "LONG_URL",
            "Unusually long URL"
        );
    }

    // 4. Excessive subdomains
    if (!isIPv4 && !isIPv6 && labels.length > 4) {
        addFinding(
            15,
            "EXCESSIVE_SUBDOMAINS",
            "Hostname contains an unusually high number of labels"
        );
    }

    // 5. Embedded credentials
    if (url.username || url.password) {
        addFinding(
            25,
            "URL_CREDENTIALS",
            "URL contains embedded username or password information"
        );
    }

    // 6. Suspicious keywords
    const suspiciousKeywords = [
        "login", "verify", "account", "secure",
        "update", "banking", "password", "signin",
        "confirm", "wallet", "authenticate"
    ];

    const matchedKeywords = suspiciousKeywords.filter(keyword =>
        labels.some(label => label.includes(keyword))
    );

    if (matchedKeywords.length > 0) {
        addFinding(
            Math.min(matchedKeywords.length * 10, 30),
            "SUSPICIOUS_KEYWORDS",
            "Potentially deceptive hostname keywords: " +
            matchedKeywords.join(", ")
        );
    }

    // 7. Punycode
    if (labels.some(label => label.startsWith("xn--"))) {
        addFinding(
            20,
            "PUNYCODE_HOSTNAME",
            "Hostname contains an internationalized punycode label"
        );
    }

    // 8. Multiple hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;

    if (hyphenCount >= 3) {
        addFinding(
            10,
            "MULTIPLE_HYPHENS",
            "Hostname contains multiple hyphens"
        );
    }

    // 9. URL encoding
    if (/%[0-9a-f]{2}/i.test(url.pathname + url.search)) {
        addFinding(
            10,
            "URL_ENCODING",
            "URL contains percent-encoded characters"
        );
    }

    // 10. Numeric-only hostname labels
    if (
        !isIPv4 &&
        !isIPv6 &&
        labels.some(label => /^\d+$/.test(label))
    ) {
        addFinding(
            10,
            "NUMERIC_DOMAIN_LABEL",
            "Hostname contains a numeric-only label"
        );
    }

    // 11. Long query string
    if (url.search.length > 150) {
        addFinding(
            5,
            "LONG_QUERY_STRING",
            "URL contains an unusually long query string"
        );
    }

    // Calculate final risk score
    riskScore = Math.min(riskScore, 100);

    // Classify severity
    let severity;

    if (riskScore >= 60) {
        severity = "HIGH";
    } else if (riskScore >= 30) {
        severity = "MEDIUM";
    } else {
        severity = "LOW";
    }

    if (findings.length === 0) {
        findings.push(
            "No configured suspicious URL indicators detected"
        );
    }

    return {
        valid: true,
        originalURL: rawURL,
        normalizedURL: url.href,
        hostname,
        protocol: url.protocol,
        riskScore,
        severity,
        findings,
        indicators
    };
}

// Browser global export
if (typeof globalThis !== "undefined") {
    globalThis.SafeBrowseAnalyzer = { analyzeURL };
}

// Node.js export for testing
if (typeof module !== "undefined" && module.exports) {
    module.exports = { analyzeURL };
}
