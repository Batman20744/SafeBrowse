const test = require("node:test");
const assert = require("node:assert/strict");

const { analyzeURL } = require("../url-analyzer");
const {
    checkBlocklist,
    normalizeHostname
} = require("../blocklist");

// ==========================================
// 1. URL VALIDATION TESTS
// ==========================================

test("Valid HTTPS URL", () => {
    const result = analyzeURL("https://google.com");
    assert.equal(result.valid, true);
    assert.equal(result.severity, "LOW");
});

test("Valid HTTP URL", () => {
    const result = analyzeURL("http://example.com");
    assert.equal(result.valid, true);
    assert.ok(result.riskScore >= 15);
});

test("Empty URL", () => {
    const result = analyzeURL("");
    assert.equal(result.valid, false);
    assert.equal(result.severity, "INVALID");
});

test("Invalid URL format", () => {
    const result = analyzeURL("not-a-url");
    assert.equal(result.valid, false);
});

test("Non-string URL", () => {
    const result = analyzeURL(null);
    assert.equal(result.valid, false);
});

test("Unsupported protocol", () => {
    const result = analyzeURL("ftp://example.com");
    assert.equal(result.valid, false);
});

// ==========================================
// 2. DETECTION TESTS
// ==========================================

test("IPv4 address detection", () => {
    const result = analyzeURL("http://192.168.1.10");
    assert.ok(result.indicators.includes("IP_ADDRESS_HOST"));
});

test("Excessive subdomain detection", () => {
    const result = analyzeURL(
        "https://a.b.c.d.example.com"
    );
    assert.ok(result.indicators.includes("EXCESSIVE_SUBDOMAINS"));
});

test("Suspicious keyword detection", () => {
    const result = analyzeURL(
        "https://secure-login.example.com"
    );
    assert.ok(result.indicators.includes("SUSPICIOUS_KEYWORDS"));
});

test("Embedded credentials detection", () => {
    const result = analyzeURL(
        "https://user:password@example.com"
    );
    assert.ok(result.indicators.includes("URL_CREDENTIALS"));
});

test("Punycode detection", () => {
    const result = analyzeURL(
        "https://xn--e1afmkfd.example"
    );
    assert.ok(result.indicators.includes("PUNYCODE_HOSTNAME"));
});

test("Multiple hyphens detection", () => {
    const result = analyzeURL(
        "https://secure-login-account-update.example"
    );
    assert.ok(result.indicators.includes("MULTIPLE_HYPHENS"));
});

test("Long URL detection", () => {
    const result = analyzeURL(
        "https://example.com/" + "a".repeat(110)
    );
    assert.ok(result.indicators.includes("LONG_URL"));
});

test("URL encoding detection", () => {
    const result = analyzeURL(
        "https://example.com/%2Fadmin"
    );
    assert.ok(result.indicators.includes("URL_ENCODING"));
});

// ==========================================
// 3. RISK SCORING TESTS
// ==========================================

test("Risk score never exceeds 100", () => {
    const result = analyzeURL(
        "http://secure-login-verify-account-update.example.com/" +
        "a".repeat(200)
    );

    assert.ok(result.riskScore <= 100);
});

test("Risk score is never negative", () => {
    const result = analyzeURL("https://google.com");
    assert.ok(result.riskScore >= 0);
});

test("HIGH severity classification", () => {
    const result = analyzeURL(
        "http://secure-login-verify-account.example.com/" +
        "a".repeat(200)
    );

    assert.ok(result.riskScore >= 60);
    assert.equal(result.severity, "HIGH");
});

test("MEDIUM severity classification", () => {
    const result = analyzeURL("http://192.168.1.10");

    assert.equal(result.riskScore, 55);
    assert.equal(result.severity, "MEDIUM");
});

test("LOW severity classification", () => {
    const result = analyzeURL("https://google.com");

    assert.equal(result.riskScore, 0);
    assert.equal(result.severity, "LOW");
});

// ==========================================
// 4. BLOCKLIST TESTS
// ==========================================

test("Exact blocklist match", () => {
    const result = checkBlocklist("phishing.test");

    assert.equal(result.blocked, true);
    assert.equal(result.matchedDomain, "phishing.test");
});

test("Subdomain blocklist match", () => {
    const result = checkBlocklist("login.phishing.test");

    assert.equal(result.blocked, true);
});

test("Unlisted domain", () => {
    const result = checkBlocklist("google.com");

    assert.equal(result.blocked, false);
});

test("Blocklist matching is case insensitive", () => {
    const result = checkBlocklist("LOGIN.PHISHING.TEST");

    assert.equal(result.blocked, true);
});

test("Blocklist prevents suffix confusion", () => {
    const result = checkBlocklist("notphishing.test");

    assert.equal(result.blocked, false);
});

test("Hostname normalization", () => {
    assert.equal(
        normalizeHostname("PHISHING.TEST."),
        "phishing.test"
    );
});

test("Empty hostname is not blocked", () => {
    const result = checkBlocklist("");

    assert.equal(result.blocked, false);
});

// ==========================================
// 5. EDGE CASE TESTS
// ==========================================

test("IPv4 localhost detection", () => {
    const result = analyzeURL("http://127.0.0.1");

    assert.ok(result.indicators.includes("IP_ADDRESS_HOST"));
});

test("HTTPS with suspicious hostname still gets flagged", () => {
    const result = analyzeURL(
        "https://secure-login.example.com"
    );

    assert.ok(result.riskScore > 0);
});

test("Valid URL returns hostname", () => {
    const result = analyzeURL("https://example.com");

    assert.equal(result.hostname, "example.com");
});

test("Invalid URL returns an INVALID severity", () => {
    const result = analyzeURL("invalid");

    assert.equal(result.severity, "INVALID");
});

test("Risk score is capped at 100", () => {
    const result = analyzeURL(
        "http://user:pass@192.168.1.10/" +
        "a".repeat(300)
    );

    assert.ok(result.riskScore <= 100);
});

test("Detection findings are returned as an array", () => {
    const result = analyzeURL("https://google.com");

    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.indicators));
});

console.log("SafeBrowse automated test suite loaded.");
