const BLOCKED_DOMAINS = [
    "phishing.test",
    "malware.test",
    "fakebank.test",
    "suspicious.test",
    "credential-theft.test",
    "fake-login.test"
];

function normalizeHostname(hostname) {
    return String(hostname || "")
        .toLowerCase()
        .replace(/\.$/, "");
}

function checkBlocklist(hostname) {
    const host = normalizeHostname(hostname);

    const matchedDomain = BLOCKED_DOMAINS.find(domain =>
        host === domain || host.endsWith("." + domain)
    );

    return {
        blocked: Boolean(matchedDomain),
        matchedDomain: matchedDomain || null
    };
}

if (typeof globalThis !== "undefined") {
    globalThis.SafeBrowseBlocklist = {
        BLOCKED_DOMAINS,
        checkBlocklist,
        normalizeHostname
    };
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        BLOCKED_DOMAINS,
        checkBlocklist,
        normalizeHostname
    };
}
