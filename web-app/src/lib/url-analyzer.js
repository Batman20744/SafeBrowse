
function analyzeURL(inputURL) {
    const findings = [];
    const indicators = [];
    let riskScore = 0;

    // INTELLIGENT_RISK_ENGINE_V17
    function addFinding(points, code, message) {
        // Prevent duplicate indicators from inflating the risk score.
        if (indicators.includes(code)) return;

        const safePoints = Number.isFinite(points)
            ? Math.max(0, points)
            : 0;

        riskScore += safePoints;
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

    const trustedLoginDomains = [
        "google.com",
        "microsoftonline.com",
        "microsoft.com",
        "paypal.com",
        "amazon.com",
        "apple.com",
        "instagram.com",
        "netflix.com",
        "facebook.com",
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com",
        "github.com",
        "github.io",
        "wikipedia.org",
        "cloudflare.com",
        "vercel.com",
        "netlify.com",
        "stackoverflow.com",
        "mozilla.org",
        "developer.mozilla.org",
        "npmjs.com",
        "nodejs.org",
        "python.org",
        "react.dev",
        "vite.dev",
        "ubuntu.com",
        "accounts.google.com"
    ];

    const isTrustedLoginDomain = trustedLoginDomains.some(domain =>
        hostname === domain || hostname.endsWith("." + domain)
    );

    const matchedKeywords = isTrustedLoginDomain
        ? []
        : suspiciousKeywords.filter(keyword =>
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
    // Brand domain and keyword impersonation detection
    const trustedBrandDomains = [
        "paypal.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "facebook.com",
        "instagram.com",
        "netflix.com",
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com"
    ];

    const monitoredBrandNames = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "facebook",
        "instagram",
        "netflix",
        "chase",
        "wellsfargo",
        "bankofamerica",
        "olx",
        "meta",
        "dpd",
        "mydpd",
        "inpost",
        "paketnavigator",
        "vinted",
        "allegro",
        "harborfreight",
        "nfacebook",
        "roblox",
        "commerz",
        "dpdgroup",
        "postnl",
        "usps",
        "fedex",
        "dhl",
        "ups",
        "shopee",
        "applejp",
        "harborfreight"
    ];

    const impersonatedBrand = trustedBrandDomains.find(brandDomain =>
        hostname.startsWith(brandDomain + ".") ||
        hostname.includes("." + brandDomain + ".")
    );

    const isGenuineBrandDomain = trustedBrandDomains.some(brandDomain =>
        hostname === brandDomain ||
        hostname.endsWith("." + brandDomain)
    );

    if (impersonatedBrand && !isGenuineBrandDomain) {
        addFinding(
            45,
            "BRAND_DOMAIN_IMPERSONATION",
            "Possible brand impersonation: trusted domain " +
            impersonatedBrand +
            " appears inside an unrelated hostname"
        );
    }

    // Detect monitored brand names inside unrelated subdomain labels.
    const subdomainLabelsForBrand = labels.slice(0, -2);

    const impersonatedBrandKeyword = monitoredBrandNames.find(brand =>
        subdomainLabelsForBrand.some(label =>
            label === brand ||
            label.startsWith(brand + "-") ||
            (brand === "meta" && /^meta[a-z0-9-]{3,}$/.test(label))
        )
    );

    if (impersonatedBrandKeyword && !isGenuineBrandDomain) {
        addFinding(
            35,
            "BRAND_KEYWORD_IMPERSONATION",
            "Possible impersonation of " +
            impersonatedBrandKeyword +
            " in an unrelated subdomain"
        );
    }

    // Detect a trusted brand name embedded in URL credentials.
    const credentialText = (url.username + " " + url.password).toLowerCase();

    const credentialBrand = monitoredBrandNames.find(brand =>
        credentialText.includes(brand)
    );

    if (credentialBrand) {
        addFinding(
            35,
            "BRAND_CREDENTIAL_IMPERSONATION",
            "URL credentials contain a monitored brand name: " +
            credentialBrand
        );
    }

    // Detect monitored brand names in URL paths on unrelated domains.
    const pathTokens = url.pathname
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter(Boolean);

    const pathBrand = monitoredBrandNames.find(brand =>
        pathTokens.some(token =>
            token === brand ||
            token.startsWith(brand + "-") ||
            (brand.length >= 5 && token.startsWith(brand) && token.length > brand.length)
        )
    );

    if (pathBrand && !isGenuineBrandDomain) {
        addFinding(
            20,
            "BRAND_PATH_IMPERSONATION",
            "Monitored brand name appears in the URL path on an unrelated domain: " +
            pathBrand
        );
    }

    // Detect combinations of suspicious path terms.
    const suspiciousPathTerms = [
        "login", "signin", "verify", "verification",
        "business-center", "account", "payment",
        "billing", "track", "tracking", "viewer",
        "update", "register", "card"
    ];

    const matchedPathTerms = suspiciousPathTerms.filter(term =>
        url.pathname.toLowerCase().includes(term)
    );

    if (!isGenuineBrandDomain && matchedPathTerms.length >= 2) {
        addFinding(
            15,
            "SUSPICIOUS_PATH_COMBINATION",
            "URL path contains multiple suspicious terms: " +
            matchedPathTerms.slice(0, 4).join(", ")
        );
    }

    // Real-world detection: randomized hosted-platform subdomains
    const hostedPlatforms = [
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "web.app",
        "firebaseapp.com",
        "workers.dev",
        "weebly.com",
        "yourwebs.app",
        "github.io",
        "gitbook.io",
        "blogspot.com",
        "4everland.app",
        "craftum.io",
        "temporary.site",
        "backblazeb2.com"
    ];

    const matchedPlatform = hostedPlatforms.find(platform =>
        hostname.endsWith("." + platform)
    );

    if (matchedPlatform) {
        const platformLabels = matchedPlatform.split(".");
        const tenantIndex = labels.length - platformLabels.length - 1;
        const tenantLabel = labels[tenantIndex];

        if (
            tenantLabel &&
            tenantLabel.length >= 24 &&
            (tenantLabel.match(/-/g) || []).length >= 3
        ) {
            addFinding(
                25,
                "RANDOMIZED_HOSTED_SUBDOMAIN",
                "Hosted platform contains an unusually long, randomized-looking subdomain"
            );
        }
    }

    if (matchedPlatform) {
        const platformLabels = matchedPlatform.split(".");
        const tenantIndex = labels.length - platformLabels.length - 1;
        const tenantLabel = labels[tenantIndex] || "";

        const suspiciousTenantPatterns = [
            /^(?:meta|facebook|netflix|apple|paypal|amazon|microsoft)-/i,
            /veryfied/i,
            /popup/i,
            /business-number/i,
            /[a-z]{2,}\d{5,}/i
        ];

        if (suspiciousTenantPatterns.some(pattern => pattern.test(tenantLabel))) {
            addFinding(
                20,
                "SUSPICIOUS_HOSTED_TENANT",
                "Hosted platform tenant contains suspicious brand or phishing-related naming"
            );
        }
    }

    // General randomized subdomain detection
    const subdomainLabels = labels.slice(0, -2);

    const hasRandomizedSubdomain = subdomainLabels.some(label => {
        const normalized = label.replace(/[^a-z0-9]/g, "");
        const uniqueRatio = normalized.length
            ? new Set(normalized).size / normalized.length
            : 0;

        return (
            normalized.length >= 9 &&
            /[a-z]/.test(normalized) &&
            /[0-9]/.test(normalized) &&
            uniqueRatio >= 0.7
        );
    });

    if (
        hasRandomizedSubdomain &&
        !indicators.includes("RANDOMIZED_HOSTED_SUBDOMAIN")
    ) {
        addFinding(
            20,
            "RANDOMIZED_SUBDOMAIN",
            "Hostname contains a long, randomized-looking subdomain"
        );
    }

    // Detect monitored brand names inside the registered domain label.
    const registeredDomainLabel = labels.length >= 2 ? labels[labels.length - 2] : "";

    const suspiciousRootBrand = monitoredBrandNames.find(brand =>
        brand.length >= 4 &&
        registeredDomainLabel !== brand &&
        registeredDomainLabel.includes(brand) &&
        (
            registeredDomainLabel.startsWith(brand) ||
            registeredDomainLabel.endsWith(brand) ||
            registeredDomainLabel.includes(brand + "-")
        )
    );

    if (suspiciousRootBrand && !isGenuineBrandDomain) {
        addFinding(
            30,
            "BRAND_ROOT_DOMAIN_IMPERSONATION",
            "A monitored brand name appears inside an unrelated registered domain"
        );
    }

    // Detect randomized-looking tenants on supported hosting platforms.
    if (matchedPlatform) {
        const platformLabels = matchedPlatform.split(".");
        const tenantIndex = labels.length - platformLabels.length - 1;
        const tenant = labels[tenantIndex] || "";
        const normalizedTenant = tenant.replace(/[^a-z0-9]/g, "");
        const uniqueTenantRatio = normalizedTenant.length
            ? new Set(normalizedTenant).size / normalizedTenant.length
            : 0;

        if (
            normalizedTenant.length >= 6 &&
            /[a-z]/i.test(normalizedTenant) &&
            /[0-9]/.test(normalizedTenant) &&
            uniqueTenantRatio >= 0.65 &&
            !indicators.includes("SUSPICIOUS_HOSTED_TENANT") &&
            !indicators.includes("RANDOMIZED_HOSTED_SUBDOMAIN")
        ) {
            addFinding(
                20,
                "RANDOMIZED_HOSTED_TENANT",
                "Hosted platform tenant has an unusual randomized-looking name"
            );
        }
    }


    // HIGH_RECALL_PATH_ANALYSIS
    // Detect high-signal phishing URL structures.
    const lowerPath = url.pathname.toLowerCase();

    const highSignalPaths = [
        [/\/home\/register(?:\/|$)/i, 25, "Suspicious registration page"],
        [/\/verify_connection(?:\.html)?$/i, 25, "Suspicious connection verification page"],
        [/\/vc\/update(?:\.html)?$/i, 20, "Suspicious verification update page"],
        [/\/track\/[a-z0-9]{8,}/i, 20, "Tracking page contains a long tracking identifier"],
        [/\/users\/\d+\/profile(?:\/|$)/i, 15, "Profile page hosted on an unverified domain"]
    ];

    for (const [pattern, points, message] of highSignalPaths) {
        if (pattern.test(lowerPath)) {
            addFinding(points, "HIGH_SIGNAL_PATH_ANALYSIS", message);
            break;
        }
    }

    // Shared-page hosting can conceal credential collection pages.
    if (
        hostname === "sharemyhtml.com" &&
        /^\/p\/[a-z0-9]{8,}/i.test(url.pathname)
    ) {
        addFinding(
            25,
            "SHARED_HTML_HOSTING_ABUSE",
            "URL uses a shared HTML publishing page associated with hosted content"
        );
    }

    // Long, opaque file paths on file-hosting infrastructure.
    if (
        hostname.endsWith(".backblazeb2.com") &&
        /^\/file\/[^/]+\/.{20,}/i.test(url.pathname)
    ) {
        addFinding(
            15,
            "SUSPICIOUS_FILE_HOSTING_PATH",
            "File-hosting URL contains an unusually long resource path"
        );
    }

    // Randomized path segments.
    const pathSegments = url.pathname.split("/").filter(Boolean);

    const suspiciousRandomPath = pathSegments.some(segment => {
        const value = segment.replace(/[^a-z0-9]/gi, "");
        if (value.length < 11) return false;

        const uniqueRatio = new Set(value.toLowerCase()).size / value.length;
        const hasLetters = /[a-z]/i.test(value);
        const hasDigits = /\d/.test(value);

        return uniqueRatio >= 0.72 && hasLetters && hasDigits;
    });

    if (suspiciousRandomPath) {
        addFinding(
            15,
            "RANDOMIZED_PATH_SEGMENT",
            "URL contains an unusually randomized-looking path segment"
        );
    }

    // Detect randomized or deceptive registered-domain labels.
    const suspiciousDomainLabel = labels.find((label, index) => {
        if (label.length < 9 || ["www", "http", "https"].includes(label)) {
            return false;
        }

        const normalized = label.replace(/[^a-z0-9]/g, "");
        const uniqueRatio = normalized.length
            ? new Set(normalized).size / normalized.length
            : 0;

        const mixedLettersAndNumbers =
            normalized.length >= 8 &&
            /[a-z]/i.test(normalized) &&
            /\d/.test(normalized);

        const vowelCount = (normalized.match(/[aeiou]/gi) || []).length;
        const vowelRatio = normalized.length ? vowelCount / normalized.length : 1;

        const unusualWordShape =
    normalized.length >= 12 &&
    uniqueRatio >= 0.80 &&
    vowelRatio <= 0.25;

        return mixedLettersAndNumbers || unusualWordShape;
    });

    if (suspiciousDomainLabel) {
        addFinding(
            20,
            "RANDOMIZED_DOMAIN_LABEL",
            "Hostname contains a randomized-looking or unusually structured domain label"
        );
    }

    // Detect numeric prefixes attached to otherwise normal-looking domains.
    if (labels.some(label => /^\d{3,}[a-z]{3,}$/i.test(label))) {
        addFinding(
            10,
            "NUMERIC_PREFIX_DOMAIN",
            "Hostname contains a long numeric prefix attached to a word"
        );
    }

    // USPS impersonation spelling variations.
    if (
        /uspostal|uspostaldirect|uspost/i.test(hostname) &&
        !hostname.endsWith(".usps.com")
    ) {
        addFinding(
            30,
            "POSTAL_BRAND_IMPERSONATION",
            "Hostname may be impersonating a postal delivery brand"
        );
    }


    // DOMAIN_STRUCTURE_UPGRADE

    // Detect monitored brand names used as the registered domain itself
    // when the hostname is not an established trusted brand domain.
    const exactRootBrand = monitoredBrandNames.find(brand =>
        registeredDomainLabel === brand
    );

    if (exactRootBrand && !isGenuineBrandDomain) {
        addFinding(
            25,
            "UNVERIFIED_BRAND_ROOT_DOMAIN",
            "A monitored brand name is used as the registered domain on an unverified hostname"
        );
    }

    // Detect suspicious domain suffixes when combined with other risk signals.
    const suspiciousTlds = [
        "xyz", "top", "click", "bond", "work",
        "support", "rest", "fit", "monster", "buzz"
    ];

    const tld = labels[labels.length - 1] || "";
    const hasSuspiciousTld = suspiciousTlds.includes(tld);

    const hasOtherDomainRisk = (
        indicators.includes("RANDOMIZED_DOMAIN_LABEL") ||
        indicators.includes("BRAND_ROOT_DOMAIN_IMPERSONATION") ||
        indicators.includes("BRAND_KEYWORD_IMPERSONATION") ||
        indicators.includes("SUSPICIOUS_KEYWORDS") ||
        indicators.includes("MULTIPLE_HYPHENS")
    );

    if (hasSuspiciousTld && hasOtherDomainRisk) {
        addFinding(
            15,
            "SUSPICIOUS_TLD_COMBINATION",
            "Unusual domain suffix appears together with other suspicious hostname indicators"
        );
    }

    // Detect unusually long consonant-heavy registered domain labels.
    const rootLabel = registeredDomainLabel || "";
    const rootLetters = rootLabel.replace(/[^a-z]/g, "");
    const vowelRatio = rootLetters.length
        ? (rootLetters.match(/[aeiou]/g) || []).length / rootLetters.length
        : 1;

   if (
    rootLetters.length >= 12 &&
    vowelRatio <= 0.20 &&
    !isGenuineBrandDomain
) {
        addFinding(
            15,
            "CONSONANT_HEAVY_DOMAIN",
            "Registered domain contains an unusually consonant-heavy name"
        );
    }

    // Inspect URL fragments for phishing-related terms.
    const fragment = url.hash.toLowerCase();

    const suspiciousFragmentTerms = [
        "login", "signin", "verify", "password",
        "account", "wallet", "secure", "credential"
    ];

    const fragmentMatches = suspiciousFragmentTerms.filter(term =>
        fragment.includes(term)
    );

    if (fragmentMatches.length >= 2 && !isGenuineBrandDomain) {
        addFinding(
            15,
            "SUSPICIOUS_FRAGMENT",
            "URL fragment contains multiple credential or verification-related terms"
        );
    }


    // CREDENTIAL_HARVESTING_UPGRADE

    // Detect combinations of credential-collection parameters.
    const queryKeys = [...url.searchParams.keys()]
        .map(key => key.toLowerCase());

    const credentialKeys = [
        "email", "username", "user", "password",
        "passwd", "pass", "otp", "cvv", "card",
        "cardnumber", "securitycode"
    ];

    const matchedCredentialKeys = credentialKeys.filter(key =>
        queryKeys.includes(key)
    );

    const hasPasswordField = matchedCredentialKeys.some(key =>
        ["password", "passwd", "pass"].includes(key)
    );

    const hasIdentityField = matchedCredentialKeys.some(key =>
        ["email", "username", "user"].includes(key)
    );

    const hasPaymentField = matchedCredentialKeys.some(key =>
        ["cvv", "card", "cardnumber", "securitycode"].includes(key)
    );

    if (
        !isGenuineBrandDomain &&
        (
            (hasPasswordField && hasIdentityField) ||
            (hasPaymentField && matchedCredentialKeys.length >= 2)
        )
    ) {
        addFinding(
            25,
            "CREDENTIAL_HARVESTING_PARAMETERS",
            "URL contains a combination of credential or payment collection parameters"
        );
    }

    // Detect deceptive external redirect parameters.
    const redirectKeys = [
        "redirect", "redirect_url", "return_url",
        "returnto", "continue", "next", "dest", "destination"
    ];

    const suspiciousRedirect = redirectKeys.some(key =>
        url.searchParams.getAll(key).some(value =>
            /^https?:\/\//i.test(value) &&
            !value.toLowerCase().includes(hostname)
        )
    );

    if (suspiciousRedirect && !isGenuineBrandDomain) {
        addFinding(
            15,
            "EXTERNAL_REDIRECT_PARAMETER",
            "URL contains a redirect parameter pointing to another host"
        );
    }


    // TYPOSQUATTING_DETECTION_UPGRADE

    // Detect one-character substitutions, insertions, or deletions
    // in monitored brand names inside the registered domain label.
    function isOneEditAway(a, b) {
        if (Math.abs(a.length - b.length) > 1) return false;

        let i = 0;
        let j = 0;
        let edits = 0;

        while (i < a.length && j < b.length) {
            if (a[i] === b[j]) {
                i++;
                j++;
                continue;
            }

            edits++;
            if (edits > 1) return false;

            if (a.length > b.length) i++;
            else if (b.length > a.length) j++;
            else {
                i++;
                j++;
            }
        }

        if (i < a.length || j < b.length) edits++;
        return edits === 1;
    }

    const normalizedRootLabel = (registeredDomainLabel || "")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

    const lookalikeBrand = monitoredBrandNames.find(brand => {
        if (brand.length < 5 || normalizedRootLabel === brand) return false;
        return isOneEditAway(normalizedRootLabel, brand);
    });

    if (lookalikeBrand && !isGenuineBrandDomain) {
        addFinding(
            35,
            "TYPOSQUATTING_BRAND_IMPERSONATION",
            "Registered domain closely resembles the monitored brand: " + lookalikeBrand
        );
    }


    // UNICODE_HOMOGRAPH_DETECTION

    const unicodeHostname = url.hostname.toLowerCase();

    const confusableCharacters = {
        "а": "a", "е": "e", "о": "o", "р": "p",
        "с": "c", "х": "x", "у": "y", "і": "i",
        "ј": "j", "ԁ": "d", "ӏ": "l", "ѕ": "s"
    };

    const hasNonAsciiHostname = /[^\x00-\x7F]/.test(unicodeHostname);

    const hasConfusableCharacter = [...unicodeHostname].some(
        character => Object.prototype.hasOwnProperty.call(
            confusableCharacters, character
        )
    );

    if (hasNonAsciiHostname && hasConfusableCharacter) {
        addFinding(
            35,
            "UNICODE_HOMOGRAPH_DOMAIN",
            "Hostname contains Unicode characters that may imitate Latin letters"
        );
    }

    // Detect mixed-script hostnames.
    const scripts = new Set();

    for (const character of unicodeHostname) {
        if (/\p{Script=Latin}/u.test(character)) scripts.add("Latin");
        else if (/\p{Script=Cyrillic}/u.test(character)) scripts.add("Cyrillic");
        else if (/\p{Script=Greek}/u.test(character)) scripts.add("Greek");
    }

    if (scripts.size > 1) {
        addFinding(
            25,
            "MIXED_SCRIPT_HOSTNAME",
            "Hostname combines multiple writing systems"
        );
    }


    // URL_OBFUSCATION_DETECTION_V9

    // Inspect query values for nested external URLs.
    const nestedURLs = [];

    for (const value of url.searchParams.values()) {
        try {
            const decoded = decodeURIComponent(value);
            const matches = decoded.match(/https?:\/\/[^\s"'<>]+/gi) || [];
            nestedURLs.push(...matches);
        } catch {
            const matches = value.match(/https?:\/\/[^\s"'<>]+/gi) || [];
            nestedURLs.push(...matches);
        }
    }

    const externalNestedURL = nestedURLs.some(value => {
        try {
            const nestedHost = new URL(value).hostname.toLowerCase();
            return nestedHost !== hostname &&
                !nestedHost.endsWith("." + hostname);
        } catch {
            return false;
        }
    });

    if (externalNestedURL && !isGenuineBrandDomain) {
        addFinding(
            20,
            "NESTED_EXTERNAL_URL",
            "Query parameters contain a URL pointing to another hostname"
        );
    }

    // Detect repeatedly encoded URL schemes.
    const encodedURLScheme =
        /(?:%25){1,}(?:3a|3A)(?:%25){1,}(?:2f|2F)/i.test(
            url.search + url.pathname
        ) ||
        /https?%3a%2f%2f/i.test(url.search + url.pathname);

    if (encodedURLScheme && !isGenuineBrandDomain) {
        addFinding(
            15,
            "ENCODED_URL_SCHEME",
            "URL contains an encoded or obfuscated URL scheme"
        );
    }

    // Detect unusually large query strings containing many parameters.
    const queryParameterCount = [...url.searchParams.keys()].length;

    if (
        queryParameterCount >= 8 &&
        url.search.length > 180 &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            10,
            "EXCESSIVE_QUERY_PARAMETERS",
            "URL contains an unusually large number of query parameters"
        );
    }


    // PHISHING_CAMPAIGN_PATTERN_V10

    // Detect brand names combined with phishing-related actions.
    const campaignActionTerms = [
        "login", "signin", "verify", "verification",
        "account", "secure", "update", "confirm",
        "payment", "billing", "wallet", "password",
        "register", "business", "tracking", "delivery"
    ];

    const campaignText = (
        hostname + " " + url.pathname + " " + url.search
    ).toLowerCase();

    const campaignBrand = monitoredBrandNames.find(brand =>
        campaignText.includes(brand)
    );

    const campaignAction = campaignActionTerms.find(term =>
        campaignText.includes(term)
    );

    if (
        campaignBrand &&
        campaignAction &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            25,
            "BRAND_ACTION_CAMPAIGN_PATTERN",
            "A monitored brand name is combined with a phishing-related action"
        );
    }

    // Hosted infrastructure combined with credential or payment actions.
    const hostedCampaignActions = [
        "login", "signin", "verify", "account",
        "password", "payment", "billing", "wallet",
        "business-center", "register"
    ];

    const hostedCampaignAction = hostedCampaignActions.some(term =>
        campaignText.includes(term)
    );

    if (
        matchedPlatform &&
        hostedCampaignAction &&
        !indicators.includes("SUSPICIOUS_HOSTED_TENANT")
    ) {
        addFinding(
            15,
            "HOSTED_PHISHING_CAMPAIGN_PATTERN",
            "Hosted website combines third-party hosting with a credential or payment action"
        );
    }

    // Detect brand-action combinations in URL fragments.
    const fragmentText = url.hash.toLowerCase();

    if (
        campaignBrand &&
        campaignActionTerms.some(term => fragmentText.includes(term)) &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            10,
            "BRAND_ACTION_FRAGMENT_PATTERN",
            "URL fragment combines a monitored brand with a suspicious action"
        );
    }


    // ADVANCED_PHISHING_KIT_DETECTION_V11

    const kitPath = url.pathname.toLowerCase();
    const kitQuery = url.search.toLowerCase();
    const kitText = kitPath + " " + kitQuery;

    // Common credential-harvesting endpoint patterns.
    const credentialEndpoints = [
        /\/(?:login|signin|sign-in|log-in)(?:\.php|\.html)?\/?$/i,
        /\/(?:authenticate|authentication|auth)\.php$/i,
        /\/(?:process|submit|validate|verify|confirm)(?:login|account|user)/i,
        /\/(?:webscr|webscr\.php|session\/verify)$/i
    ];

    const hasCredentialEndpoint = credentialEndpoints.some(pattern =>
        pattern.test(kitPath)
    );

    // Payment and financial information capture paths.
    const paymentCapturePaths = [
        /\/(?:payment|billing|checkout|card-details)(?:\/|\.php|\.html|$)/i,
        /\/(?:credit-card|debit-card|payment-details)(?:\/|$)/i,
        /\/(?:secure-payment|confirm-payment)(?:\/|$)/i
    ];

    const hasPaymentCapturePath = paymentCapturePaths.some(pattern =>
        pattern.test(kitPath)
    );

    // Phishing-kit indicators frequently combined in fake login pages.
    const kitTerms = [
        "password", "credential", "webmail",
        "secure-login", "account-verify",
        "session-expired", "confirm-identity",
        "recover-account", "unlock-account"
    ];

    const matchedKitTerms = kitTerms.filter(term =>
        kitText.includes(term)
    );

    if (
        !isGenuineBrandDomain &&
        hasCredentialEndpoint &&
        (
            matchedKitTerms.length > 0 ||
            indicators.includes("BRAND_KEYWORD_IMPERSONATION") ||
            indicators.includes("BRAND_ROOT_DOMAIN_IMPERSONATION") ||
            indicators.includes("BRAND_ACTION_CAMPAIGN_PATTERN")
        )
    ) {
        addFinding(
            25,
            "PHISHING_KIT_CREDENTIAL_ENDPOINT",
            "Credential endpoint is combined with additional phishing-kit indicators"
        );
    }

    if (
        !isGenuineBrandDomain &&
        hasPaymentCapturePath &&
        (
            matchedKitTerms.length > 0 ||
            indicators.includes("BRAND_ACTION_CAMPAIGN_PATTERN") ||
            indicators.includes("BRAND_ROOT_DOMAIN_IMPERSONATION")
        )
    ) {
        addFinding(
            25,
            "PHISHING_KIT_PAYMENT_ENDPOINT",
            "Payment capture path is combined with additional phishing indicators"
        );
    }

    // Suspicious authentication and identity verification combinations.
    const identityTerms = [
        "identity", "verification", "validate",
        "security-check", "account-recovery"
    ];

    const identityTermCount = identityTerms.filter(term =>
        kitText.includes(term)
    ).length;

    if (
        !isGenuineBrandDomain &&
        identityTermCount >= 2
    ) {
        addFinding(
            15,
            "IDENTITY_HARVESTING_PATTERN",
            "URL contains multiple identity-verification workflow indicators"
        );
    }

    // Detect suspicious executable-looking web endpoints.
    const sensitiveEndpoint = /\.(?:php|asp|aspx|jsp)$/i.test(kitPath);

    if (
        !isGenuineBrandDomain &&
        sensitiveEndpoint &&
        (
            matchedKitTerms.length > 0 ||
            indicators.includes("BRAND_ACTION_CAMPAIGN_PATTERN") ||
            indicators.includes("BRAND_ROOT_DOMAIN_IMPERSONATION")
        )
    ) {
        addFinding(
            15,
            "SUSPICIOUS_AUTHENTICATION_SCRIPT",
            "Dynamic web endpoint is combined with phishing-related indicators"
        );
    }


    // DOMAIN_HOSTING_REPUTATION_V12

    // Hosting providers commonly used for legitimate and malicious content.
    // Hosting alone is not evidence of phishing.
    const sharedHostingProviders = [
        "vercel.app", "netlify.app", "pages.dev",
        "workers.dev", "web.app", "firebaseapp.com",
        "weebly.com", "yourwebs.app", "github.io",
        "gitbook.io", "blogspot.com", "4everland.app",
        "craftum.io", "temporary.site", "backblazeb2.com"
    ];

    const sharedHostingProvider = sharedHostingProviders.find(provider =>
        hostname === provider || hostname.endsWith("." + provider)
    );

    const reputationRiskSignals = [
        "BRAND_KEYWORD_IMPERSONATION",
        "BRAND_ROOT_DOMAIN_IMPERSONATION",
        "BRAND_ACTION_CAMPAIGN_PATTERN",
        "SUSPICIOUS_HOSTED_TENANT",
        "RANDOMIZED_HOSTED_TENANT",
        "PHISHING_KIT_CREDENTIAL_ENDPOINT",
        "PHISHING_KIT_PAYMENT_ENDPOINT",
        "HIGH_SIGNAL_PATH_ANALYSIS",
        "SUSPICIOUS_PATH_COMBINATION"
    ];

    const hasReputationRisk = reputationRiskSignals.some(signal =>
        indicators.includes(signal)
    );

    if (sharedHostingProvider && hasReputationRisk) {
        addFinding(
            20,
            "SHARED_HOSTING_RISK_COMBINATION",
            "Shared hosting infrastructure is combined with additional phishing indicators"
        );
    }

    // Temporary-hosting naming combined with suspicious URL behavior.
    const temporaryHostingPattern =
        /(?:temporary|temp|freehost|instant|pages|sitebuilder)/i;

    if (
        temporaryHostingPattern.test(hostname) &&
        hasReputationRisk
    ) {
        addFinding(
            15,
            "TEMPORARY_HOSTING_RISK",
            "Temporary or site-builder hosting is combined with phishing indicators"
        );
    }

    // URL shorteners are not malicious by themselves.
    // Flag only when a redirect or nested external destination is also present.
    const knownShorteners = [
        "bit.ly", "tinyurl.com", "t.co", "is.gd",
        "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"
    ];

    const isShortener = knownShorteners.some(domain =>
        hostname === domain || hostname.endsWith("." + domain)
    );

    if (
        isShortener &&
        (
            indicators.includes("EXTERNAL_REDIRECT_PARAMETER") ||
            indicators.includes("NESTED_EXTERNAL_URL")
        )
    ) {
        addFinding(
            20,
            "SHORTENER_REDIRECT_RISK",
            "URL shortener is combined with an external redirect destination"
        );
    }


    // INTELLIGENT_RISK_CORRELATION_V13

    // Correlate independent categories of phishing evidence.
    const evidenceGroups = {
        brand: [
            "BRAND_KEYWORD_IMPERSONATION",
            "BRAND_ROOT_DOMAIN_IMPERSONATION",
            "BRAND_DOMAIN_IMPERSONATION",
            "TYPOSQUATTING_BRAND_IMPERSONATION",
            "POSTAL_BRAND_IMPERSONATION",
            "UNVERIFIED_BRAND_ROOT_DOMAIN"
        ],
        credential: [
            "PHISHING_KIT_CREDENTIAL_ENDPOINT",
            "PHISHING_KIT_PAYMENT_ENDPOINT",
            "CREDENTIAL_HARVESTING_PARAMETERS",
            "IDENTITY_HARVESTING_PATTERN"
        ],
        infrastructure: [
            "SUSPICIOUS_HOSTED_TENANT",
            "RANDOMIZED_HOSTED_TENANT",
            "RANDOMIZED_HOSTED_SUBDOMAIN",
            "RANDOMIZED_SUBDOMAIN",
            "SHARED_HOSTING_RISK_COMBINATION",
            "TEMPORARY_HOSTING_RISK"
        ],
        deception: [
            "UNICODE_HOMOGRAPH_DOMAIN",
            "MIXED_SCRIPT_HOSTNAME",
            "NESTED_EXTERNAL_URL",
            "EXTERNAL_REDIRECT_PARAMETER",
            "SUSPICIOUS_PATH_COMBINATION",
            "HIGH_SIGNAL_PATH_ANALYSIS"
        ]
    };

    const activeEvidenceGroups = Object.values(evidenceGroups)
        .filter(group => group.some(code => indicators.includes(code)))
        .length;

    if (activeEvidenceGroups >= 3) {
        addFinding(
            15,
            "MULTI_LAYER_PHISHING_CORRELATION",
            "Multiple independent categories of phishing indicators were detected"
        );
    } else if (activeEvidenceGroups === 2) {
        addFinding(
            8,
            "COMBINED_PHISHING_EVIDENCE",
            "Two independent categories of suspicious indicators were detected"
        );
    }


    // URL_EVASION_DETECTION_V14

    // Detect repeated percent encoding.
    const repeatedlyEncoded = /%25(?:[0-9a-f]{2})/i.test(
        rawURL
    );

    if (repeatedlyEncoded) {
        addFinding(
            15,
            "DOUBLE_URL_ENCODING",
            "URL contains repeatedly percent-encoded characters"
        );
    }

    // Detect encoded path separators.
    const encodedSeparators = /%(?:2f|5c|252f|255c)/i.test(
        rawURL
    );

    if (encodedSeparators) {
        addFinding(
            10,
            "ENCODED_PATH_SEPARATOR",
            "URL contains encoded forward or backward path separators"
        );
    }

    // Detect null bytes and control characters.
    const containsControlCharacters =
        /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(rawURL) ||
        /%00|%0[1-8]|%0b|%0c|%0e|%0f|%1[0-9a-f]|%7f/i.test(rawURL);

    if (containsControlCharacters) {
        addFinding(
            25,
            "URL_CONTROL_CHARACTER",
            "URL contains encoded or literal control characters"
        );
    }

    // Detect punycode combined with additional deception indicators.
    const hasPunycode = labels.some(label =>
        label.startsWith("xn--")
    );

    if (
        hasPunycode &&
        (
            indicators.includes("BRAND_ROOT_DOMAIN_IMPERSONATION") ||
            indicators.includes("BRAND_KEYWORD_IMPERSONATION") ||
            indicators.includes("SUSPICIOUS_KEYWORDS")
        )
    ) {
        addFinding(
            20,
            "PUNYCODE_DECEPTION_COMBINATION",
            "Punycode hostname is combined with additional phishing indicators"
        );
    }


    // ADVANCED_DOMAIN_ANALYSIS_V15

    // Detect monitored brands hidden inside deceptive hostname labels.
    const v15BrandLabel = labels.find((label, index) => {
        if (index === labels.length - 1) return false;

        return monitoredBrandNames.some(brand =>
            brand.length >= 4 &&
            label !== brand &&
            label.includes(brand)
        );
    });

    if (
        v15BrandLabel &&
        !isGenuineBrandDomain &&
        !indicators.includes("BRAND_KEYWORD_IMPERSONATION") &&
        !indicators.includes("BRAND_ROOT_DOMAIN_IMPERSONATION")
    ) {
        addFinding(
            25,
            "DECEPTIVE_BRAND_LABEL_V15",
            "A hostname label embeds a monitored brand name"
        );
    }

    // Detect deep subdomain structures combined with suspicious terms.
    const v15Subdomains = labels.slice(0, -2);

    const v15SuspiciousTerms = [
        "login", "verify", "account", "secure",
        "payment", "wallet", "password", "update"
    ];

    const v15HasSuspiciousSubdomain = v15Subdomains.some(label =>
        v15SuspiciousTerms.some(term => label.includes(term))
    );

    if (
        v15Subdomains.length >= 4 &&
        v15HasSuspiciousSubdomain &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            15,
            "DEEP_SUBDOMAIN_RISK_V15",
            "Deep subdomain structure contains phishing-related terminology"
        );
    }


    // PHISHING_INFRASTRUCTURE_V16

    // Detect suspicious hosted-platform tenant combinations.
    const v16HostingPlatforms = [
        "vercel.app", "netlify.app", "pages.dev",
        "workers.dev", "web.app", "firebaseapp.com",
        "weebly.com", "yourwebs.app", "github.io",
        "gitbook.io", "4everland.app", "craftum.io",
        "temporary.site"
    ];

    const v16Platform = v16HostingPlatforms.find(platform =>
        hostname.endsWith("." + platform)
    );

    const v16PlatformLabels = v16Platform
        ? v16Platform.split(".")
        : [];

    const v16TenantIndex = v16Platform
        ? labels.length - v16PlatformLabels.length - 1
        : -1;

    const v16Tenant = v16TenantIndex >= 0
        ? labels[v16TenantIndex]
        : "";

    const v16TenantLooksDeceptive =
        /(?:verify|secure|account|login|paypal|microsoft|netflix|facebook|apple|amazon|banking)/i
            .test(v16Tenant);

    const v16CredentialPath =
        /(?:login|signin|password|verify|account|payment|billing|wallet|register)/i
            .test(url.pathname);

    if (
        v16Platform &&
        v16TenantLooksDeceptive &&
        v16CredentialPath &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            25,
            "HOSTED_PHISHING_INFRASTRUCTURE_V16",
            "Hosted tenant combines deceptive naming with a credential-related page"
        );
    }

    // Detect suspicious campaign-style hostnames.
    const v16CampaignPattern =
        /(?:business-number|veryfied|account-security|secure-login|customer-verify)/i;

    if (
        v16CampaignPattern.test(hostname) &&
        (
            v16CredentialPath ||
            indicators.includes("BRAND_ACTION_CAMPAIGN_PATTERN")
        )
    ) {
        addFinding(
            20,
            "PHISHING_CAMPAIGN_INFRASTRUCTURE_V16",
            "Hostname contains a phishing campaign naming pattern combined with suspicious activity"
        );
    }

    // Detect unusual hosting tenants with both numeric and alphabetic content.
    const v16NormalizedTenant = v16Tenant.replace(/[^a-z0-9]/gi, "");

    if (
        v16Platform &&
        v16NormalizedTenant.length >= 12 &&
        /[a-z]/i.test(v16NormalizedTenant) &&
        /\d/.test(v16NormalizedTenant) &&
        v16CredentialPath &&
        !indicators.includes("RANDOMIZED_HOSTED_TENANT") &&
        !indicators.includes("SUSPICIOUS_HOSTED_TENANT")
    ) {
        addFinding(
            15,
            "UNUSUAL_HOSTED_TENANT_ACTIVITY_V16",
            "Unusual hosted tenant name is combined with a credential-related URL path"
        );
    }



    // TARGETED OPENPHISH GAP DETECTION

    // Unusual tenant naming on hosted platforms.
    const targetedTenant = v16Tenant.replace(/[^a-z0-9]/gi, "");
    const targetedUniqueRatio = targetedTenant.length
        ? new Set(targetedTenant).size / targetedTenant.length
        : 0;
    const targetedVowelRatio = targetedTenant.length
        ? (targetedTenant.match(/[aeiou]/gi) || []).length / targetedTenant.length
        : 1;

    if (
        v16Platform &&
        targetedTenant.length >= 12 &&
        targetedUniqueRatio >= 0.60 &&
        targetedVowelRatio <= 0.40 &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            10,
            "UNUSUAL_HOSTED_TENANT_NAME",
            "Hosted platform tenant has an unusual name structure"
        );
    }

    // Consonant-heavy subdomains under .biz.id.
    const targetedBizIdLabels = hostname.endsWith(".biz.id")
        ? labels.slice(0, -3)
        : [];

    if (
        targetedBizIdLabels.some(label =>
            /^[a-z]{5,7}$/i.test(label) &&
            (label.match(/[aeiou]/gi) || []).length <= 1
        ) &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            15,
            "SUSPICIOUS_BIZ_ID_SUBDOMAIN",
            "Short consonant-heavy subdomain detected under .biz.id"
        );
    }

    // Domain-like identifiers embedded in URL fragments.
    if (
        /@[a-z0-9-]{12,}\.[a-z]{2,}(?:[\/?#]|$)/i.test(fragment) &&
        !isGenuineBrandDomain
    ) {
        addFinding(
            15,
            "DOMAIN_LIKE_FRAGMENT",
            "URL fragment contains a domain-like identifier"
        );
    }

    // FALSE_POSITIVE_PROTECTION_V18
    // Exact trusted service domains suppress generic hostname keyword scoring.
    // They do not bypass other security indicators or URL analysis.
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

    
    // FINAL_ENGINE_OPTIMIZATION_V20
    // Normalize the final score and remove duplicate output signals.
    riskScore = Math.min(100, Math.max(0, Math.round(
        Number.isFinite(Number(riskScore)) ? Number(riskScore) : 0
    )));

    const v20UniqueIndicators = [...new Set(indicators)];
    indicators.splice(0, indicators.length, ...v20UniqueIndicators);

    const v20UniqueFindings = [...new Set(findings)];
    findings.splice(0, findings.length, ...v20UniqueFindings);

    if (severity !== "INVALID") {
        severity = riskScore >= 60
            ? "HIGH"
            : riskScore >= 30
                ? "MEDIUM"
                : "LOW";
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


export { analyzeURL };
