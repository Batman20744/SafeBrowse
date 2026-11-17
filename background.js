chrome.runtime.onInstalled.addListener(async () => {
    const data = await chrome.storage.local.get(["scanHistory"]);

    if (!Array.isArray(data.scanHistory)) {
        await chrome.storage.local.set({
            scanHistory: []
        });
    }

    console.log("SafeBrowse v1.0.0 installed.");
});



// SAFEBROWSE_REAL_TIME_WARNING_V21
importScripts("url-analyzer.js", "blocklist.js");

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    const pageURL = details.url;
    if (!/^https?:\/\//i.test(pageURL)) return;

    try {
        const analysis = globalThis.SafeBrowseAnalyzer.analyzeURL(pageURL);

        let score = Number(analysis.riskScore) || 0;
        let findings = [...(analysis.findings || [])];

        const blockResult =
            typeof checkBlocklist === "function"
                ? checkBlocklist(analysis.hostname)
                : { blocked: false };

        if (blockResult && blockResult.blocked) {
            score = Math.max(score, 80);
            findings.unshift(
                "LOCAL BLOCKLIST MATCH: " + blockResult.matchedDomain
            );
        }

        score = Math.min(100, score);

        const severity = blockResult?.blocked || score >= 60
            ? "HIGH"
            : score >= 30
                ? "MEDIUM"
                : "LOW";

        await chrome.action.setBadgeText({
            tabId: details.tabId,
            text: severity === "HIGH" ? "!" : ""
        });

        await chrome.action.setBadgeBackgroundColor({
            tabId: details.tabId,
            color: "#dc2626"
        });

        const stored = await chrome.storage.local.get(["scanHistory"]);
        const history = Array.isArray(stored.scanHistory)
            ? stored.scanHistory
            : [];

        if (severity === "HIGH") {
            const entry = {
                url: pageURL,
                score,
                riskScore: score,
                severity,
                findings,
                time: new Date().toLocaleString(),
                timestamp: Date.now(),
                source: "automatic-tab-scan"
            };

            const updatedHistory = history.filter(
                item => item.url !== pageURL
            );

            updatedHistory.unshift(entry);

            await chrome.storage.local.set({
                scanHistory: updatedHistory.slice(0, 100)
            });

            await chrome.notifications.create(
                "safebrowse-warning-" + details.tabId,
                {
                    type: "basic",
                    iconUrl: "safebrowse-warning.png",
                    title: "SafeBrowse: High Risk Website",
                    message: "Risk score: " + score +
                        "/100. Suspicious website detected.",
                    priority: 2
                }
            );
        }
    } catch (error) {
        console.error("SafeBrowse warning system error:", error);
    }
});


// SAFEBROWSE_INTERACTIVE_THREAT_RESPONSE_V22
// Clicking a threat notification focuses the flagged browser tab.
chrome.notifications.onClicked.addListener(async (notificationId) => {
    const prefix = "safebrowse-warning-";

    if (!notificationId.startsWith(prefix)) return;

    const tabId = Number(notificationId.slice(prefix.length));
    if (!Number.isInteger(tabId)) return;

    try {
        const tab = await chrome.tabs.get(tabId);

        if (tab.windowId !== undefined) {
            await chrome.windows.update(tab.windowId, {
                focused: true
            });
        }

        await chrome.tabs.update(tabId, {
            active: true
        });

        await chrome.notifications.clear(notificationId);
    } catch (error) {
        console.warn("SafeBrowse could not reopen the flagged tab:", error);
    }
});
