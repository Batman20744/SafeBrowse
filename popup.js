document.addEventListener("DOMContentLoaded", async () => {

    const $ = id => document.getElementById(id);

    const websiteURL = $("websiteURL");
    const statusText = $("statusText");
    const resultText = $("resultText");
    const riskScore = $("riskScore");
    const severityText = $("severityText");
    const riskBar = $("riskBar");

    const scanButton = $("scanButton");
    const clearHistoryButton = $("clearHistoryButton");
    const historyList = $("historyList");
    const openDashboardButton = $("openDashboardButton");

    let currentURL = "";

    // OPEN FULL-SCREEN DASHBOARD
    openDashboardButton.addEventListener("click", () => {
        chrome.tabs.create({
            url: chrome.runtime.getURL("dashboard.html")
        });
    });

    // LOAD CURRENT BROWSER TAB
    try {
        const tabs = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        if (tabs.length && tabs[0].url) {
            currentURL = tabs[0].url;
            websiteURL.textContent = currentURL;
        } else {
            websiteURL.textContent = "Website unavailable";
        }
    } catch (error) {
        websiteURL.textContent = "Unable to access current tab";
    }

    await loadHistory();

    // PERFORM URL SECURITY SCAN
    scanButton.addEventListener("click", async () => {

        if (!/^https?:\/\//i.test(currentURL)) {
            statusText.textContent = "Unsupported page";
            resultText.textContent =
                "Open a regular HTTP or HTTPS website.";
            return;
        }

        scanButton.disabled = true;
        scanButton.textContent = "SCANNING...";

        try {
            const analysis = analyzeURL(currentURL);

            const blockResult =
                checkBlocklist(analysis.hostname);

            let score = analysis.riskScore;
            let findings = [...analysis.findings];

            if (blockResult.blocked) {
                score = Math.max(score, 80);

                findings.unshift(
                    "LOCAL BLOCKLIST MATCH: " +
                    blockResult.matchedDomain
                );
            }

            score = Math.min(score, 100);

            const severity = blockResult.blocked || score >= 60
                ? "HIGH"
                : score >= 30
                    ? "MEDIUM"
                    : "LOW";

            displayResults(score, severity, findings);

            await saveHistory({
                url: currentURL,
                score,
                severity,
                time: new Date().toLocaleString()
            });

        } catch (error) {
            statusText.textContent = "Scan failed";
            resultText.textContent = error.message;
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "SCAN WEBSITE";
        }
    });

    // DISPLAY RESULTS
    function displayResults(score, severity, findings) {

        riskScore.textContent = score;
        severityText.textContent = "Risk Level: " + severity;

        const colors = {
            HIGH: "#ff5555",
            MEDIUM: "#ffb347",
            LOW: "#62c99b"
        };

        const color = colors[severity];

        statusText.textContent = severity === "HIGH"
            ? "High Risk Indicators Detected"
            : severity === "MEDIUM"
                ? "Suspicious Indicators Found"
                : "Low Risk Indicators";

        statusText.style.color = color;
        severityText.style.color = color;
        riskScore.style.color = color;
        riskBar.style.width = score + "%";
        riskBar.style.background = color;

        resultText.replaceChildren();

        findings.forEach(finding => {
            const line = document.createElement("div");
            line.className = "finding";
            line.textContent = "• " + finding;
            resultText.appendChild(line);
        });
    }

    // SAVE UP TO 20 RECENT SCANS
    async function saveHistory(entry) {

        const data = await chrome.storage.local.get("scanHistory");

        const history = Array.isArray(data.scanHistory)
            ? data.scanHistory
            : [];

        history.unshift(entry);

        await chrome.storage.local.set({
            scanHistory: history.slice(0, 20)
        });

        await loadHistory();
    }

    // DISPLAY SCAN HISTORY
    async function loadHistory() {

        const data = await chrome.storage.local.get("scanHistory");

        const history = Array.isArray(data.scanHistory)
            ? data.scanHistory
            : [];

        historyList.replaceChildren();

        if (!history.length) {
            historyList.textContent = "No scan history.";
            return;
        }

        history.forEach(item => {

            const container = document.createElement("div");
            container.className = "history-item";

            const url = document.createElement("div");
            url.textContent = item.url;

            const score = document.createElement("div");
            score.className = "history-score";
            score.textContent =
                item.severity + " | Risk: " + item.score + "/100";

            const time = document.createElement("div");
            time.className = "history-time";
            time.textContent = item.time;

            container.append(url, score, time);
            historyList.appendChild(container);
        });
    }

    // CLEAR SCAN HISTORY
    clearHistoryButton.addEventListener("click", async () => {

        await chrome.storage.local.set({
            scanHistory: []
        });

        await loadHistory();
    });

});
