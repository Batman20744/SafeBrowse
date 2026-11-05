/* =========================================
   SAFEBROWSE v1.0.0
   SECURITY DASHBOARD
========================================= */

document.addEventListener("DOMContentLoaded", async () => {
    const $ = id => document.getElementById(id);

    let scanHistory = [];

    const COLORS = {
        purpleDark: "#6D28D9",
        purple: "#9333EA",
        purpleLight: "#A855F7",
        purplePale: "#C084FC",
        pink: "#ed42cb",
        green: "#42d6a0",
        orange: "#ffad55",
        red: "#ff5475",
        muted: "#9189a5",
        grid: "#30263f",
        text: "#d9d0e8"
    };

    const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

    // =====================================
    // HELPERS
    // =====================================

    function escapeHTML(value) {
        return String(value ?? "").replace(/[&<>"']/g, char => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[char]);
    }

    function getSeverityCount(severity) {
        return scanHistory.filter(item =>
            String(item.severity).toUpperCase() === severity
        ).length;
    }

    function severityClass(severity) {
        const value = String(severity || "LOW").toUpperCase();
        return SEVERITIES.includes(value) ? value : "LOW";
    }

    function formatHostname(value) {
        try {
            return new URL(value).hostname;
        } catch {
            return String(value || "Unknown");
        }
    }

    // =====================================
    // CHROME STORAGE
    // =====================================

    async function loadHistory() {
        try {
            const data = await chrome.storage.local.get("scanHistory");

            scanHistory = Array.isArray(data.scanHistory)
                ? data.scanHistory
                : [];

            renderDashboard();

        } catch (error) {
            console.error("Storage error:", error);
        }
    }

    // =====================================
    // NAVIGATION
    // =====================================

    document.querySelectorAll(".nav-item").forEach(button => {
        button.addEventListener("click", () => {
            navigateTo(button.dataset.page);
        });
    });

    document.querySelectorAll("[data-goto]").forEach(button => {
        button.addEventListener("click", () => {
            navigateTo(button.dataset.goto);
        });
    });

    function navigateTo(pageName) {
        const pages = [
            "overview", "scanner", "alerts",
            "history", "blocklist", "reports", "settings"
        ];

        if (!pages.includes(pageName)) return;

        document.querySelectorAll(".page").forEach(page => {
            page.classList.remove("active");
        });

        document.querySelectorAll(".nav-item").forEach(button => {
            button.classList.toggle(
                "active",
                button.dataset.page === pageName
            );
        });

        const selectedPage = $("page-" + pageName);

        if (selectedPage) selectedPage.classList.add("active");

        const titles = {
            overview: "Dashboard Overview",
            scanner: "URL Security Scanner",
            alerts: "Threat Alerts",
            history: "Scan History",
            blocklist: "Domain Blocklist",
            reports: "Security Reports",
            settings: "Application Settings"
        };

        $("pageTitle").textContent = titles[pageName];

        if (pageName === "overview") {
            requestAnimationFrame(renderCharts);
        }

        if (pageName === "scanner") {
            $("urlInput").focus();
        }
    }

    // =====================================
    // STATISTICS
    // =====================================

    function updateStatistics() {
        const total = scanHistory.length;

        const low = getSeverityCount("LOW");
        const medium = getSeverityCount("MEDIUM");
        const high = getSeverityCount("HIGH");
        const critical = getSeverityCount("CRITICAL");

        const totalRisk = scanHistory.reduce(
            (sum, item) => sum + Math.max(
                0,
                Math.min(100, Number(item.score) || 0)
            ),
            0
        );

        const average = total
            ? Math.round(totalRisk / total)
            : 0;

        const detected = medium + high + critical;

        const rate = total
            ? Math.round((detected / total) * 100)
            : 0;

        const values = {
            totalScans: total,
            highAlerts: high,
            mediumAlerts: medium,
            lowAlerts: low,
            criticalAlerts: critical,
            blockedDomains: Array.isArray(
                globalThis.SafeBrowseBlocklist?.BLOCKED_DOMAINS
            )
                ? globalThis.SafeBrowseBlocklist.BLOCKED_DOMAINS.length
                : 0,
            averageRisk: average,
            detectionRate: rate + "%"
        };

        Object.entries(values).forEach(([id, value]) => {
            const element = $(id);
            if (element) element.textContent = value;
        });

        $("donutTotal").textContent = total;
    }

    // =====================================
    // CANVAS ENGINE + TOOLTIP
    // =====================================

    function drawCanvas(id, drawFunction) {
        const canvas = $(id);
        if (!canvas) return;

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const rect = canvas.getBoundingClientRect();

        const width = Math.floor(rect.width);
        const height = Math.floor(rect.height);

        if (width <= 0 || height <= 0) return;

        const ratio = window.devicePixelRatio || 1;

        // Set physical resolution without changing CSS dimensions.
        const pixelWidth = Math.round(width * ratio);
        const pixelHeight = Math.round(height * ratio);

        if (canvas.width !== pixelWidth ||
            canvas.height !== pixelHeight) {
            canvas.width = pixelWidth;
            canvas.height = pixelHeight;
        }

        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        ctx.clearRect(0, 0, width, height);

        const hitRegions = [];

        drawFunction(ctx, width, height, hitRegions, null);

        canvas._hitRegions = hitRegions;
        canvas._chartDraw = drawFunction;

        let tooltip = canvas.parentElement.querySelector(
            ".chart-tooltip"
        );

        if (!tooltip) {
            canvas.parentElement.style.position = "relative";

            tooltip = document.createElement("div");
            tooltip.className = "chart-tooltip";

            canvas.parentElement.appendChild(tooltip);
        }

        if (canvas._hoverEventsAttached) return;

        canvas.addEventListener("mousemove", event => {
            const bounds = canvas.getBoundingClientRect();

            const x = event.clientX - bounds.left;
            const y = event.clientY - bounds.top;

            const region = (canvas._hitRegions || []).find(item => {
                if (item.donut) {
                    const dx = x - item.centerX;
                    const dy = y - item.centerY;

                    const distance = Math.sqrt(dx * dx + dy * dy);

                    let angle = Math.atan2(dy, dx);

                    if (angle < -Math.PI / 2) {
                        angle += Math.PI * 2;
                    }

                    return distance >= item.radius - item.thickness / 2 - 8 &&
                        distance <= item.radius + item.thickness / 2 + 8 &&
                        angle >= item.startAngle &&
                        angle <= item.endAngle;
                }

                return x >= item.x &&
                    x <= item.x + item.width &&
                    y >= item.y &&
                    y <= item.y + item.height;
            });

            if (region) {
                tooltip.innerHTML =
                    "<strong>" + escapeHTML(region.title) +
                    "</strong>" + escapeHTML(region.value);

                tooltip.style.display = "block";

                tooltip.style.left =
                    Math.min(x + 12, width - 150) + "px";

                tooltip.style.top =
                    Math.max(5, y - 45) + "px";

                canvas.style.cursor = "pointer";

            } else {
                tooltip.style.display = "none";
                canvas.style.cursor = "crosshair";
            }
        });

        canvas.addEventListener("mouseleave", () => {
            tooltip.style.display = "none";
            canvas.style.cursor = "crosshair";
        });

        canvas._hoverEventsAttached = true;
    }

    // =====================================
    // CHART 1: ALERTS BY SEVERITY
    // =====================================

    function drawSeverityChart() {
        drawCanvas("severityChart", (ctx, width, height, regions) => {
            const items = [
                { label: "Critical", value: getSeverityCount("CRITICAL"), color: COLORS.purpleDark },
                { label: "High", value: getSeverityCount("HIGH"), color: COLORS.purple },
                { label: "Medium", value: getSeverityCount("MEDIUM"), color: COLORS.purpleLight },
                { label: "Low", value: getSeverityCount("LOW"), color: COLORS.purplePale }
            ];

            const left = 38;
            const right = width - 15;
            const top = 15;
            const bottom = height - 30;

            const chartHeight = bottom - top;

            const maximum = Math.max(1, ...items.map(i => i.value));
            const scale = Math.ceil(maximum / 5) * 5 || 5;

            ctx.font = "10px Arial";
            ctx.textAlign = "right";
            ctx.fillStyle = COLORS.muted;
            ctx.strokeStyle = COLORS.grid;

            for (let i = 0; i <= 4; i++) {
                const y = bottom - (i / 4) * chartHeight;

                ctx.beginPath();
                ctx.moveTo(left, y);
                ctx.lineTo(right, y);
                ctx.stroke();

                ctx.fillText(
                    String(Math.round(scale * i / 4)),
                    left - 7,
                    y + 3
                );
            }

            const slot = (right - left) / items.length;
            const barWidth = Math.min(42, slot * 0.55);

            items.forEach((item, index) => {
                const barHeight = (item.value / scale) * chartHeight;

                const x = left + index * slot + (slot - barWidth) / 2;
                const y = bottom - barHeight;

                ctx.fillStyle = item.color;

                ctx.fillRect(
                    x,
                    y,
                    barWidth,
                    Math.max(2, barHeight)
                );

                ctx.fillStyle = COLORS.text;
                ctx.textAlign = "center";

                ctx.fillText(
                    String(item.value),
                    x + barWidth / 2,
                    Math.max(top + 10, y - 6)
                );

                regions.push({
                    title: item.label,
                    value: item.value + " alerts",
                    x,
                    y: top,
                    width: barWidth,
                    height: chartHeight
                });
            });
        });
    }

    // =====================================
    // CHART 2: ESCALATIONS VS TOTAL ALERTS
    // =====================================

    function drawEscalationChart() {
        drawCanvas("escalationChart", (ctx, width, height, regions) => {
            const labels = ["Low", "Medium", "High", "Critical"];

            const series = [
                {
                    label: "Total Scans",
                    values: labels.map(label =>
                        getSeverityCount(label.toUpperCase())
                    ),
                    color: COLORS.purple
                },
                {
                    label: "High/Critical",
                    values: labels.map(label =>
                        ["HIGH", "CRITICAL"].includes(label.toUpperCase())
                            ? getSeverityCount(label.toUpperCase())
                            : 0
                    ),
                    color: COLORS.pink
                }
            ];

            const left = 38;
            const right = width - 15;
            const top = 15;
            const bottom = height - 30;

            const chartHeight = bottom - top;

            const maximum = Math.max(
                1,
                ...series.flatMap(s => s.values)
            );

            const scale = Math.ceil(maximum / 5) * 5 || 5;

            ctx.strokeStyle = COLORS.grid;
            ctx.fillStyle = COLORS.muted;
            ctx.textAlign = "right";
            ctx.font = "10px Arial";

            for (let i = 0; i <= 4; i++) {
                const y = bottom - (i / 4) * chartHeight;

                ctx.beginPath();
                ctx.moveTo(left, y);
                ctx.lineTo(right, y);
                ctx.stroke();

                ctx.fillText(
                    String(Math.round(scale * i / 4)),
                    left - 7,
                    y + 3
                );
            }

            const pointX = index =>
                left + (index / (labels.length - 1)) * (right - left);

            labels.forEach((label, index) => {
                ctx.textAlign = "center";
                ctx.fillStyle = COLORS.muted;

                ctx.fillText(label, pointX(index), height - 8);
            });

            series.forEach((item, seriesIndex) => {
                ctx.beginPath();
                ctx.strokeStyle = item.color;
                ctx.lineWidth = 2;

                item.values.forEach((value, index) => {
                    const x = pointX(index);
                    const y = bottom - (value / scale) * chartHeight;

                    if (index === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                });

                ctx.stroke();

                item.values.forEach((value, index) => {
                    const x = pointX(index);
                    const y = bottom - (value / scale) * chartHeight;

                    ctx.beginPath();
                    ctx.arc(x, y, 3, 0, Math.PI * 2);
                    ctx.fillStyle = item.color;
                    ctx.fill();

                    regions.push({
                        title: item.label + " · " + labels[index],
                        value: value + " scans",
                        x: x - 10,
                        y: y - 10,
                        width: 20,
                        height: 20
                    });
                });
            });
        });
    }

    // =====================================
    // CHART 3: TOP 5 SOURCES
    // =====================================

    function drawSourcesChart() {
        drawCanvas("sourcesChart", (ctx, width, height, regions) => {
            const counts = {};

            scanHistory.forEach(item => {
                const host = formatHostname(item.url);
                counts[host] = (counts[host] || 0) + 1;
            });

            const sources = Object.entries(counts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);

            const left = Math.min(125, width * 0.4);
            const right = width - 15;
            const top = 16;
            const rowHeight = Math.min(34, (height - 35) / 5);

            const maximum = Math.max(
                1,
                ...sources.map(item => item[1])
            );

            ctx.font = "10px Arial";

            if (!sources.length) {
                ctx.fillStyle = COLORS.muted;
                ctx.textAlign = "center";
                ctx.fillText(
                    "No scan sources recorded",
                    width / 2,
                    height / 2
                );
                return;
            }

            sources.forEach(([name, value], index) => {
                const y = top + index * rowHeight;
                const barWidth = (value / maximum) * (right - left - 25);

                ctx.textAlign = "right";
                ctx.fillStyle = COLORS.text;

                ctx.fillText(
                    name.length > 18
                        ? name.slice(0, 16) + "…"
                        : name,
                    left - 8,
                    y + 12
                );

                ctx.fillStyle = COLORS.grid;
                ctx.fillRect(left, y, right - left - 25, 12);

                const gradient = ctx.createLinearGradient(
                    left, 0, left + barWidth, 0
                );

                gradient.addColorStop(0, COLORS.purpleDark);
                gradient.addColorStop(1, COLORS.purplePale);

                ctx.fillStyle = gradient;
                ctx.fillRect(left, y, Math.max(2, barWidth), 12);

                ctx.textAlign = "left";
                ctx.fillStyle = COLORS.muted;
                ctx.fillText(String(value), left + barWidth + 5, y + 10);

                regions.push({
                    title: name,
                    value: value + " scans",
                    x: left,
                    y: y - 4,
                    width: right - left - 25,
                    height: 22
                });
            });
        });
    }

    // =====================================
    // CHART 4: RISK DISTRIBUTION
    // =====================================

    function drawRiskChart() {
        drawCanvas("riskChart", (ctx, width, height, regions) => {
            const values = [
                getSeverityCount("LOW"),
                getSeverityCount("MEDIUM"),
                getSeverityCount("HIGH"),
                getSeverityCount("CRITICAL")
            ];

            const names = ["Low", "Medium", "High", "Critical"];

            const colors = [
                COLORS.purpleDark,
                COLORS.purple,
                COLORS.purpleLight,
                COLORS.purplePale
            ];

            const total = values.reduce((sum, value) => sum + value, 0);

            const centerX = width / 2;
            const centerY = height / 2;

            const radius = Math.min(width, height) * 0.39;
            const thickness = Math.max(15, radius * 0.35);

            let startAngle = -Math.PI / 2;

            if (total === 0) {
                ctx.beginPath();
                ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
                ctx.strokeStyle = COLORS.grid;
                ctx.lineWidth = thickness;
                ctx.stroke();
                return;
            }

            values.forEach((value, index) => {
                if (value === 0) return;

                const angle = (value / total) * Math.PI * 2;

                const endAngle = startAngle + angle;

                ctx.beginPath();

                ctx.arc(
                    centerX,
                    centerY,
                    radius,
                    startAngle,
                    endAngle
                );

                ctx.strokeStyle = colors[index];
                ctx.lineWidth = thickness;
                ctx.lineCap = "butt";
                ctx.stroke();

                regions.push({
                    title: names[index],
                    value: value + " scans",
                    donut: true,
                    startAngle,
                    endAngle,
                    centerX,
                    centerY,
                    radius,
                    thickness
                });

                startAngle = endAngle;
            });
        });
    }

    // =====================================
    // RENDER ALL CHARTS
    // =====================================

    function renderCharts() {
        drawSeverityChart();
        drawEscalationChart();
        drawSourcesChart();
        drawRiskChart();
    }

    // =====================================
    // RECENT ACTIVITY
    // =====================================

    function renderRecentActivity() {
        const tbody = $("recentActivity");
        tbody.replaceChildren();

        if (!scanHistory.length) {
            tbody.innerHTML =
                '<tr><td colspan="4" class="empty-state">' +
                'No scan activity recorded yet.</td></tr>';
            return;
        }

        scanHistory.slice(0, 5).forEach(item => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHTML(item.url)}</td>
                <td>${Number(item.score) || 0}/100</td>
                <td><span class="severity-badge ${severityClass(item.severity)}">${escapeHTML(severityClass(item.severity))}</span></td>
                <td>${escapeHTML(item.time)}</td>
            `;

            tbody.appendChild(row);
        });
    }

    // =====================================
    // THREAT ALERTS
    // =====================================

    function renderAlerts() {
        const tbody = $("alertsTable");
        tbody.replaceChildren();

        const alerts = scanHistory.filter(item =>
            ["MEDIUM", "HIGH", "CRITICAL"].includes(
                String(item.severity).toUpperCase()
            )
        );

        if (!alerts.length) {
            tbody.innerHTML =
                '<tr><td colspan="4" class="empty-state">' +
                'No threat alerts recorded.</td></tr>';
            return;
        }

        alerts.forEach(item => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHTML(item.url)}</td>
                <td>${Number(item.score) || 0}/100</td>
                <td><span class="severity-badge ${severityClass(item.severity)}">${escapeHTML(severityClass(item.severity))}</span></td>
                <td>${escapeHTML(item.time)}</td>
            `;

            tbody.appendChild(row);
        });
    }

    // =====================================
    // SCAN HISTORY
    // =====================================

    function renderHistory() {
        const tbody = $("historyTable");
        const search = $("historySearch").value.toLowerCase();
        const severity = $("severityFilter").value;

        tbody.replaceChildren();

        const filtered = scanHistory.filter(item => {
            const matchesSearch = String(item.url || "")
                .toLowerCase()
                .includes(search);

            const matchesSeverity = severity === "ALL" ||
                String(item.severity).toUpperCase() === severity;

            return matchesSearch && matchesSeverity;
        });

        if (!filtered.length) {
            tbody.innerHTML =
                '<tr><td colspan="4" class="empty-state">' +
                'No matching scan records found.</td></tr>';
            return;
        }

        filtered.forEach(item => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHTML(item.url)}</td>
                <td>${Number(item.score) || 0}/100</td>
                <td><span class="severity-badge ${severityClass(item.severity)}">${escapeHTML(severityClass(item.severity))}</span></td>
                <td>${escapeHTML(item.time)}</td>
            `;

            tbody.appendChild(row);
        });
    }

    $("historySearch").addEventListener("input", renderHistory);
    $("severityFilter").addEventListener("change", renderHistory);

    // =====================================
    // BLOCKLIST
    // =====================================

    function renderBlocklist() {
        const tbody = $("blocklistTable");
        tbody.replaceChildren();

        const domains =
            globalThis.SafeBrowseBlocklist?.BLOCKED_DOMAINS || [];

        if (!domains.length) {
            tbody.innerHTML =
                '<tr><td colspan="3" class="empty-state">' +
                'No blocklist domains available.</td></tr>';
            return;
        }

        domains.forEach(domain => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHTML(domain)}</td>
                <td><span class="severity-badge HIGH">BLOCKLISTED</span></td>
                <td>Local demonstration list</td>
            `;

            tbody.appendChild(row);
        });
    }

    // =====================================
    // URL SCANNER
    // =====================================

    $("scanURLButton").addEventListener("click", async () => {
        const input = $("urlInput").value.trim();
        const button = $("scanURLButton");
        const result = $("scannerResult");

        if (!input) {
            result.textContent = "Please enter a URL.";
            return;
        }

        button.disabled = true;
        button.textContent = "SCANNING...";

        try {
            const analysis = analyzeURL(input);

            if (!analysis.valid) {
                result.textContent =
                    "Invalid URL: " + analysis.findings.join(", ");
                return;
            }

            const blockResult = checkBlocklist(analysis.hostname);

            let score = analysis.riskScore;
            const findings = [...analysis.findings];

            if (blockResult.blocked) {
                score = Math.max(score, 80);

                findings.unshift(
                    "LOCAL BLOCKLIST MATCH: " +
                    blockResult.matchedDomain
                );
            }

            score = Math.min(score, 100);

            const severity =
                blockResult.blocked || score >= 60
                    ? "HIGH"
                    : score >= 30
                        ? "MEDIUM"
                        : "LOW";

            const entry = {
                url: analysis.normalizedURL,
                score,
                severity,
                time: new Date().toLocaleString()
            };

            const data = await chrome.storage.local.get("scanHistory");

            const history = Array.isArray(data.scanHistory)
                ? data.scanHistory
                : [];

            history.unshift(entry);

            await chrome.storage.local.set({
                scanHistory: history.slice(0, 20)
            });

            renderScannerResult(entry, findings);

            await loadHistory();

        } catch (error) {
            result.textContent = "Scan failed: " + error.message;

        } finally {
            button.disabled = false;
            button.textContent = "SCAN URL";
        }
    });

    $("urlInput").addEventListener("keydown", event => {
        if (event.key === "Enter") {
            $("scanURLButton").click();
        }
    });

    function renderScannerResult(entry, findings) {
        const result = $("scannerResult");
        result.replaceChildren();

        const box = document.createElement("div");
        box.className = "result-box";

        const title = document.createElement("h3");
        title.textContent = "Security Analysis Result";

        const url = document.createElement("p");
        url.textContent = entry.url;
        url.style.overflowWrap = "anywhere";

        const score = document.createElement("div");
        score.className = "result-score";
        score.textContent = entry.score + " / 100";

        const severity = document.createElement("span");
        severity.className =
            "severity-badge " + severityClass(entry.severity);
        severity.textContent = entry.severity;

        const heading = document.createElement("h4");
        heading.textContent = "Detection Findings";

        const list = document.createElement("ul");
        list.className = "finding-list";

        findings.forEach(finding => {
            const li = document.createElement("li");
            li.textContent = finding;
            list.appendChild(li);
        });

        box.append(title, url, score, severity, heading, list);
        result.appendChild(box);
    }

    // =====================================
    // CLEAR HISTORY
    // =====================================

    $("clearDashboardHistory").addEventListener("click", async () => {
        if (!confirm("Delete all scan history?")) return;

        await chrome.storage.local.set({ scanHistory: [] });

        await loadHistory();
    });

    // =====================================
    // CSV EXPORT
    // =====================================

    $("exportCSV").addEventListener("click", () => {
        if (!scanHistory.length) {
            alert("No scan records available to export.");
            return;
        }

        const columns = [
            "URL",
            "Risk Score",
            "Severity",
            "Timestamp"
        ];

        const rows = scanHistory.map(item => [
            item.url,
            item.score,
            item.severity,
            item.time
        ]);

        const escapeCSV = value =>
            '"' + String(value ?? "").replace(/"/g, '""') + '"';

        const csv = [
            columns,
            ...rows
        ].map(row =>
            row.map(escapeCSV).join(",")
        ).join("\r\n");

        const blob = new Blob(["\uFEFF" + csv], {
            type: "text/csv;charset=utf-8;"
        });

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = url;
        link.download = "SafeBrowse_Scan_Report.csv";

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(url);
    });

    // =====================================
    // REFRESH
    // =====================================

    $("refreshButton").addEventListener("click", loadHistory);

    // =====================================
    // COMPLETE DASHBOARD RENDER
    // =====================================

    function renderDashboard() {
        updateStatistics();
        renderRecentActivity();
        renderAlerts();
        renderHistory();
        renderBlocklist();

        requestAnimationFrame(renderCharts);
    }

    // =====================================
    // LIVE STORAGE UPDATES
    // =====================================

    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "local" && changes.scanHistory) {
            loadHistory();
        }
    });

    // =====================================
    // RESPONSIVE RESIZING
    // =====================================

    let resizeTimeout;

    window.addEventListener("resize", () => {
        clearTimeout(resizeTimeout);

        resizeTimeout = setTimeout(() => {
            renderCharts();
        }, 200);
    });

    // =====================================
    // INITIALIZATION
    // =====================================

    await loadHistory();

    console.log("SafeBrowse Dashboard v1.0.0 initialized.");
});