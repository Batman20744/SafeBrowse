import { useEffect, useState } from 'react'
import {
  ShieldCheck, ShieldAlert, Search, Globe, Activity,
  LayoutDashboard, History, Settings, LockKeyhole,
  ArrowUpRight, ScanLine, AlertTriangle, CheckCircle2,
  Clock3, X, Fingerprint, Radar, Trash2, Download
} from 'lucide-react'
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts'

import { analyzeURL } from './lib/url-analyzer'
import './App.css'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)

  const [history, setHistory] = useState(() => {
    try {
      const savedHistory = localStorage.getItem('safebrowse_scan_history')
      const parsed = savedHistory ? JSON.parse(savedHistory) : []
      return Array.isArray(parsed) ? parsed.slice(0, 20) : []
    } catch {
      return []
    }
  })

  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('scanner')
  const [selectedHistoryId, setSelectedHistoryId] = useState(null)

  // Persist scan history
  useEffect(() => {
    try {
      localStorage.setItem(
        'safebrowse_scan_history',
        JSON.stringify(history)
      )
    } catch (error) {
      console.error('Unable to save scan history:', error)
    }
  }, [history])

  // Analyze URL
  const scanURL = (value = url) => {
    const target = value.trim()

   if (!target) {
  setError('Please enter a website URL to scan.')
  setResult(null)
  return
}

    setError('')

    const analysis = analyzeURL(target)

    const scan = {
      ...analysis,
      id: Date.now(),
      scannedAt: new Date().toLocaleTimeString()
    }

    setResult(scan)

setHistory(previous => {
  const filteredHistory = previous.filter(
    item => item.normalizedURL !== scan.normalizedURL
  )

  return [scan, ...filteredHistory].slice(0, 20)
})

setUrl(target)
  }

  // Download detailed CSV report
  const downloadReport = (scan) => {
    if (!scan) return

    const rows = [
      ['Field', 'Value'],
      ['URL', scan.originalURL || 'N/A'],
      ['Hostname', scan.hostname || 'N/A'],
      ['Risk Score', scan.riskScore],
      ['Severity', scan.severity],
      ['Scanned At', scan.scannedAt || 'N/A'],
      ['Valid URL', scan.valid ? 'Yes' : 'No'],
      ['Indicator Codes', (scan.indicators || []).join('; ')],
      ['Findings', (scan.findings || []).join('; ')]
    ]

    const escapeCSV = (value) => {
      const text = String(value ?? '')

      const safe = /^[\s]*[=+\-@\t\r\n]/.test(text)
        ? "'" + text
        : text

      return `"${safe.replace(/"/g, '""')}"`
    }

    const csv = rows
      .map(row => row.map(escapeCSV).join(','))
      .join('\r\n')

    const blob = new Blob(
      [csv],
      { type: 'text/csv;charset=utf-8' }
    )

    const downloadURL = URL.createObjectURL(blob)
    const link = document.createElement('a')

    link.href = downloadURL
    link.download = `SafeBrowse_Report_${scan.id}.csv`

    document.body.appendChild(link)
    link.click()
    link.remove()

    window.setTimeout(() => {
      URL.revokeObjectURL(downloadURL)
    }, 1000)
  }

  // Clear scan history
  const clearHistory = () => {
    setHistory([])
    setResult(null)
    setSelectedHistoryId(null)
  }

  // Severity colors
  const severityColor = severity => {
    if (severity === 'HIGH' || severity === 'INVALID') {
      return 'danger'
    }

    if (severity === 'MEDIUM') {
      return 'warning'
    }

    return 'safe'
  }

  const selectedHistoryScan = history.find(
    item => item.id === selectedHistoryId
  )

  // Dashboard statistics
  const totalScans = history.length

  const highRisk = history.filter(
    item => item.severity === 'HIGH' || item.severity === 'INVALID'
  ).length

  const safeScans = history.filter(
    item => item.severity === 'LOW'
  ).length

  // Analytics derived from the saved scan history
  const mediumRisk = history.filter(
    item => item.severity === 'MEDIUM'
  ).length

  const riskDistribution = [
    { name: 'Low Risk', value: safeScans, color: '#22c58b' },
    { name: 'Medium Risk', value: mediumRisk, color: '#f4b740' },
    { name: 'High Risk', value: highRisk, color: '#ff647c' }
  ]

  const recentChartData = [...history]
    .slice(0, 7)
    .reverse()
    .map((item, index) => ({
      name: item.hostname
        ? item.hostname.length > 15
          ? `${item.hostname.slice(0, 15)}…`
          : item.hostname
        : `Scan ${index + 1}`,
      score: Number(item.riskScore) || 0
    }))

  const indicatorCounts = history
    .flatMap(item => item.indicators || [])
    .reduce((counts, indicator) => {
      counts[indicator] = (counts[indicator] || 0) + 1
      return counts
    }, {})

  const topIndicators = Object.entries(indicatorCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  return (
    <div className="app-shell">

      {/* Sidebar */}
      <aside className="sidebar">

        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>
            <h2>Safe<span>Browse</span></h2>
            <small>THREAT INTELLIGENCE</small>
          </div>
        </div>

        <div className="side-label">WORKSPACE</div>

        <nav className="side-nav">

          <button
            className={activeTab === 'scanner' ? 'nav-item active' : 'nav-item'}
            onClick={() => setActiveTab('scanner')}
          >
            <LayoutDashboard size={18} />
            Overview
          </button>

          <button
            className={activeTab === 'history' ? 'nav-item active' : 'nav-item'}
            onClick={() => setActiveTab('history')}
          >
            <History size={18} />
            Scan History
          </button>

        </nav>

        <div className="sidebar-bottom">

          <div className="sidebar-security">
            <div className="security-icon">
              <LockKeyhole size={18} />
            </div>

            <strong>Browser Security</strong>

            <p>
              Protect yourself from suspicious websites.
            </p>

            <span>
              <span className="online-dot" />
              Detection engine ready
            </span>
          </div>

          <div className="sidebar-footer">
            <Settings size={16} />
            SafeBrowse v1.0
          </div>

        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">

        <header className="topbar">

          <div className="breadcrumb">
            Security Center
            <span>/</span>
            {activeTab === 'scanner' ? 'Overview' : 'Scan History'}
          </div>

          <div className="topbar-right">

            <span className="system-status">
              <span className="online-dot" />
              SYSTEM OPERATIONAL
            </span>

            <div className="user-avatar">SB</div>

          </div>
        </header>

        <div className="page-content">

          {/* Welcome Section */}
          <section className="welcome-section">

            <div>
              <div className="eyebrow">
                <Radar size={14} />
                WEB THREAT ANALYSIS
              </div>

              <h1>
                Security <span>Dashboard</span>
              </h1>

              <p>
                Analyze suspicious URLs and identify potential phishing indicators.
              </p>
            </div>

            <div className="date-label">
              <Activity size={16} />
              Real-time local analysis
            </div>

          </section>

          {/* Statistics */}
          <section className="stats-grid">

            <div className="stat-card">
              <div className="stat-top">
                <span>Total Scans</span>
                <div className="stat-icon purple">
                  <ScanLine size={19} />
                </div>
              </div>

              <strong>{totalScans}</strong>
              <small>URLs analyzed this session</small>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span>High Risk</span>
                <div className="stat-icon red">
                  <ShieldAlert size={19} />
                </div>
              </div>

              <strong>{highRisk}</strong>
              <small>High risk or invalid URLs</small>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span>Low Risk</span>
                <div className="stat-icon green">
                  <ShieldCheck size={19} />
                </div>
              </div>

              <strong>{safeScans}</strong>
              <small>Low indicator score</small>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span>Detection Engine</span>
                <div className="stat-icon blue">
                  <Fingerprint size={19} />
                </div>
              </div>

              <strong className="engine-value">ACTIVE</strong>
              <small>Heuristic analysis enabled</small>
            </div>

          </section>

          {/* Scanner */}
          {activeTab === 'scanner' ? (
            <>

              {/* Scan Analytics */}
              <section className="analytics-section">
                <div className="analytics-heading">
                  <div>
                    <div className="eyebrow">
                      <Activity size={14} />
                      SECURITY INSIGHTS
                    </div>
                    <h2>Scan Analytics</h2>
                    <p>Risk distribution and detection trends from your saved scans.</p>
                  </div>
                  <span className="analytics-count">
                    {totalScans} {totalScans === 1 ? 'scan' : 'scans'} recorded
                  </span>
                </div>

                {totalScans === 0 ? (
                  <div className="analytics-empty">
                    <Radar size={22} />
                    <div>
                      <strong>No analytics yet</strong>
                      <p>Scan a few URLs to see your risk distribution and detection trends.</p>
                    </div>
                  </div>
                ) : (
                  <div className="analytics-grid">
                    <div className="panel-card analytics-card">
                      <div className="panel-title">
                        <div>
                          <ShieldAlert size={18} />
                          <h3>Risk Distribution</h3>
                        </div>
                      </div>

                      <div className="risk-chart-wrap">
                        <div className="risk-donut">
                          <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                              <Pie
                                data={riskDistribution}
                                dataKey="value"
                                nameKey="name"
                                cx="50%"
                                cy="50%"
                                innerRadius="68%"
                                outerRadius="92%"
                                paddingAngle={3}
                                stroke="none"
                              >
                                {riskDistribution.map((entry) => (
                                  <Cell key={entry.name} fill={entry.color} />
                                ))}
                              </Pie>
                              <Tooltip
                                contentStyle={{
                                  background: '#171426',
                                  border: '1px solid #39324f',
                                  borderRadius: '10px',
                                  color: '#fff'
                                }}
                              />
                            </PieChart>
                          </ResponsiveContainer>
                          <div className="risk-chart-center">
                            <strong>{totalScans}</strong>
                            <span>Total scans</span>
                          </div>
                        </div>

                        <div className="risk-legend">
                          {riskDistribution.map(item => (
                            <div className="risk-legend-row" key={item.name}>
                              <span className="risk-legend-label">
                                <i style={{ background: item.color }} />
                                {item.name}
                              </span>
                              <strong>{item.value}</strong>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="panel-card analytics-card">
                      <div className="panel-title">
                        <div>
                          <Activity size={18} />
                          <h3>Recent Risk Scores</h3>
                        </div>
                      </div>

                      <div className="risk-bar-chart">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            data={recentChartData}
                            margin={{ top: 8, right: 8, left: -20, bottom: 8 }}
                          >
                            <CartesianGrid stroke="#302a43" strokeDasharray="3 3" />
                            <XAxis
                              dataKey="name"
                              tick={{ fill: '#a7a1b8', fontSize: 11 }}
                              axisLine={{ stroke: '#39324f' }}
                              tickLine={false}
                            />
                            <YAxis
                              domain={[0, 100]}
                              tick={{ fill: '#a7a1b8', fontSize: 11 }}
                              axisLine={false}
                              tickLine={false}
                            />
                            <Tooltip
  cursor={false}
  formatter={(value) => [`${value}/100`, 'Risk score']}
  contentStyle={{
    background: '#171426',
    border: '1px solid #39324f',
    borderRadius: '10px',
    color: '#fff'
  }}
/>
                            <Bar
                              dataKey="score"
                              name="Risk Score"
                              fill="#9b75ff"
                              radius={[6, 6, 0, 0]}
                              maxBarSize={42}
                            />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                      <p className="chart-footnote">Latest {recentChartData.length} scans · score out of 100</p>
                    </div>

                    <div className="panel-card analytics-card indicators-card">
                      <div className="panel-title">
                        <div>
                          <Fingerprint size={18} />
                          <h3>Top Detection Indicators</h3>
                        </div>
                      </div>

                      {topIndicators.length === 0 ? (
                        <div className="analytics-no-indicators">
                          No detection indicators have been recorded yet.
                        </div>
                      ) : (
                        <div className="indicator-list">
                          {topIndicators.map((item, index) => (
                            <div className="indicator-row" key={item.name}>
                              <span className="indicator-rank">{index + 1}</span>
                              <span className="indicator-name">{item.name}</span>
                              <strong>{item.count}</strong>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </section>

              <section className="scanner-card">

                <div className="section-heading">

                  <div className="heading-icon">
                    <Search size={19} />
                  </div>

                  <div>
                    <h3>Website Security Scanner</h3>

                    <p>
                      Enter a URL to check for suspicious patterns and phishing indicators.
                    </p>
                  </div>

                </div>

                <form
                  className="scanner-form"
                  onSubmit={event => {
                    event.preventDefault()
                    scanURL()
                  }}
                >

                  <div className="url-input-wrap">

                    <Globe size={19} />

                    <input
                      type="text"
                      value={url}
                      onChange={event => setUrl(event.target.value)}
                      placeholder="https://example.com"
                      aria-label="Website URL to scan"
                    />

                    {url && (
                      <button
                        type="button"
                        className="clear-input"
                        onClick={() => setUrl('')}
                      >
                        ×
                      </button>
                    )}

                  </div>

                  <button type="submit" className="scan-button">
                    <ScanLine size={18} />
                    Analyze URL
                  </button>

                </form>

                {error && (
                  <p className="input-error">{error}</p>
                )}

                <div className="scanner-hint">
                  <LockKeyhole size={14} />
                  Analysis runs locally in your browser. URLs are not sent to our server.
                </div>

                <div className="quick-examples">

                  <span>TRY AN EXAMPLE:</span>

                  <button
                    type="button"
                    onClick={() => {
                      setUrl('https://google.com')
                      scanURL('https://google.com')
                    }}
                  >
                    Google
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setUrl('http://192.168.1.1/login/verify')
                      scanURL('http://192.168.1.1/login/verify')
                    }}
                  >
                    Suspicious pattern
                  </button>

                </div>

              </section>

              {/* Scan Result */}
              {result && (
                <section className="result-card">

                  <div className="result-header">

                    <div>
                      <div className="eyebrow">SCAN RESULT</div>
                      <h3>Analysis Report</h3>
                    </div>

                    <div className="result-actions">

                      <span className={`severity-badge ${severityColor(result.severity)}`}>

                        {result.severity === 'LOW'
                          ? <CheckCircle2 size={15} />
                          : <AlertTriangle size={15} />
                        }

                        {result.severity === 'INVALID'
                          ? 'INVALID URL'
                          : `${result.severity} RISK`
                        }

                      </span>

                      <button
                        type="button"
                        className="report-download"
                        onClick={() => downloadReport(result)}
                      >
                        <Download size={16} />
                        Export CSV
                      </button>

                      <button
                        type="button"
                        className="close-report"
                        onClick={() => setResult(null)}
                        aria-label="Close scan report"
                        title="Close report"
                      >
                        <X size={17} />
                      </button>

                    </div>

                  </div>

                  <div className="result-summary">

                    <div className={`score-circle ${severityColor(result.severity)}`}>
                      <strong>{result.riskScore}</strong>
                      <span>/ 100</span>
                    </div>

                    <div className="result-description">

                      <h4>
                        {result.hostname || 'Invalid hostname'}
                      </h4>

                      <p className="scanned-url">
                        {result.originalURL || url}
                      </p>

                      <p>
  {result.findings.length === 0
    ? 'No configured suspicious indicators were detected.'
    : result.severity === 'LOW'
      ? 'Minor suspicious indicators detected. Exercise caution.'
      : result.severity === 'MEDIUM'
        ? 'Some suspicious indicators were detected. Exercise caution.'
        : 'Significant risk indicators detected. Avoid interacting with this URL.'}
</p>

                    </div>

                  </div>

                  <div className="findings-heading">
                    <h4>Detection Findings</h4>
                    <span>{result.indicators.length} indicator(s)</span>
                  </div>

                  <div className="findings-list">

                    {result.findings.map((finding, index) => (
                      <div
                        className="finding-row"
                        key={`${finding}-${index}`}
                      >
                        <AlertTriangle size={16} />
                        <span>{finding}</span>
                      </div>
                    ))}

                  </div>

                  <div className="result-disclaimer">
                    <AlertTriangle size={15} />
                    This is heuristic analysis, not a definitive malware or phishing verdict. A low score does not guarantee a website is safe.
                  </div>

                </section>
              )}

              {/* Bottom Dashboard Panels */}
              <section className="bottom-grid">

                <div className="panel-card">

                  <div className="panel-title">
                    <div>
                      <Activity size={18} />
                      <h3>Detection Capabilities</h3>
                    </div>
                  </div>

                  {[
                    'Suspicious hostname keywords',
                    'IP address hostnames',
                    'Embedded URL credentials',
                    'Punycode and encoded URLs',
                    'Excessive subdomains',
                    'Insecure HTTP connections'
                  ].map(item => (
                    <div className="capability-row" key={item}>
                      <CheckCircle2 size={16} />
                      {item}
                    </div>
                  ))}

                </div>

                <div className="panel-card">

                  <div className="panel-title">

                    <div>
                      <Clock3 size={18} />
                      <h3>Recent Scans</h3>
                    </div>

                    <button
                      type="button"
                      className="text-link"
                      onClick={() => setActiveTab('history')}
                    >
                      View all
                      <ArrowUpRight size={14} />
                    </button>

                  </div>

                  {history.length === 0 ? (
                    <div className="empty-state">
                      Your recent scans will appear here.
                    </div>
                  ) : (
                    history.slice(0, 4).map(item => (
                      <button
                        type="button"
                        className="recent-row"
                        key={item.id}
                        onClick={() => setResult(item)}
                      >
                        <Globe size={16} />

                        <span>
                          {item.hostname || 'Invalid URL'}
                        </span>

                        <span className={`mini-badge ${severityColor(item.severity)}`}>
                          {item.riskScore}
                        </span>
                      </button>
                    ))
                  )}

                </div>

              </section>

            </>
          ) : (

            /* Scan History */
            <section className="panel-card history-panel">

              <div className="panel-title">

                <div>
                  <History size={18} />
                  <h3>Scan History</h3>
                </div>

                <button
                  type="button"
                  className="text-link"
                  onClick={clearHistory}
                >
                  <Trash2 size={15} />
                  Clear history
                </button>

              </div>

              {history.length === 0 ? (

                <div className="empty-state">
                  No scans yet. Visit Overview to analyze a URL.
                </div>

              ) : (

                <div className="history-table">

                  <div className="history-table-head">
                    <span>WEBSITE</span>
                    <span>RISK SCORE</span>
                    <span>SEVERITY</span>
                    <span>TIME</span>
                  </div>

                  {history.map(item => (

                    <button
                      type="button"
                      className="history-table-row"
                      key={item.id}
                      onClick={() => {
                        setSelectedHistoryId(previous =>
                          previous === item.id ? null : item.id
                        )
                      }}
                    >

                      <span className="history-domain">
                        <Globe size={16} />
                        {item.hostname || 'Invalid URL'}
                      </span>

                      <span>{item.riskScore}/100</span>

                      <span>
                        <span className={`mini-badge ${severityColor(item.severity)}`}>
                          {item.severity}
                        </span>
                      </span>

                      <span>
                        {item.scannedAt}
                        <Search size={15} />
                      </span>

                    </button>

                  ))}

                </div>

              )}

              {/* Selected scan report below history */}
              {selectedHistoryScan && (
                <div className="history-selected-report">

                  <div className="result-header">

                    <div>
                      <div className="eyebrow">SCAN DETAILS</div>
                      <h3>Selected Scan Report</h3>
                    </div>

                    <div className="result-actions">

                      <span className={`severity-badge ${severityColor(selectedHistoryScan.severity)}`}>
                        {selectedHistoryScan.severity === 'LOW'
                          ? <CheckCircle2 size={15} />
                          : <AlertTriangle size={15} />
                        }

                        {selectedHistoryScan.severity === 'INVALID'
                          ? 'INVALID URL'
                          : `${selectedHistoryScan.severity} RISK`
                        }
                      </span>

                      <button
                        type="button"
                        className="report-download"
                        onClick={() => downloadReport(selectedHistoryScan)}
                      >
                        <Download size={16} />
                        Export CSV
                      </button>

                      <button
                        type="button"
                        className="close-report"
                        onClick={() => setSelectedHistoryId(null)}
                        aria-label="Close selected scan report"
                        title="Close report"
                      >
                        <X size={17} />
                      </button>

                    </div>

                  </div>

                  <div className="result-summary">

                    <div className={`score-circle ${severityColor(selectedHistoryScan.severity)}`}>
                      <strong>{selectedHistoryScan.riskScore}</strong>
                      <span>/ 100</span>
                    </div>

                    <div className="result-description">

                      <h4>
                        {selectedHistoryScan.hostname || 'Invalid hostname'}
                      </h4>

                      <p className="scanned-url">
                        {selectedHistoryScan.originalURL || 'N/A'}
                      </p>

                      <p>
                        Scanned at {selectedHistoryScan.scannedAt || 'Unknown time'}
                        {' · '}
                        {(selectedHistoryScan.indicators || []).length} indicator(s)
                      </p>

                    </div>

                  </div>

                  <div className="findings-heading">
                    <h4>Detection Findings</h4>
                    <span>
                      {(selectedHistoryScan.findings || []).length} finding(s)
                    </span>
                  </div>

                  <div className="findings-list">

                    {(selectedHistoryScan.findings || []).map((finding, index) => (
                      <div
                        className="finding-row"
                        key={`${finding}-${index}`}
                      >
                        <AlertTriangle size={16} />
                        <span>{finding}</span>
                      </div>
                    ))}

                  </div>

                  <div className="result-disclaimer">
                    <AlertTriangle size={15} />
                    Heuristic analysis is not a definitive phishing verdict. A low score does not guarantee safety.
                  </div>

                </div>
              )}

            </section>

          )}

          {/* Footer */}
          <footer className="page-footer">

            <span>© 2026 SafeBrowse Security</span>

            <span>
              <ShieldCheck size={14} />
              Client-side heuristic URL analysis
            </span>

          </footer>

        </div>
      </main>
    </div>
  )
}

export default App