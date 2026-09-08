import { useEffect, useMemo, useState } from 'react'

const TICKETS_API = 'http://localhost:5001/api/tickets'
const REPORTS_API = 'http://localhost:5001/api/reports'

export default function Reports() {
  const [reports, setReports] = useState([])
  const [selectedReport, setSelectedReport] = useState(null)

  const [searchTerm, setSearchTerm] = useState('')
  const [riskFilter, setRiskFilter] = useState('All')
  const [typeFilter, setTypeFilter] = useState('All')

  const [showGenerator, setShowGenerator] = useState(false)
  const [reportGenerated, setReportGenerated] = useState(false)
  const [generating, setGenerating] = useState(false)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // =========================================
  // FETCH TICKETS + SAVED REPORTS
  // =========================================

  const fetchReports = async () => {
    try {
      setLoading(true)
      setError('')

      const [ticketsResponse, reportsResponse] = await Promise.all([
        fetch(TICKETS_API),
        fetch(REPORTS_API),
      ])

      if (!ticketsResponse.ok) {
        throw new Error('Failed to fetch investigation tickets')
      }

      if (!reportsResponse.ok) {
        throw new Error('Failed to fetch saved reports')
      }

      const ticketsData = await ticketsResponse.json()
      const reportsData = await reportsResponse.json()

      if (!ticketsData.success) {
        throw new Error(
          ticketsData.message || 'Failed to fetch investigation data',
        )
      }

      if (!reportsData.success) {
        throw new Error(
          reportsData.message || 'Failed to fetch saved reports',
        )
      }

      // Reports created from tickets
      const ticketReports = (ticketsData.tickets || []).map(formatReport)

      // Reports permanently saved in MongoDB
      const savedReports = (reportsData.reports || []).map(
        formatSavedReport,
      )

      /*
       * Keep both:
       * 1. Ticket-based investigation reports
       * 2. Permanently generated reports
       *
       * This means the existing investigation reports remain visible,
       * while generated reports survive page refresh.
       */
      const combinedReports = [
        ...savedReports,
        ...ticketReports,
      ]

      setReports(combinedReports)

      if (combinedReports.length > 0) {
        setSelectedReport(combinedReports[0])
      } else {
        setSelectedReport(null)
      }
    } catch (err) {
      console.error(err)

      setError(
        'Unable to connect to the backend. Make sure the backend server is running on port 5001.',
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchReports()
  }, [])

  // =========================================
  // FILTER REPORTS
  // =========================================

  const filteredReports = useMemo(() => {
    const search = searchTerm.toLowerCase().trim()

    return reports.filter((report) => {
      const matchesSearch =
        !search ||
        report.id.toLowerCase().includes(search) ||
        report.title.toLowerCase().includes(search) ||
        report.caseId.toLowerCase().includes(search) ||
        report.classification.toLowerCase().includes(search) ||
        report.sender.toLowerCase().includes(search) ||
        report.sourceIp.toLowerCase().includes(search) ||
        report.domain.toLowerCase().includes(search)

      const matchesRisk =
        riskFilter === 'All' || report.risk === riskFilter

      const matchesType =
        typeFilter === 'All' || report.type === typeFilter

      return matchesSearch && matchesRisk && matchesType
    })
  }, [reports, searchTerm, riskFilter, typeFilter])

  // =========================================
  // STATISTICS
  // =========================================

  const criticalReports = reports.filter(
    (report) => report.risk === 'Critical',
  ).length

  const readyReports = reports.filter(
    (report) => report.status === 'Ready',
  ).length

  const thisWeekReports = reports.filter((report) => {
    if (!report.rawDate) return false

    const now = new Date()
    const sevenDaysAgo = new Date()

    sevenDaysAgo.setDate(now.getDate() - 7)

    return report.rawDate >= sevenDaysAgo
  }).length

  // =========================================
  // GENERATE + SAVE REPORT
  // =========================================

  const handleGenerate = async () => {
    if (reports.length === 0) {
      setShowGenerator(false)
      return
    }

    try {
      setGenerating(true)
      setError('')

      const sourceReport = selectedReport || reports[0]

      const generatedDate = new Date()

      const reportId = `RPT-${generatedDate.getFullYear()}-${Date.now()
        .toString()
        .slice(-6)}`

      const generatedReportPayload = {
        reportId,

        ticketId: sourceReport.caseId,

        title: sourceReport.title,

        type: 'Forensic Report',

        classification: sourceReport.classification,

        risk: sourceReport.risk,

        score: sourceReport.score,

        confidence: sourceReport.confidence,

        sender: sourceReport.sender,

        sourceIp: sourceReport.sourceIp,

        domain: sourceReport.domain,

        indicators: sourceReport.indicators,

        assignedTeam: sourceReport.assignedTeam,

        description: sourceReport.description,

        authentication: {
          spf: sourceReport.authentication?.spf || 'UNKNOWN',
          dkim: sourceReport.authentication?.dkim || 'UNKNOWN',
          dmarc: sourceReport.authentication?.dmarc || 'UNKNOWN',
        },

        status: 'Ready',
      }

      const response = await fetch(REPORTS_API, {
        method: 'POST',

        headers: {
          'Content-Type': 'application/json',
        },

        body: JSON.stringify(generatedReportPayload),
      })

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(
          data.message || 'Failed to generate report',
        )
      }

      const savedReport = formatSavedReport(data.report)

      setReports((currentReports) => [
        savedReport,
        ...currentReports,
      ])

      setSelectedReport(savedReport)

      setShowGenerator(false)

      setReportGenerated(true)

      setTimeout(() => {
        setReportGenerated(false)
      }, 3000)
    } catch (err) {
      console.error(err)

      setError(
        err.message ||
          'Unable to generate the report. Please try again.',
      )
    } finally {
      setGenerating(false)
    }
  }

  // =========================================
  // EXPORT REPORT
  // =========================================

  const handleExport = (report) => {
    const reportContent = `
TRACE MAIL AI
FORENSIC INTELLIGENCE REPORT
========================================

Report ID: ${report.id}
Case ID: ${report.caseId}
Title: ${report.title}

Threat Classification: ${report.classification}
Risk Level: ${report.risk}
Risk Score: ${report.score}/100
AI Confidence: ${report.confidence}%

Sender: ${report.sender}
Source IP: ${report.sourceIp}
Domain: ${report.domain}
Indicators: ${report.indicators}
Assigned Team: ${report.assignedTeam}

Authentication Analysis
----------------------------------------
SPF: ${report.authentication.spf}
DKIM: ${report.authentication.dkim}
DMARC: ${report.authentication.dmarc}

Forensic Findings
----------------------------------------
✓ Email authentication analyzed
✓ Header chain reviewed
✓ Source infrastructure analyzed
✓ Indicators of compromise extracted
✓ Threat classification generated

Investigation Summary
----------------------------------------
${report.description}

Status: ${report.status}
Generated: ${report.date}

========================================
TraceMail AI • Forensic Intelligence Platform
`

    const blob = new Blob([reportContent], {
      type: 'text/plain',
    })

    const url = URL.createObjectURL(blob)

    const link = document.createElement('a')

    link.href = url
    link.download = `${report.id}-forensic-report.txt`

    document.body.appendChild(link)

    link.click()

    document.body.removeChild(link)

    URL.revokeObjectURL(url)
  }

  // =========================================
  // PRINT REPORT
  // =========================================

  const handlePrint = (report) => {
    const printWindow = window.open('', '_blank')

    if (!printWindow) {
      alert('Please allow pop-ups to print the report.')
      return
    }

    printWindow.document.write(`
      <html>
        <head>
          <title>${report.id}</title>

          <style>
            body {
              font-family: Arial, sans-serif;
              padding: 40px;
              color: #111827;
            }

            h1 {
              margin-bottom: 5px;
            }

            h2 {
              margin-top: 30px;
            }

            .meta {
              color: #6b7280;
              margin-bottom: 25px;
            }

            .box {
              border: 1px solid #d1d5db;
              padding: 15px;
              margin: 10px 0;
              border-radius: 8px;
            }

            table {
              width: 100%;
              border-collapse: collapse;
              margin-top: 15px;
            }

            td {
              border: 1px solid #d1d5db;
              padding: 10px;
            }

            .risk {
              font-weight: bold;
            }
          </style>
        </head>

        <body>

          <h1>TraceMail AI</h1>

          <div class="meta">
            Forensic Intelligence Report
          </div>

          <div class="box">
            <strong>Report ID:</strong> ${report.id}<br/>
            <strong>Case ID:</strong> ${report.caseId}<br/>
            <strong>Title:</strong> ${report.title}
          </div>

          <h2>Threat Assessment</h2>

          <table>

            <tr>
              <td>Classification</td>
              <td>${report.classification}</td>
            </tr>

            <tr>
              <td>Risk Level</td>
              <td class="risk">${report.risk}</td>
            </tr>

            <tr>
              <td>Risk Score</td>
              <td>${report.score}/100</td>
            </tr>

            <tr>
              <td>AI Confidence</td>
              <td>${report.confidence}%</td>
            </tr>

          </table>

          <h2>Source Intelligence</h2>

          <table>

            <tr>
              <td>Sender</td>
              <td>${report.sender}</td>
            </tr>

            <tr>
              <td>Source IP</td>
              <td>${report.sourceIp}</td>
            </tr>

            <tr>
              <td>Domain</td>
              <td>${report.domain}</td>
            </tr>

            <tr>
              <td>IOC Count</td>
              <td>${report.indicators}</td>
            </tr>

            <tr>
              <td>Assigned Team</td>
              <td>${report.assignedTeam}</td>
            </tr>

          </table>

          <h2>Authentication Analysis</h2>

          <div class="box">
            SPF: ${report.authentication.spf}<br/>
            DKIM: ${report.authentication.dkim}<br/>
            DMARC: ${report.authentication.dmarc}
          </div>

          <h2>Investigation Summary</h2>

          <div class="box">
            ${report.description}
          </div>

          <h2>Forensic Findings</h2>

          <div class="box">
            ✓ Email authentication analyzed<br/>
            ✓ Header chain reviewed<br/>
            ✓ Source infrastructure analyzed<br/>
            ✓ Indicators of compromise extracted<br/>
            ✓ Threat classification generated
          </div>

          <p>
            Status: ${report.status}<br/>
            Generated: ${report.date}
          </p>

        </body>
      </html>
    `)

    printWindow.document.close()
    printWindow.focus()
    printWindow.print()
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">

      {/* HEADER */}

      <header className="border-b border-slate-800 bg-slate-950/95 px-8 py-6">

        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">

          <div className="flex items-center gap-4">

            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-xl">
              📄
            </div>

            <div>

              <p className="text-xs font-semibold uppercase tracking-[0.25em] text-cyan-400">
                INCIDENT DOCUMENTATION
              </p>

              <h1 className="mt-1 text-2xl font-bold text-slate-100">
                Reports
              </h1>

              <p className="mt-1 text-sm text-slate-500">
                Generate and manage structured forensic intelligence reports.
              </p>

            </div>

          </div>

          <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900 px-4 py-3">

            <span className="relative flex h-2.5 w-2.5">

              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-50" />

              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-400" />

            </span>

            <div>

              <p className="text-xs text-slate-400">
                Report Engine
              </p>

              <p className="text-xs font-semibold text-green-400">
                READY
              </p>

            </div>

          </div>

        </div>

      </header>

      <main className="p-8">

        {/* ERROR */}

        {error && (

          <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/10 px-5 py-4">

            <div className="flex items-center justify-between gap-4">

              <div>

                <p className="text-sm font-semibold text-red-400">
                  Backend Connection Issue
                </p>

                <p className="mt-1 text-xs text-red-300/70">
                  {error}
                </p>

              </div>

              <button
                onClick={fetchReports}
                className="rounded-lg border border-red-500/20 bg-slate-950 px-3 py-2 text-xs font-semibold text-red-400 hover:bg-red-500/10"
              >
                Retry
              </button>

            </div>

          </div>

        )}

        {/* SUCCESS */}

        {reportGenerated && (

          <div className="mb-6 flex items-center gap-3 rounded-xl border border-green-500/20 bg-green-500/10 px-5 py-4">

            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-green-500/10 text-green-400">
              ✓
            </span>

            <div>

              <p className="text-sm font-semibold text-green-400">
                Report generated successfully
              </p>

              <p className="mt-0.5 text-xs text-slate-500">
                The forensic intelligence report has been saved to the backend.
              </p>

            </div>

          </div>

        )}

        {/* STATISTICS */}

        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">

          <StatCard
            label="Total Reports"
            value={reports.length}
            description="Generated reports"
            icon="📄"
            valueClass="text-cyan-400"
          />

          <StatCard
            label="Ready Reports"
            value={readyReports}
            description="Available for review"
            icon="✓"
            valueClass="text-green-400"
          />

          <StatCard
            label="Critical Findings"
            value={criticalReports}
            description="Require attention"
            icon="⚠"
            valueClass="text-red-400"
          />

          <StatCard
            label="This Week"
            value={thisWeekReports}
            description="Reports generated"
            icon="↗"
            valueClass="text-yellow-400"
          />

        </div>

        {/* REPORT GENERATOR */}

        <section className="mt-6 rounded-2xl border border-cyan-500/20 bg-slate-900 p-6">

          <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-center">

            <div>

              <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                REPORT GENERATOR
              </p>

              <h2 className="mt-2 text-xl font-semibold text-slate-100">
                Generate Forensic Intelligence Report
              </h2>

              <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">
                Create a structured investigation report containing threat
                classification, authentication results, indicators,
                source intelligence and forensic findings.
              </p>

            </div>

            <button
              onClick={() => setShowGenerator(true)}
              disabled={reports.length === 0}
              className="shrink-0 rounded-xl bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              + Generate Report
            </button>

          </div>

          <div className="mt-6 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">

            <ReportFeature
              icon="🔍"
              title="Threat Analysis"
              description="Classification & risk"
            />

            <ReportFeature
              icon="🧾"
              title="Header Forensics"
              description="Authentication & hops"
            />

            <ReportFeature
              icon="🌍"
              title="Geo Intelligence"
              description="IP & infrastructure"
            />

            <ReportFeature
              icon="🔗"
              title="IOC Extraction"
              description="Domains, IPs & URLs"
            />

          </div>

        </section>

        {/* FILTERS */}

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-5">

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">

            <div>

              <label className="mb-2 block text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                Search Reports
              </label>

              <div className="relative">

                <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-slate-600">
                  🔍
                </span>

                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search ID, case, title..."
                  className="w-full rounded-xl border border-slate-800 bg-slate-950 py-3 pl-10 pr-4 text-sm text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-500/40"
                />

              </div>

            </div>

            <div>

              <label className="mb-2 block text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                Risk Level
              </label>

              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-300 outline-none focus:border-cyan-500/40"
              >
                <option value="All">All Risk Levels</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>

            </div>

            <div>

              <label className="mb-2 block text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                Report Type
              </label>

              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-300 outline-none focus:border-cyan-500/40"
              >
                <option value="All">All Report Types</option>
                <option value="Forensic Report">Forensic Report</option>
                <option value="Threat Report">Threat Report</option>
                <option value="Incident Report">Incident Report</option>
                <option value="Intelligence Report">
                  Intelligence Report
                </option>
              </select>

            </div>

          </div>

        </section>

        {/* REPORT LIST + DETAILS */}

        <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">

          <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 xl:col-span-2">

            <div className="border-b border-slate-800 p-6">

              <div className="flex items-center justify-between gap-4">

                <div>

                  <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                    REPORT ARCHIVE
                  </p>

                  <h2 className="mt-1 text-lg font-semibold text-slate-100">
                    Investigation Reports
                  </h2>

                  <p className="mt-1 text-xs text-slate-500">
                    Reports synchronized with backend investigations.
                  </p>

                </div>

                <span className="rounded-full border border-slate-800 bg-slate-950 px-3 py-1 text-xs text-slate-500">
                  {filteredReports.length} SHOWN
                </span>

              </div>

            </div>

            {loading ? (

              <div className="p-12 text-center">

                <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

                <p className="mt-4 text-sm text-slate-500">
                  Loading reports from backend...
                </p>

              </div>

            ) : (

              <div className="divide-y divide-slate-800">

                {filteredReports.length > 0 ? (

                  filteredReports.map((report) => (

                    <button
                      key={report.uniqueKey}
                      onClick={() => setSelectedReport(report)}
                      className={`w-full p-5 text-left transition hover:bg-slate-950/60 ${
                        selectedReport?.uniqueKey === report.uniqueKey
                          ? 'bg-cyan-500/5'
                          : ''
                      }`}
                    >

                      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">

                        <div className="min-w-0">

                          <div className="flex flex-wrap items-center gap-2">

                            <span className="text-sm font-semibold text-cyan-400">
                              {report.id}
                            </span>

                            <RiskBadge risk={report.risk} />

                            {report.isSaved && (
                              <span className="rounded-full border border-green-500/20 bg-green-500/10 px-2.5 py-1 text-[10px] font-medium text-green-400">
                                SAVED
                              </span>
                            )}

                          </div>

                          <h3 className="mt-2 text-sm font-semibold text-slate-200">
                            {report.title}
                          </h3>

                          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-500">

                            <span>
                              Case: {report.caseId}
                            </span>

                            <span>•</span>

                            <span>
                              {report.type}
                            </span>

                            <span>•</span>

                            <span>
                              {report.date}
                            </span>

                          </div>

                        </div>

                        <div className="flex items-center gap-5">

                          <div className="text-right">

                            <p className="text-[10px] uppercase tracking-wider text-slate-600">
                              Risk Score
                            </p>

                            <p
                              className={`mt-1 text-lg font-bold ${
                                report.score >= 90
                                  ? 'text-red-400'
                                  : report.score >= 75
                                    ? 'text-yellow-400'
                                    : 'text-green-400'
                              }`}
                            >
                              {report.score}
                            </p>

                          </div>

                          <span className="rounded-lg bg-green-500/10 px-3 py-1.5 text-xs font-medium text-green-400">
                            {report.status}
                          </span>

                        </div>

                      </div>

                    </button>

                  ))

                ) : (

                  <div className="p-12 text-center">

                    <div className="text-3xl">
                      🔎
                    </div>

                    <p className="mt-4 text-sm font-semibold text-slate-300">
                      No reports found
                    </p>

                    <p className="mt-1 text-xs text-slate-600">
                      Try changing your search or filters.
                    </p>

                  </div>

                )}

              </div>

            )}

          </section>

          {/* REPORT DETAILS */}

          <section className="rounded-2xl border border-slate-800 bg-slate-900">

            {selectedReport ? (

              <ReportDetails
                report={selectedReport}
                onExport={handleExport}
                onPrint={handlePrint}
              />

            ) : (

              <div className="flex min-h-[420px] flex-col items-center justify-center p-8 text-center">

                <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-2xl">
                  📋
                </div>

                <h3 className="text-lg font-semibold text-slate-200">
                  Select a Report
                </h3>

                <p className="mt-2 max-w-xs text-sm leading-6 text-slate-500">
                  Select an investigation report from the archive
                  to view its forensic summary.
                </p>

              </div>

            )}

          </section>

        </div>

        {/* REPORT CAPABILITIES */}

        <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-5">

            <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
              REPORT CAPABILITIES
            </p>

            <h2 className="mt-1 text-lg font-semibold text-slate-100">
              Forensic Documentation
            </h2>

          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">

            <Capability
              title="Evidence Preservation"
              description="Maintain structured evidence and investigation metadata."
              icon="🗂️"
            />

            <Capability
              title="Threat Classification"
              description="Document phishing, impersonation, BEC and credential threats."
              icon="⚠️"
            />

            <Capability
              title="Infrastructure Intelligence"
              description="Include source IP, ASN, location and network intelligence."
              icon="🌐"
            />

            <Capability
              title="Incident Response"
              description="Provide actionable findings for security investigation teams."
              icon="🛡️"
            />

          </div>

        </section>

        {/* FOOTER */}

        <div className="mt-8 flex flex-col gap-3 border-t border-slate-800 pt-5 text-xs text-slate-600 md:flex-row md:items-center md:justify-between">

          <p>
            TraceMail AI • Forensic Intelligence Reporting Engine
          </p>

          <p>
            Reports synchronized with backend investigations.
          </p>

        </div>

      </main>

      {/* GENERATE REPORT MODAL */}

      {showGenerator && (

        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-6 backdrop-blur-sm">

          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl">

            <div className="border-b border-slate-800 p-6">

              <div className="flex items-start justify-between">

                <div>

                  <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                    REPORT GENERATOR
                  </p>

                  <h2 className="mt-2 text-xl font-bold text-slate-100">
                    Generate New Report
                  </h2>

                </div>

                <button
                  onClick={() => setShowGenerator(false)}
                  className="text-xl text-slate-500 transition hover:text-slate-200"
                >
                  ×
                </button>

              </div>

            </div>

            <div className="space-y-5 p-6">

              <div className="rounded-xl border border-cyan-500/10 bg-cyan-500/5 p-4">

                <p className="text-sm font-semibold text-slate-200">
                  Automated Forensic Report
                </p>

                <p className="mt-1 text-xs leading-5 text-slate-500">
                  The platform will combine the selected backend
                  investigation data into a structured forensic report
                  and permanently save it to MongoDB.
                </p>

              </div>

              <div className="space-y-3">

                <GeneratorRow
                  icon="✓"
                  label="Threat Classification"
                />

                <GeneratorRow
                  icon="✓"
                  label="Email Authentication"
                />

                <GeneratorRow
                  icon="✓"
                  label="Header Forensics"
                />

                <GeneratorRow
                  icon="✓"
                  label="Geo & Infrastructure Intelligence"
                />

                <GeneratorRow
                  icon="✓"
                  label="IOC Extraction"
                />

              </div>

              {selectedReport && (

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

                  <p className="text-[10px] uppercase tracking-wider text-slate-600">
                    Selected Investigation
                  </p>

                  <p className="mt-2 text-sm font-semibold text-slate-200">
                    {selectedReport.caseId}
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    {selectedReport.title}
                  </p>

                </div>

              )}

              <div className="flex gap-3 pt-2">

                <button
                  onClick={() => setShowGenerator(false)}
                  disabled={generating}
                  className="flex-1 rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm font-semibold text-slate-400 transition hover:text-slate-200 disabled:opacity-50"
                >
                  Cancel
                </button>

                <button
                  onClick={handleGenerate}
                  disabled={reports.length === 0 || generating}
                  className="flex-1 rounded-xl bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {generating ? 'Saving Report...' : 'Generate Report'}
                </button>

              </div>

            </div>

          </div>

        </div>

      )}

    </div>
  )
}

// =========================================
// FORMAT BACKEND TICKET AS REPORT
// =========================================

function formatReport(ticket) {
  const rawDate = ticket.createdAt
    ? new Date(ticket.createdAt)
    : new Date()

  const score = Number(ticket.threatScore) || 0

  const ticketId =
    ticket.ticketId ||
    ticket._id ||
    'UNKNOWN'

  return {
    uniqueKey:
      `${ticket._id || 'local'}-${ticketId}`,

    id:
      `RPT-${new Date(rawDate).getFullYear()}-${String(
        ticketId,
      ).slice(-6)}`,

    title:
      ticket.subject ||
      'Email Threat Investigation',

    caseId:
      ticketId,

    type:
      score >= 85
        ? 'Forensic Report'
        : score >= 70
          ? 'Threat Report'
          : 'Incident Report',

    classification:
      ticket.category ||
      'Suspicious',

    risk:
      getRiskLevel(score),

    score,

    date:
      formatReportDate(rawDate),

    rawDate,

    status:
      'Ready',

    sender:
      ticket.sender ||
      'Unknown Sender',

    sourceIp:
      ticket.sourceIp ||
      'Pending Analysis',

    domain:
      ticket.domain ||
      'Pending Extraction',

    indicators:
      Array.isArray(ticket.indicators)
        ? ticket.indicators.length
        : 0,

    confidence:
      Number(ticket.aiConfidence) || 0,

    assignedTeam:
      ticket.assignedTeam ||
      'Threat Intelligence',

    description:
      ticket.emailBody ||
      ticket.recommendedSolution ||
      'No investigation summary available.',

    authentication: {
      spf:
        ticket.authentication?.spf ||
        'UNKNOWN',

      dkim:
        ticket.authentication?.dkim ||
        'UNKNOWN',

      dmarc:
        ticket.authentication?.dmarc ||
        'UNKNOWN',
    },

    isSaved: false,
  }
}

// =========================================
// FORMAT SAVED MONGODB REPORT
// =========================================

function formatSavedReport(report) {
  const rawDate = report.createdAt
    ? new Date(report.createdAt)
    : new Date()

  const score = Number(report.score) || 0

  return {
    uniqueKey:
      `saved-${report._id || report.reportId}`,

    id:
      report.reportId ||
      `RPT-${rawDate.getFullYear()}-${String(
        report._id || Date.now(),
      ).slice(-6)}`,

    title:
      report.title ||
      'Forensic Intelligence Report',

    caseId:
      report.ticketId ||
      'UNKNOWN',

    type:
      report.type ||
      'Forensic Report',

    classification:
      report.classification ||
      'Suspicious',

    risk:
      report.risk ||
      getRiskLevel(score),

    score,

    date:
      formatReportDate(rawDate),

    rawDate,

    status:
      report.status ||
      'Ready',

    sender:
      report.sender ||
      'Unknown Sender',

    sourceIp:
      report.sourceIp ||
      'Pending Analysis',

    domain:
      report.domain ||
      'Pending Extraction',

    indicators:
      Number(report.indicators) || 0,

    confidence:
      Number(report.confidence) || 0,

    assignedTeam:
      report.assignedTeam ||
      'Threat Intelligence',

    description:
      report.description ||
      'No investigation summary available.',

    authentication: {
      spf:
        report.authentication?.spf ||
        'UNKNOWN',

      dkim:
        report.authentication?.dkim ||
        'UNKNOWN',

      dmarc:
        report.authentication?.dmarc ||
        'UNKNOWN',
    },

    isSaved: true,

    mongoId:
      report._id || null,
  }
}

// =========================================
// RISK LEVEL
// =========================================

function getRiskLevel(score) {
  if (score >= 85) return 'Critical'
  if (score >= 70) return 'High'
  if (score >= 50) return 'Medium'
  return 'Low'
}

// =========================================
// DATE FORMAT
// =========================================

function formatReportDate(date) {
  if (!date || Number.isNaN(date.getTime())) {
    return 'Unknown'
  }

  return date.toLocaleDateString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  })
}

// =========================================
// STAT CARD
// =========================================

function StatCard({
  label,
  value,
  description,
  icon,
  valueClass,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 transition hover:border-slate-700">

      <div className="flex items-start justify-between">

        <p className="text-xs font-medium uppercase tracking-wider text-slate-600">
          {label}
        </p>

        <span className="rounded-lg bg-slate-950 px-2.5 py-1.5 text-xs text-slate-400">
          {icon}
        </span>

      </div>

      <p className={`mt-3 text-3xl font-bold ${valueClass}`}>
        {value}
      </p>

      <p className="mt-2 text-xs text-slate-600">
        {description}
      </p>

    </div>
  )
}

// =========================================
// REPORT FEATURE
// =========================================

function ReportFeature({
  icon,
  title,
  description,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

      <div className="flex items-center gap-3">

        <span className="text-lg">
          {icon}
        </span>

        <div>

          <p className="text-sm font-medium text-slate-300">
            {title}
          </p>

          <p className="mt-0.5 text-xs text-slate-600">
            {description}
          </p>

        </div>

      </div>

    </div>
  )
}

// =========================================
// RISK BADGE
// =========================================

function RiskBadge({ risk }) {
  const classes = {
    Critical:
      'bg-red-500/10 text-red-400 border-red-500/20',

    High:
      'bg-orange-500/10 text-orange-400 border-orange-500/20',

    Medium:
      'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',

    Low:
      'bg-green-500/10 text-green-400 border-green-500/20',
  }

  return (
    <span
      className={`rounded-full border px-2.5 py-1 text-[10px] font-medium ${
        classes[risk] || classes.Medium
      }`}
    >
      {risk}
    </span>
  )
}

// =========================================
// REPORT DETAILS
// =========================================

function ReportDetails({
  report,
  onExport,
  onPrint,
}) {
  return (
    <div>

      <div className="border-b border-slate-800 p-6">

        <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
          REPORT DETAILS
        </p>

        <div className="mt-3 flex items-start justify-between gap-4">

          <div>

            <h3 className="text-lg font-bold text-slate-100">
              {report.id}
            </h3>

            <p className="mt-1 text-sm text-slate-400">
              {report.title}
            </p>

          </div>

          <div
            className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border text-lg font-bold ${
              report.score >= 90
                ? 'border-red-500/20 bg-red-500/10 text-red-400'
                : report.score >= 75
                  ? 'border-yellow-500/20 bg-yellow-500/10 text-yellow-400'
                  : 'border-green-500/20 bg-green-500/10 text-green-400'
            }`}
          >
            {report.score}
          </div>

        </div>

      </div>

      <div className="space-y-6 p-6">

        {/* Classification */}

        <div>

          <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
            Threat Classification
          </p>

          <div className="mt-3 flex items-center justify-between gap-3">

            <span className="rounded-full bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400">
              {report.classification}
            </span>

            <span className="text-xs text-slate-600">
              {report.confidence}% confidence
            </span>

          </div>

        </div>

        {/* Case */}

        <div className="grid grid-cols-2 gap-3">

          <DetailBox
            label="Case ID"
            value={report.caseId}
          />

          <DetailBox
            label="Status"
            value={report.status}
            valueClass="text-green-400"
          />

        </div>

        {/* Source Intelligence */}

        <div>

          <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
            Source Intelligence
          </p>

          <div className="mt-3 space-y-3">

            <InfoRow
              label="Sender"
              value={report.sender}
            />

            <InfoRow
              label="Source IP"
              value={report.sourceIp}
            />

            <InfoRow
              label="Domain"
              value={report.domain}
            />

            <InfoRow
              label="IOC Count"
              value={`${report.indicators} indicators`}
            />

            <InfoRow
              label="Assigned Team"
              value={report.assignedTeam}
            />

          </div>

        </div>

        {/* Authentication */}

        <div>

          <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
            Authentication
          </p>

          <div className="mt-3 grid grid-cols-3 gap-2">

            <AuthBox
              label="SPF"
              value={report.authentication.spf}
            />

            <AuthBox
              label="DKIM"
              value={report.authentication.dkim}
            />

            <AuthBox
              label="DMARC"
              value={report.authentication.dmarc}
            />

          </div>

        </div>

        {/* Risk Score */}

        <div>

          <div className="flex items-center justify-between">

            <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
              Threat Risk Score
            </p>

            <span className="text-xs font-semibold text-slate-400">
              {report.score}/100
            </span>

          </div>

          <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">

            <div
              className={`h-full rounded-full ${
                report.score >= 90
                  ? 'bg-red-500'
                  : report.score >= 75
                    ? 'bg-yellow-500'
                    : 'bg-green-500'
              }`}
              style={{
                width: `${report.score}%`,
              }}
            />

          </div>

        </div>

        {/* Summary */}

        <div>

          <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
            Investigation Summary
          </p>

          <p className="mt-3 text-sm leading-6 text-slate-400">
            {report.description}
          </p>

        </div>

        {/* Findings */}

        <div>

          <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
            Included Findings
          </p>

          <div className="mt-3 space-y-3">

            <Finding
              label="Email Authentication"
              value="Included"
            />

            <Finding
              label="Header Analysis"
              value="Included"
            />

            <Finding
              label="Source Intelligence"
              value="Included"
            />

            <Finding
              label="IOC Extraction"
              value="Included"
            />

          </div>

        </div>

        {/* Actions */}

        <div className="grid grid-cols-2 gap-3">

          <button
            onClick={() => onExport(report)}
            className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm font-semibold text-cyan-400 transition hover:bg-cyan-500/20"
          >
            ↓ Export
          </button>

          <button
            onClick={() => onPrint(report)}
            className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm font-semibold text-slate-300 transition hover:border-slate-600 hover:text-white"
          >
            🖨 Print
          </button>

        </div>

      </div>

    </div>
  )
}

// =========================================
// DETAIL BOX
// =========================================

function DetailBox({
  label,
  value,
  valueClass = 'text-slate-300',
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className={`mt-2 text-sm font-medium ${valueClass}`}>
        {value}
      </p>

    </div>
  )
}

// =========================================
// INFO ROW
// =========================================

function InfoRow({
  label,
  value,
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">

      <span className="text-xs text-slate-500">
        {label}
      </span>

      <span className="max-w-[65%] break-all text-right text-xs font-medium text-slate-300">
        {value}
      </span>

    </div>
  )
}

// =========================================
// AUTH BOX
// =========================================

function AuthBox({
  label,
  value,
}) {
  const normalized = String(value).toUpperCase()

  const isFail = normalized === 'FAIL'
  const isPass = normalized === 'PASS'

  return (
    <div
      className={`rounded-lg border p-3 ${
        isFail
          ? 'border-red-500/20 bg-red-500/5'
          : isPass
            ? 'border-green-500/20 bg-green-500/5'
            : 'border-slate-800 bg-slate-950/60'
      }`}
    >

      <p className="text-[9px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p
        className={`mt-1 text-xs font-semibold ${
          isFail
            ? 'text-red-400'
            : isPass
              ? 'text-green-400'
              : 'text-slate-400'
        }`}
      >
        {value}
      </p>

    </div>
  )
}

// =========================================
// FINDING
// =========================================

function Finding({
  label,
  value,
}) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 pb-3">

      <span className="text-sm text-slate-400">
        {label}
      </span>

      <span className="text-xs font-medium text-green-400">
        ✓ {value}
      </span>

    </div>
  )
}

// =========================================
// GENERATOR ROW
// =========================================

function GeneratorRow({
  icon,
  label,
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/50 px-4 py-3">

      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-green-500/10 text-xs text-green-400">
        {icon}
      </span>

      <span className="text-sm text-slate-300">
        {label}
      </span>

    </div>
  )
}

// =========================================
// CAPABILITY
// =========================================

function Capability({
  title,
  description,
  icon,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-5">

      <div className="mb-3 text-xl">
        {icon}
      </div>

      <h3 className="text-sm font-semibold text-slate-200">
        {title}
      </h3>

      <p className="mt-2 text-xs leading-5 text-slate-500">
        {description}
      </p>

    </div>
  )
}