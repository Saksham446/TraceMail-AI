import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const API_URL = 'http://localhost:5001/api/tickets'

const filterOptions = ['All', 'Critical', 'High', 'Medium', 'Low']

function getStoredUser() {
  try {
    return JSON.parse(
      localStorage.getItem('tracemail_user') || 'null',
    )
  } catch {
    return null
  }
}

function getAuthHeaders(includeJson = false) {
  const token = localStorage.getItem('tracemail_auth_token')

  return {
    ...(includeJson ? { 'Content-Type': 'application/json' } : {}),
    ...(token
      ? {
          Authorization: `Bearer ${token}`,
        }
      : {}),
  }
}

export default function Cases() {
  const navigate = useNavigate()
  const currentUser = getStoredUser()

  const canManageCases =
    currentUser?.role === 'Admin' ||
    currentUser?.role === 'Analyst'

  const canGenerateReports =
    currentUser?.role === 'Admin' ||
    currentUser?.role === 'Analyst'

  const [caseList, setCaseList] = useState([])
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const [selectedCase, setSelectedCase] = useState(null)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [showNewCase, setShowNewCase] = useState(false)
  const [creatingCase, setCreatingCase] = useState(false)

  const [newCase, setNewCase] = useState({
    title: '',
    sender: '',
    classification: 'Phishing',
    priority: 'Medium',
    sourceIp: '',
    domain: '',
    assignedTo: 'SOC Team',
    description: '',
  })

  // =========================================
  // FETCH CASES FROM BACKEND
  // =========================================

  const fetchCases = async () => {
    try {
      setLoading(true)
      setError('')

      const response = await fetch(API_URL, {
        headers: getAuthHeaders(),
      })

      if (!response.ok) {
        throw new Error('Failed to fetch cases')
      }

      const data = await response.json()

      if (!data.success) {
        throw new Error(data.message || 'Failed to fetch cases')
      }

      const formattedCases = (data.tickets || []).map(formatTicket)

      setCaseList(formattedCases)

      if (formattedCases.length > 0) {
        setSelectedCase(formattedCases[0])
      } else {
        setSelectedCase(null)
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
    fetchCases()
  }, [])

  // =========================================
  // FILTER CASES
  // =========================================

  const filteredCases = useMemo(() => {
    return caseList.filter((item) => {
      const searchText = search.toLowerCase().trim()

      const matchesSearch =
        !searchText ||
        item.id.toLowerCase().includes(searchText) ||
        item.title.toLowerCase().includes(searchText) ||
        item.sender.toLowerCase().includes(searchText) ||
        item.classification.toLowerCase().includes(searchText) ||
        item.domain.toLowerCase().includes(searchText) ||
        item.sourceIp.toLowerCase().includes(searchText)

      const matchesRisk =
        riskFilter === 'All' || item.priority === riskFilter

      const matchesStatus =
        statusFilter === 'All' || item.status === statusFilter

      return matchesSearch && matchesRisk && matchesStatus
    })
  }, [caseList, search, riskFilter, statusFilter])

  // =========================================
  // STATISTICS
  // =========================================

  const criticalCases = caseList.filter(
    (item) => item.priority === 'Critical',
  ).length

  const openCases = caseList.filter(
    (item) => item.status === 'Open',
  ).length

  const investigatingCases = caseList.filter(
    (item) => item.status === 'Investigating',
  ).length

  const resolvedCases = caseList.filter(
    (item) => item.status === 'Resolved',
  ).length

  // =========================================
  // NEW CASE FORM
  // =========================================

  const handleNewCaseChange = (e) => {
    const { name, value } = e.target

    setNewCase((previous) => ({
      ...previous,
      [name]: value,
    }))
  }

  const calculateRisk = (priority) => {
    if (priority === 'Critical') return 90
    if (priority === 'High') return 76
    if (priority === 'Medium') return 58
    return 32
  }

  const getBackendCategory = (classification) => {
    if (classification === 'Impersonation') {
      return 'Suspicious'
    }

    return classification
  }

  const handleCreateCase = async (e) => {
    e.preventDefault()

    if (!newCase.title.trim() || !newCase.sender.trim()) {
      return
    }

    try {
      setCreatingCase(true)
      setError('')

      const risk = calculateRisk(newCase.priority)

      const ticketId = `TM-${new Date().getFullYear()}-${Date.now()
        .toString()
        .slice(-6)}`

      const payload = {
        ticketId,
        subject: newCase.title.trim(),
        sender: newCase.sender.trim(),
        recipient: '',
        emailBody:
          newCase.description.trim() ||
          'Case created manually by the analyst.',
        category: getBackendCategory(newCase.classification),
        priority: newCase.priority,
        status: 'Open',
        threatScore: risk,
        aiConfidence: 75,
        authentication: {
          spf: 'UNKNOWN',
          dkim: 'UNKNOWN',
          dmarc: 'UNKNOWN',
        },
        sourceIp: newCase.sourceIp.trim(),
        domain: newCase.domain.trim(),
        indicators: [],
        assignedTeam: newCase.assignedTo,
        recommendedSolution:
          'Investigate the case evidence and review associated indicators.',
      }

      const response = await fetch(API_URL, {
        method: 'POST',
        headers: getAuthHeaders(true),
        body: JSON.stringify(payload),
      })

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(data.message || 'Failed to create case')
      }

      const createdCase = formatTicket(data.ticket)

      setCaseList((previous) => [createdCase, ...previous])
      setSelectedCase(createdCase)
      setShowNewCase(false)

      setNewCase({
        title: '',
        sender: '',
        classification: 'Phishing',
        priority: 'Medium',
        sourceIp: '',
        domain: '',
        assignedTo: 'SOC Team',
        description: '',
      })
    } catch (err) {
      console.error(err)

      setError(
        err.message ||
          'Failed to create case. Please check the backend connection.',
      )
    } finally {
      setCreatingCase(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">

      {/* =========================================
          HEADER
      ========================================= */}

      <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/95 px-6 py-5 backdrop-blur lg:px-8">

        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">

          <div>

            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
              Investigation Management
            </p>

            <div className="mt-2 flex items-center gap-3">

              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-xl">
                📁
              </div>

              <div>

                <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                  Cases
                </h1>

                <p className="mt-1 text-sm text-slate-500">
                  Manage, investigate and preserve email security cases.
                </p>

              </div>

            </div>

          </div>

          <div className="flex items-center gap-3">

            <div className="rounded-xl border border-slate-800 bg-slate-900 px-4 py-3">

              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                Case Engine
              </p>

              <div className="mt-1 flex items-center gap-2">

                <span className="h-2 w-2 rounded-full bg-green-400" />

                <span className="text-xs font-semibold text-green-400">
                  READY
                </span>

              </div>

            </div>

            {canManageCases && (
              <button
                onClick={() => setShowNewCase(true)}
                className="rounded-xl bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                + New Case
              </button>
            )}

          </div>

        </div>

      </header>

      <main className="p-6 lg:p-8">

        {/* =========================================
            ERROR
        ========================================= */}

        {error && (

          <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/10 p-4">

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
                onClick={fetchCases}
                className="rounded-lg border border-red-500/20 bg-slate-950 px-3 py-2 text-xs font-semibold text-red-400 hover:bg-red-500/10"
              >
                Retry
              </button>

            </div>

          </div>

        )}

        {/* =========================================
            STATISTICS
        ========================================= */}

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">

          <StatCard
            label="Total Cases"
            value={caseList.length}
            description="All investigations"
            icon="📁"
            textClass="text-cyan-400"
            borderClass="border-cyan-500/10"
          />

          <StatCard
            label="Critical Cases"
            value={criticalCases}
            description="Require immediate attention"
            icon="⚠"
            textClass="text-red-400"
            borderClass="border-red-500/10"
          />

          <StatCard
            label="Investigating"
            value={investigatingCases}
            description="Currently under analysis"
            icon="🔍"
            textClass="text-yellow-400"
            borderClass="border-yellow-500/10"
          />

          <StatCard
            label="Resolved"
            value={resolvedCases}
            description={`${openCases} currently open`}
            icon="✓"
            textClass="text-green-400"
            borderClass="border-green-500/10"
          />

        </section>

        {/* =========================================
            WORKSPACE
        ========================================= */}

        <section className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-5">

          {/* =========================================
              CASE LIST
          ========================================= */}

          <div className="xl:col-span-3">

            <div className="rounded-2xl border border-slate-800 bg-slate-900">

              <div className="border-b border-slate-800 p-5">

                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

                  <div>

                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                      Active Investigations
                    </p>

                    <h2 className="mt-1 text-lg font-semibold text-slate-100">
                      Case Management
                    </h2>

                  </div>

                  <span className="rounded-full border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-500">
                    {filteredCases.length} cases
                  </span>

                </div>

                {/* Search */}

                <div className="mt-5">

                  <div className="relative">

                    <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600">
                      🔎
                    </span>

                    <input
                      type="text"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Search case ID, sender, domain, IP or threat..."
                      className="w-full rounded-xl border border-slate-800 bg-slate-950 py-3 pl-11 pr-4 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-500/50"
                    />

                  </div>

                </div>

                {/* Filters */}

                <div className="mt-4 flex flex-wrap gap-2">

                  {filterOptions.map((option) => (

                    <button
                      key={option}
                      onClick={() => setRiskFilter(option)}
                      className={`rounded-lg px-3 py-2 text-xs font-medium transition ${
                        riskFilter === option
                          ? 'bg-cyan-500/10 text-cyan-400 ring-1 ring-cyan-500/20'
                          : 'border border-slate-800 bg-slate-950 text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      {option}
                    </button>

                  ))}

                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400 outline-none focus:border-cyan-500/50"
                  >
                    <option value="All">All Status</option>
                    <option value="Open">Open</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Resolved">Resolved</option>
                  </select>

                  {(search || riskFilter !== 'All' || statusFilter !== 'All') && (

                    <button
                      onClick={() => {
                        setSearch('')
                        setRiskFilter('All')
                        setStatusFilter('All')
                      }}
                      className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-500 transition hover:text-slate-200"
                    >
                      Clear Filters
                    </button>

                  )}

                </div>

              </div>

              {/* =========================================
                  LOADING / CASES
              ========================================= */}

              {loading ? (

                <div className="p-12 text-center">

                  <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

                  <p className="mt-4 text-sm text-slate-500">
                    Loading cases from backend...
                  </p>

                </div>

              ) : (

                <div className="divide-y divide-slate-800">

                  {filteredCases.length === 0 ? (

                    <div className="p-12 text-center">

                      <div className="text-3xl">
                        🔎
                      </div>

                      <h3 className="mt-4 font-semibold text-slate-200">
                        No cases found
                      </h3>

                      <p className="mt-2 text-sm text-slate-500">
                        Try changing your search or filters.
                      </p>

                      <button
                        onClick={() => {
                          setSearch('')
                          setRiskFilter('All')
                          setStatusFilter('All')
                        }}
                        className="mt-5 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400"
                      >
                        Reset Filters
                      </button>

                    </div>

                  ) : (

                    filteredCases.map((item) => (

                      <button
                        key={item.mongoId || item.id}
                        onClick={() => setSelectedCase(item)}
                        className={`w-full text-left transition hover:bg-slate-950/70 ${
                          selectedCase?.id === item.id
                            ? 'bg-cyan-500/[0.03]'
                            : ''
                        }`}
                      >

                        <div className="p-5">

                          <div className="flex items-start justify-between gap-4">

                            <div className="min-w-0">

                              <div className="flex flex-wrap items-center gap-2">

                                <span className="text-sm font-semibold text-cyan-400">
                                  {item.id}
                                </span>

                                <PriorityBadge
                                  priority={item.priority}
                                />

                              </div>

                              <h3 className="mt-2 truncate text-sm font-semibold text-slate-200">
                                {item.title}
                              </h3>

                              <p className="mt-1 truncate text-xs text-slate-500">
                                {item.sender}
                              </p>

                            </div>

                            <div className="shrink-0 text-right">

                              <p
                                className={`text-lg font-bold ${getRiskText(
                                  item.risk,
                                )}`}
                              >
                                {item.risk}
                              </p>

                              <p className="text-[10px] text-slate-600">
                                RISK
                              </p>

                            </div>

                          </div>

                          <div className="mt-4 flex flex-wrap items-center gap-3">

                            <ClassificationBadge
                              classification={item.classification}
                            />

                            <StatusBadge
                              status={item.status}
                            />

                            <span className="text-xs text-slate-600">
                              {item.indicators} indicators
                            </span>

                            <span className="text-xs text-slate-700">
                              •
                            </span>

                            <span className="text-xs text-slate-600">
                              {item.updated}
                            </span>

                          </div>

                        </div>

                      </button>

                    ))

                  )}

                </div>

              )}

            </div>

          </div>

          {/* =========================================
              CASE DETAILS
          ========================================= */}

          <div className="xl:col-span-2">

            {selectedCase && (

              <div className="sticky top-28 rounded-2xl border border-slate-800 bg-slate-900">

                {/* Details Header */}

                <div className="border-b border-slate-800 p-6">

                  <div className="flex items-start justify-between gap-4">

                    <div>

                      <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                        Investigation Detail
                      </p>

                      <h2 className="mt-2 text-xl font-bold text-slate-100">
                        {selectedCase.id}
                      </h2>

                      <p className="mt-1 text-sm text-slate-400">
                        {selectedCase.title}
                      </p>

                    </div>

                    <div
                      className={`flex h-12 w-12 items-center justify-center rounded-xl border ${getRiskBorder(
                        selectedCase.risk,
                      )} bg-slate-950`}
                    >

                      <span
                        className={`text-lg font-bold ${getRiskText(
                          selectedCase.risk,
                        )}`}
                      >
                        {selectedCase.risk}
                      </span>

                    </div>

                  </div>

                  <div className="mt-5 flex flex-wrap gap-2">

                    <PriorityBadge
                      priority={selectedCase.priority}
                    />

                    <StatusBadge
                      status={selectedCase.status}
                    />

                  </div>

                </div>

                {/* Overview */}

                <div className="p-6">

                  <div>

                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                      Threat Classification
                    </p>

                    <div className="mt-3">

                      <ClassificationBadge
                        classification={selectedCase.classification}
                      />

                    </div>

                  </div>

                  <div className="mt-6">

                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                      Investigation Summary
                    </p>

                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      {selectedCase.description}
                    </p>

                  </div>

                  {/* Details */}

                  <div
                    className={`mt-6 grid gap-3 ${
                      canGenerateReports ? 'grid-cols-2' : 'grid-cols-1'
                    }`}
                  >

                    <DetailBox
                      label="Source IP"
                      value={selectedCase.sourceIp}
                    />

                    <DetailBox
                      label="Indicators"
                      value={selectedCase.indicators}
                    />

                    <DetailBox
                      label="Domain"
                      value={selectedCase.domain}
                    />

                    <DetailBox
                      label="Assigned Team"
                      value={selectedCase.assignedTo}
                    />

                    <DetailBox
                      label="Created"
                      value={selectedCase.created}
                    />

                    <DetailBox
                      label="Last Updated"
                      value={selectedCase.updated}
                    />

                  </div>

                  {/* Risk Score */}

                  <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950 p-4">

                    <div className="flex items-center justify-between">

                      <div>

                        <p className="text-xs uppercase tracking-wider text-slate-600">
                          Threat Risk Score
                        </p>

                        <p
                          className={`mt-1 text-2xl font-bold ${getRiskText(
                            selectedCase.risk,
                          )}`}
                        >
                          {selectedCase.risk}

                          <span className="text-sm font-normal text-slate-600">
                            /100
                          </span>

                        </p>

                      </div>

                      <span className="text-xs text-slate-600">
                        AI assessment
                      </span>

                    </div>

                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-800">

                      <div
                        className={`h-full rounded-full ${getRiskBar(
                          selectedCase.risk,
                        )}`}
                        style={{
                          width: `${selectedCase.risk}%`,
                        }}
                      />

                    </div>

                  </div>

                  {/* Timeline */}

                  <div className="mt-6">

                    <div className="flex items-center justify-between">

                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                        Investigation Timeline
                      </p>

                      <span className="text-[10px] text-slate-700">
                        LIVE CASE
                      </span>

                    </div>

                    <div className="mt-4 space-y-4">

                      {selectedCase.auditTimeline?.length > 0 ? (
                        selectedCase.auditTimeline.map((event, index) => (
                          <TimelineItem
                            key={`${event.action}-${event.timestamp || index}`}
                            time={formatAuditTime(event.timestamp)}
                            title={event.action}
                            description={event.details || 'Forensic activity recorded.'}
                            actor={event.actor}
                            evidenceHash={event.evidenceHash}
                            isLast={index === selectedCase.auditTimeline.length - 1}
                          />
                        ))
                      ) : (
                        <>
                          <TimelineItem
                            time={selectedCase.created}
                            title="Case opened"
                            description="Investigation created and stored in the backend database."
                            isLast={false}
                          />

                          <TimelineItem
                            time={selectedCase.updated}
                            title="Latest investigation update"
                            description="Threat intelligence and forensic evidence reviewed."
                            isLast
                          />
                        </>
                      )}

                    </div>

                    {/* Evidence integrity summary */}
                    {selectedCase.evidenceHash && (
                      <div className="mt-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
                        <div className="flex items-start gap-3">
                          <span className="text-lg">🔐</span>
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                              Evidence Integrity
                            </p>
                            <p className="mt-1 text-[10px] text-slate-600">
                              {selectedCase.hashAlgorithm} forensic fingerprint
                            </p>
                            <p className="mt-2 break-all font-mono text-[10px] leading-5 text-slate-400">
                              {selectedCase.evidenceHash}
                            </p>
                            <p className="mt-2 text-[10px] text-green-400">
                              ✓ Evidence fingerprint preserved with case
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                  </div>

                  {/* Actions */}

                  <div
                    className={`mt-6 grid gap-3 ${
                      canGenerateReports ? 'grid-cols-2' : 'grid-cols-1'
                    }`}
                  >

                    <button
                      onClick={() => navigate('/forensics')}
                      className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/30 hover:text-cyan-400"
                    >
                      View Evidence
                    </button>

                    {canGenerateReports && (
                      <button
                        onClick={() => navigate('/reports')}
                        className="rounded-xl bg-cyan-500 px-4 py-3 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400"
                      >
                        Generate Report
                      </button>
                    )}

                  </div>

                </div>

              </div>

            )}

          </div>

        </section>

        {/* =========================================
            INTELLIGENCE PANELS
        ========================================= */}

        <section className="mt-6 grid grid-cols-1 gap-5 md:grid-cols-3">

          <InfoPanel
            icon="🔐"
            title="Evidence Preservation"
            description="Forensic artifacts can be preserved with case metadata and investigation history."
          />

          <InfoPanel
            icon="🧩"
            title="IOC Correlation"
            description="IP addresses, domains, senders and extracted indicators can be correlated across cases."
          />

          <InfoPanel
            icon="📊"
            title="Investigation Reports"
            description="Structured case reports can be generated for incident response and further analysis."
          />

        </section>

        {/* =========================================
            FOOTER
        ========================================= */}

        <footer className="mt-8 flex flex-col gap-3 border-t border-slate-800 pt-5 text-xs text-slate-600 md:flex-row md:items-center md:justify-between">

          <p>
            TraceMail AI • Case Investigation Management
          </p>

          <div className="flex items-center gap-2">

            <span className="h-1.5 w-1.5 rounded-full bg-green-400" />

            Case engine operational

          </div>

        </footer>

      </main>

      {/* =========================================
          NEW CASE MODAL
      ========================================= */}

      {showNewCase && canManageCases && (

        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget && !creatingCase) {
              setShowNewCase(false)
            }
          }}
        >

          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl">

            {/* Modal Header */}

            <div className="flex items-center justify-between border-b border-slate-800 p-6">

              <div>

                <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                  Investigation Management
                </p>

                <h2 className="mt-1 text-xl font-bold text-slate-100">
                  Create New Case
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Create a new email security investigation.
                </p>

              </div>

              <button
                onClick={() => setShowNewCase(false)}
                disabled={creatingCase}
                className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-slate-950 text-slate-500 transition hover:text-slate-200 disabled:opacity-50"
              >
                ✕
              </button>

            </div>

            {/* Form */}

            <form
              onSubmit={handleCreateCase}
              className="space-y-5 p-6"
            >

              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">

                {/* Title */}

                <div className="md:col-span-2">

                  <label className="text-xs font-medium text-slate-400">
                    Case Title
                  </label>

                  <input
                    name="title"
                    value={newCase.title}
                    onChange={handleNewCaseChange}
                    placeholder="e.g. Suspicious credential harvesting attempt"
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
                    required
                  />

                </div>

                {/* Sender */}

                <div>

                  <label className="text-xs font-medium text-slate-400">
                    Sender Email
                  </label>

                  <input
                    name="sender"
                    type="email"
                    value={newCase.sender}
                    onChange={handleNewCaseChange}
                    placeholder="attacker@example.com"
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
                    required
                  />

                </div>

                {/* Classification */}

                <div>

                  <label className="text-xs font-medium text-slate-400">
                    Classification
                  </label>

                  <select
                    name="classification"
                    value={newCase.classification}
                    onChange={handleNewCaseChange}
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-300 outline-none focus:border-cyan-500/50"
                  >
                    <option>Phishing</option>
                    <option>Impersonation</option>
                    <option>BEC / Fraud</option>
                    <option>Credential Theft</option>
                    <option>Malware</option>
                    <option>Suspicious</option>
                  </select>

                </div>

                {/* Priority */}

                <div>

                  <label className="text-xs font-medium text-slate-400">
                    Priority
                  </label>

                  <select
                    name="priority"
                    value={newCase.priority}
                    onChange={handleNewCaseChange}
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-300 outline-none focus:border-cyan-500/50"
                  >
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>

                </div>

                {/* Team */}

                <div>

                  <label className="text-xs font-medium text-slate-400">
                    Assigned Team
                  </label>

                  <select
                    name="assignedTo"
                    value={newCase.assignedTo}
                    onChange={handleNewCaseChange}
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-300 outline-none focus:border-cyan-500/50"
                  >
                    <option>SOC Team</option>
                    <option>Threat Response</option>
                    <option>Incident Response</option>
                    <option>Fraud Investigation</option>
                    <option>Malware Analysis</option>
                    <option>Identity Security</option>
                    <option>Threat Intelligence</option>
                  </select>

                </div>

                {/* Source IP */}

                <div>

                  <label className="text-xs font-medium text-slate-400">
                    Source IP
                  </label>

                  <input
                    name="sourceIp"
                    value={newCase.sourceIp}
                    onChange={handleNewCaseChange}
                    placeholder="185.220.101.42"
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
                  />

                </div>

                {/* Domain */}

                <div>

                  <label className="text-xs font-medium text-slate-400">
                    Suspicious Domain
                  </label>

                  <input
                    name="domain"
                    value={newCase.domain}
                    onChange={handleNewCaseChange}
                    placeholder="suspicious-domain.com"
                    className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
                  />

                </div>

                {/* Description */}

                <div className="md:col-span-2">

                  <label className="text-xs font-medium text-slate-400">
                    Investigation Summary
                  </label>

                  <textarea
                    name="description"
                    value={newCase.description}
                    onChange={handleNewCaseChange}
                    rows="4"
                    placeholder="Describe the suspicious activity..."
                    className="mt-2 w-full resize-none rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
                  />

                </div>

              </div>

              {/* Form Actions */}

              <div className="flex justify-end gap-3 border-t border-slate-800 pt-5">

                <button
                  type="button"
                  onClick={() => setShowNewCase(false)}
                  disabled={creatingCase}
                  className="rounded-xl border border-slate-700 bg-slate-950 px-5 py-3 text-sm font-medium text-slate-400 transition hover:text-slate-200 disabled:opacity-50"
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  disabled={creatingCase}
                  className="rounded-xl bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {creatingCase ? 'Creating...' : 'Create Case'}
                </button>

              </div>

            </form>

          </div>

        </div>

      )}

    </div>
  )
}

/* =========================================
   FORMAT BACKEND TICKET
========================================= */

function formatTicket(ticket) {
  const createdDate = ticket.createdAt
    ? new Date(ticket.createdAt)
    : null

  const updatedDate = ticket.updatedAt
    ? new Date(ticket.updatedAt)
    : null

  const classification =
    ticket.category === 'Suspicious'
      ? 'Suspicious'
      : ticket.category || 'Other'

  return {
    mongoId: ticket._id,
    id: ticket.ticketId || ticket._id,
    title: ticket.subject || 'Untitled Investigation',
    sender: ticket.sender || 'Unknown Sender',
    classification,
    risk: Number(ticket.threatScore) || 0,
    status: ticket.status || 'Open',
    priority: ticket.priority || 'Medium',
    sourceIp: ticket.sourceIp || 'Pending',
    domain: ticket.domain || 'Pending',
    assignedTo: ticket.assignedTeam || 'Threat Intelligence',
    created: formatDate(createdDate),
    updated: formatDate(updatedDate),
    indicators: Array.isArray(ticket.indicators)
      ? ticket.indicators.length
      : 0,

    // Chain of Custody / Audit Timeline
    auditTimeline: Array.isArray(ticket.auditTimeline)
      ? ticket.auditTimeline
      : [],

    evidenceHash: ticket.evidenceHash || '',
    hashAlgorithm: ticket.hashAlgorithm || 'SHA-256',

    description:
      ticket.emailBody ||
      ticket.recommendedSolution ||
      'No investigation summary available.',
  }
}

/* =========================================
   DATE FORMAT
========================================= */

function formatDate(date) {
  if (!date || Number.isNaN(date.getTime())) {
    return 'Unknown'
  }

  const now = new Date()
  const diff = now.getTime() - date.getTime()

  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)

  if (minutes < 1) return 'Just now'

  if (minutes < 60) {
    return `${minutes} min ago`
  }

  if (hours < 24) {
    return `${hours} hr ago`
  }

  if (days === 1) {
    return 'Yesterday'
  }

  if (days < 7) {
    return `${days} days ago`
  }

  return date.toLocaleDateString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  })
}

/* =========================================
   STAT CARD
========================================= */

function StatCard({
  label,
  value,
  description,
  icon,
  textClass,
  borderClass,
}) {
  return (
    <div
      className={`rounded-2xl border ${borderClass} bg-slate-900 p-5 transition hover:border-slate-700`}
    >

      <div className="flex items-start justify-between">

        <p className="text-xs font-medium uppercase tracking-wider text-slate-600">
          {label}
        </p>

        <span className="rounded-lg bg-slate-950 px-2.5 py-1.5 text-xs">
          {icon}
        </span>

      </div>

      <p className={`mt-3 text-3xl font-bold ${textClass}`}>
        {value}
      </p>

      <p className="mt-2 text-xs text-slate-600">
        {description}
      </p>

    </div>
  )
}

/* =========================================
   PRIORITY BADGE
========================================= */

function PriorityBadge({ priority }) {

  const styles = {
    Critical: 'bg-red-500/10 text-red-400 border-red-500/20',
    High: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    Medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    Low: 'bg-green-500/10 text-green-400 border-green-500/20',
  }

  return (
    <span
      className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold ${
        styles[priority] || styles.Medium
      }`}
    >
      {priority}
    </span>
  )
}

/* =========================================
   CLASSIFICATION BADGE
========================================= */

function ClassificationBadge({ classification }) {

  const styles = {
    Phishing: 'bg-red-500/10 text-red-400',
    Impersonation: 'bg-yellow-500/10 text-yellow-400',
    'BEC / Fraud': 'bg-orange-500/10 text-orange-400',
    'Credential Theft': 'bg-red-500/10 text-red-400',
    Malware: 'bg-purple-500/10 text-purple-400',
    Suspicious: 'bg-yellow-500/10 text-yellow-400',
    Other: 'bg-slate-800 text-slate-400',
  }

  return (
    <span
      className={`rounded-full px-2.5 py-1 text-[10px] font-medium ${
        styles[classification] || styles.Other
      }`}
    >
      {classification}
    </span>
  )
}

/* =========================================
   STATUS BADGE
========================================= */

function StatusBadge({ status }) {

  const styles = {
    Open: 'bg-cyan-500/10 text-cyan-400',
    Investigating: 'bg-green-500/10 text-green-400',
    Resolved: 'bg-slate-800 text-slate-400',
  }

  return (
    <span
      className={`rounded-full px-2.5 py-1 text-[10px] font-medium ${
        styles[status] || 'bg-slate-800 text-slate-400'
      }`}
    >
      {status}
    </span>
  )
}

/* =========================================
   DETAIL BOX
========================================= */

function DetailBox({ label, value }) {

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">

      <p className="text-[9px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-1 break-words text-xs font-medium text-slate-300">
        {value}
      </p>

    </div>
  )
}

/* =========================================
   AUDIT TIMESTAMP FORMAT
========================================= */

function formatAuditTime(timestamp) {
  if (!timestamp) return 'Unknown time'

  const date = new Date(timestamp)

  if (Number.isNaN(date.getTime())) {
    return 'Unknown time'
  }

  return date.toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/* =========================================
   TIMELINE
========================================= */

function TimelineItem({
  time,
  title,
  description,
  actor,
  evidenceHash,
  isLast = false,
}) {

  return (
    <div className="flex gap-3">

      <div className="flex flex-col items-center">

        <span className="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full bg-cyan-400 ring-4 ring-cyan-500/10" />

        {!isLast && (
          <span className="mt-1 h-full min-h-8 w-px bg-slate-800" />
        )}

      </div>

      <div className="min-w-0 pb-2">

        <div className="flex flex-wrap items-center gap-2">
          <p className="text-[10px] font-medium uppercase tracking-wider text-cyan-400">
            {time}
          </p>

          {actor && (
            <span className="rounded-full border border-slate-800 bg-slate-950 px-2 py-0.5 text-[9px] text-slate-600">
              {actor}
            </span>
          )}
        </div>

        <p className="mt-1 text-xs font-semibold text-slate-300">
          {title}
        </p>

        <p className="mt-1 text-xs leading-5 text-slate-600">
          {description}
        </p>

        {evidenceHash && (
          <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950 p-2.5">
            <p className="text-[9px] uppercase tracking-wider text-slate-700">
              Evidence SHA-256
            </p>
            <p className="mt-1 break-all font-mono text-[9px] leading-4 text-slate-500">
              {evidenceHash}
            </p>
          </div>
        )}

      </div>

    </div>
  )
}

/* =========================================
   INFO PANEL
========================================= */

function InfoPanel({ icon, title, description }) {

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">

      <div className="flex items-start gap-3">

        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyan-500/10 text-lg">
          {icon}
        </div>

        <div>

          <h3 className="text-sm font-semibold text-slate-200">
            {title}
          </h3>

          <p className="mt-2 text-xs leading-5 text-slate-600">
            {description}
          </p>

        </div>

      </div>

    </div>
  )
}

/* =========================================
   RISK HELPERS
========================================= */

function getRiskText(risk) {

  if (risk >= 85) return 'text-red-400'

  if (risk >= 70) return 'text-orange-400'

  if (risk >= 50) return 'text-yellow-400'

  return 'text-green-400'
}

function getRiskBorder(risk) {

  if (risk >= 85) return 'border-red-500/30'

  if (risk >= 70) return 'border-orange-500/30'

  if (risk >= 50) return 'border-yellow-500/30'

  return 'border-green-500/30'
}

function getRiskBar(risk) {

  if (risk >= 85) return 'bg-red-500'

  if (risk >= 70) return 'bg-orange-500'

  if (risk >= 50) return 'bg-yellow-500'

  return 'bg-green-500'
}