import { useEffect, useMemo, useState } from 'react'

const TICKET_API_URL = 'http://localhost:5001/api/tickets'

const DEMO_CAMPAIGNS = [
  {
    id: 'CMP-2026-001',
    name: 'Microsoft Account Phishing',
    type: 'Credential Theft',
    risk: 'Critical',
    score: 96,
    emails: 28,
    domains: 6,
    ips: 4,
    iocs: 61,
    firstSeen: 'Today, 09:42',
    lastSeen: 'Today, 13:18',
    status: 'Active',
    confidence: 94,
    real: false,
    domainsList: [
      'micros0ft-support.com',
      'microsoft-security-alert.com',
      'account-verify.net',
    ],
    ipsList: [
      '185.220.101.42',
      '185.220.101.43',
    ],
    indicators: [
      'verify your account',
      'password',
      'urgent',
      'login',
      'suspicious URL',
    ],
  },
  {
    id: 'CMP-2026-002',
    name: 'Invoice Payment Fraud',
    type: 'BEC / Fraud',
    risk: 'High',
    score: 88,
    emails: 19,
    domains: 4,
    ips: 3,
    iocs: 37,
    firstSeen: 'Yesterday, 15:20',
    lastSeen: 'Today, 12:06',
    status: 'Active',
    confidence: 91,
    real: false,
    domainsList: [
      'company-finance-secure.com',
      'vendor-payment.net',
    ],
    ipsList: [
      '185.220.102.20',
      '185.220.102.21',
    ],
    indicators: [
      'urgent payment',
      'confidential',
      'new vendor account',
      'INR 2,45,000',
    ],
  },
  {
    id: 'CMP-2026-003',
    name: 'Corporate Password Reset',
    type: 'Credential Theft',
    risk: 'High',
    score: 84,
    emails: 13,
    domains: 3,
    ips: 2,
    iocs: 29,
    firstSeen: '2 days ago',
    lastSeen: 'Today, 10:31',
    status: 'Monitoring',
    confidence: 87,
    real: false,
    domainsList: [
      'corporate-password-reset.com',
      'secure-login-portal.net',
    ],
    ipsList: [
      '103.75.118.20',
      '103.75.118.21',
    ],
    indicators: [
      'password reset',
      'verify identity',
      'login',
      'account suspended',
    ],
  },
  {
    id: 'CMP-2026-004',
    name: 'Delivery Notification Scam',
    type: 'Phishing',
    risk: 'Medium',
    score: 68,
    emails: 9,
    domains: 2,
    ips: 2,
    iocs: 16,
    firstSeen: '4 days ago',
    lastSeen: 'Yesterday, 18:44',
    status: 'Monitoring',
    confidence: 82,
    real: false,
    domainsList: [
      'delivery-track-alert.com',
      'parcel-verification.net',
    ],
    ipsList: [
      '45.91.20.11',
      '45.91.20.12',
    ],
    indicators: [
      'delivery notification',
      'tracking link',
      'verify delivery',
    ],
  },
]

export default function Campaigns() {
  const [selectedCampaign, setSelectedCampaign] = useState(null)

  const [tickets, setTickets] = useState([])

  const [loading, setLoading] = useState(true)

  const [backendStatus, setBackendStatus] =
    useState('Connecting...')

  const [error, setError] = useState('')

  const [lastUpdated, setLastUpdated] = useState(null)

  // =========================================
  // FETCH REAL INVESTIGATIONS
  // =========================================

  const fetchTickets = async () => {
    setLoading(true)
    setError('')

    try {
      const token = localStorage.getItem('tracemail_auth_token')

      const response = await fetch(TICKET_API_URL, {
        headers: {
          ...(token
            ? { Authorization: `Bearer ${token}` }
            : {}),
        },
      })

      if (!response.ok) {
        throw new Error(
          `Backend returned ${response.status}`
        )
      }

      const data = await response.json()

      const list = Array.isArray(data)
        ? data
        : Array.isArray(data.tickets)
          ? data.tickets
          : Array.isArray(data.data)
            ? data.data
            : []

      setTickets(list)

      setBackendStatus('Connected')

      setLastUpdated(new Date())
    } catch (err) {
      console.error(
        'Campaign backend error:',
        err
      )

      setBackendStatus('Demo Mode')

      setError(
        'Backend campaign data is unavailable. Showing demo campaign intelligence.'
      )

      setTickets([])
    } finally {
      setLoading(false)
    }
  }

  // =========================================
  // LOAD DATA
  // =========================================

  useEffect(() => {
    fetchTickets()
  }, [])

  // =========================================
  // NORMALIZE TICKET
  // =========================================

  const normalizeTicket = (ticket, index) => {
    const indicators = Array.isArray(
      ticket.indicators
    )
      ? ticket.indicators
      : []

    const domain =
      ticket.domain ||
      extractDomain(
        ticket.sender ||
          ticket.from ||
          ''
      )

    const sourceIp =
      ticket.sourceIp ||
      ticket.sourceIP ||
      ticket.ip ||
      ''

    const category =
      ticket.category ||
      'Suspicious'

    const priority =
      ticket.priority ||
      'Medium'

    const threatScore = Number(
      ticket.threatScore ??
        ticket.riskScore ??
        0
    )

    const confidence = Number(
      ticket.aiConfidence ??
        ticket.confidence ??
        0
    )

    const subject =
      ticket.subject ||
      'Suspicious Email'

    const ticketId =
      ticket.ticketId ||
      ticket.caseId ||
      ticket._id ||
      `CASE-${index + 1}`

    const createdAt =
      ticket.createdAt ||
      ticket.updatedAt ||
      null

    return {
      ...ticket,
      normalizedId: ticketId,
      normalizedDomain: domain,
      normalizedIp: sourceIp,
      normalizedCategory: category,
      normalizedPriority: priority,
      normalizedScore: threatScore,
      normalizedConfidence: confidence,
      normalizedIndicators: indicators,
      normalizedSubject: subject,
      normalizedCreatedAt: createdAt,
    }
  }

  // =========================================
  // CREATE REAL CAMPAIGNS
  // =========================================

  const realCampaigns = useMemo(() => {
    const normalized = tickets.map(
      normalizeTicket
    )

    if (normalized.length === 0) {
      return []
    }

    const groups = new Map()

    normalized.forEach((ticket) => {
      const domain =
        ticket.normalizedDomain ||
        'unknown-domain'

      const ip =
        ticket.normalizedIp ||
        'unknown-ip'

      const category =
        ticket.normalizedCategory ||
        'Suspicious'

      let key = ''

      if (
        domain !== 'unknown-domain'
      ) {
        key = `domain:${domain}`
      } else if (
        ip !== 'unknown-ip'
      ) {
        key = `ip:${ip}`
      } else {
        key = `category:${category}`
      }

      if (!groups.has(key)) {
        groups.set(key, [])
      }

      groups.get(key).push(ticket)
    })

    const campaigns = []

    let counter = 1

    groups.forEach((group) => {
      const domains = unique(
        group
          .map(
            (item) =>
              item.normalizedDomain
          )
          .filter(Boolean)
      )

      const ips = unique(
        group
          .map(
            (item) =>
              item.normalizedIp
          )
          .filter(Boolean)
      )

      const indicatorSet = unique(
        group.flatMap(
          (item) =>
            item.normalizedIndicators
        )
      )

      const maxScore = Math.max(
        ...group.map(
          (item) =>
            item.normalizedScore || 0
        ),
        0
      )

      const avgScore =
        group.length > 0
          ? Math.round(
              group.reduce(
                (sum, item) =>
                  sum +
                  (item.normalizedScore ||
                    0),
                0
              ) / group.length
            )
          : 0

      const score = Math.max(
        maxScore,
        avgScore
      )

      const confidenceValues =
        group
          .map(
            (item) =>
              item.normalizedConfidence
          )
          .filter(
            (value) =>
              value > 0
          )

      const confidence =
        confidenceValues.length > 0
          ? Math.round(
              confidenceValues.reduce(
                (sum, value) =>
                  sum + value,
                0
              ) /
                confidenceValues.length
            )
          : Math.min(
              95,
              70 +
                group.length * 5
            )

      const category =
        getCampaignType(
          group.map(
            (item) =>
              item.normalizedCategory
          )
        )

      const risk =
        getRiskFromScore(score)

      const status =
        group.some(
          (item) =>
            String(
              item.status || ''
            ).toLowerCase() ===
              'closed' ||
            String(
              item.status || ''
            ).toLowerCase() ===
              'resolved'
        )
          ? 'Monitoring'
          : 'Active'

      const name =
        buildCampaignName(
          category,
          domains,
          group
        )

      const dates = group
        .map(
          (item) =>
            item.normalizedCreatedAt
        )
        .filter(Boolean)
        .map(
          (value) =>
            new Date(value)
        )
        .filter(
          (date) =>
            !Number.isNaN(
              date.getTime()
            )
        )
        .sort(
          (a, b) =>
            a.getTime() -
            b.getTime()
        )

      const firstSeen =
        dates.length > 0
          ? formatDate(dates[0])
          : 'Recently'

      const lastSeen =
        dates.length > 0
          ? formatDate(
              dates[dates.length - 1]
            )
          : 'Recently'

      campaigns.push({
        id: `CMP-REAL-${String(
          counter
        ).padStart(3, '0')}`,

        name,

        type: category,

        risk,

        score,

        emails: group.length,

        domains: domains.length,

        ips: ips.length,

        iocs: indicatorSet.length,

        firstSeen,

        lastSeen,

        status,

        confidence,

        real: true,

        tickets: group,

        domainsList: domains,

        ipsList: ips,

        indicators: indicatorSet,
      })

      counter += 1
    })

    return campaigns.sort(
      (a, b) =>
        b.score - a.score
    )
  }, [tickets])

  // =========================================
  // COMBINE REAL + DEMO
  // =========================================

  const campaigns = useMemo(() => {
    if (
      realCampaigns.length === 0
    ) {
      return DEMO_CAMPAIGNS
    }

    return [
      ...realCampaigns,
      ...DEMO_CAMPAIGNS,
    ]
  }, [realCampaigns])

  // =========================================
  // GLOBAL STATISTICS
  // =========================================

  const statistics = useMemo(() => {
    if (tickets.length === 0) {
      return {
        activeCampaigns: 7,
        correlatedEmails: 69,
        relatedDomains: 15,
        highRiskCampaigns: 4,
        totalIps: 11,
        totalIocs: 143,
      }
    }

    const allDomains = unique(
      tickets
        .map(
          (ticket) =>
            normalizeTicket(
              ticket,
              0
            ).normalizedDomain
        )
        .filter(Boolean)
    )

    const allIps = unique(
      tickets
        .map(
          (ticket) =>
            normalizeTicket(
              ticket,
              0
            ).normalizedIp
        )
        .filter(Boolean)
    )

    const allIocs = unique(
      tickets.flatMap(
        (ticket) =>
          normalizeTicket(
            ticket,
            0
          ).normalizedIndicators
      )
    )

    const highRisk = tickets.filter(
      (ticket) => {
        const normalized =
          normalizeTicket(
            ticket,
            0
          )

        return (
          normalized.normalizedScore >=
            70 ||
          ['High', 'Critical'].includes(
            normalized.normalizedPriority
          )
        )
      }
    ).length

    return {
      activeCampaigns:
        realCampaigns.filter(
          (campaign) =>
            campaign.status ===
            'Active'
        ).length,

      correlatedEmails:
        tickets.length,

      relatedDomains:
        allDomains.length,

      highRiskCampaigns:
        highRisk,

      totalIps:
        allIps.length,

      totalIocs:
        allIocs.length,
    }
  }, [
    tickets,
    realCampaigns,
  ])

  // =========================================
  // TYPE DISTRIBUTION
  // =========================================

  const distribution =
    useMemo(() => {
      if (
        tickets.length === 0
      ) {
        return [
          {
            label:
              'Credential Theft',
            value: 43,
          },
          {
            label:
              'BEC / Fraud',
            value: 27,
          },
          {
            label: 'Phishing',
            value: 21,
          },
          {
            label: 'Other',
            value: 9,
          },
        ]
      }

      const counts = {}

      tickets.forEach(
        (ticket) => {
          const category =
            getCampaignType([
              ticket.category ||
                'Suspicious',
            ])

          counts[category] =
            (counts[category] ||
              0) + 1
        }
      )

      const total =
        tickets.length || 1

      const rows = Object.entries(
        counts
      )
        .map(
          ([label, count]) => ({
            label,
            value: Math.round(
              (count / total) *
                100
            ),
          })
        )
        .sort(
          (a, b) =>
            b.value - a.value
        )

      return rows.length > 0
        ? rows
        : [
            {
              label: 'Other',
              value: 100,
            },
          ]
    }, [tickets])

  // =========================================
  // SELECT CAMPAIGN
  // =========================================

  const handleCampaignSelect = (
    campaign
  ) => {
    setSelectedCampaign(
      campaign
    )

    setTimeout(() => {
      window.scrollTo({
        top: document.body
          .scrollHeight,
        behavior: 'smooth',
      })
    }, 50)
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6 text-white lg:p-8">

      {/* =========================================
          HEADER
      ========================================= */}

      <div className="mb-8 flex flex-col justify-between gap-4 xl:flex-row xl:items-center">

        <div className="flex items-center gap-4">

          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-2xl">
            🕸
          </div>

          <div>

            <p className="text-xs font-medium uppercase tracking-[0.2em] text-cyan-500">
              Threat Correlation
            </p>

            <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-100">
              Campaigns
            </h1>

            <p className="mt-1 text-sm text-slate-500">
              Correlate related emails, domains, IPs and indicators to identify coordinated threats.
            </p>

          </div>

        </div>

        <div className="flex flex-wrap items-center gap-3">

          <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900 px-4 py-3">

            <span className="relative flex h-2.5 w-2.5">

              <span
                className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-50 ${
                  backendStatus ===
                  'Connected'
                    ? 'bg-green-400'
                    : 'bg-yellow-400'
                }`}
              ></span>

              <span
                className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                  backendStatus ===
                  'Connected'
                    ? 'bg-green-400'
                    : 'bg-yellow-400'
                }`}
              ></span>

            </span>

            <div>

              <p className="text-xs font-medium text-slate-300">
                Correlation Engine
              </p>

              <p
                className={`text-[10px] uppercase tracking-wider ${
                  backendStatus ===
                  'Connected'
                    ? 'text-green-400'
                    : 'text-yellow-400'
                }`}
              >
                {backendStatus}
              </p>

            </div>

          </div>

          <button
            type="button"
            onClick={fetchTickets}
            disabled={loading}
            className="rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-xs font-medium text-slate-400 transition hover:border-cyan-500/30 hover:text-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading
              ? 'Refreshing...'
              : '↻ Refresh'}
          </button>

        </div>

      </div>

      {/* =========================================
          BACKEND INFO
      ========================================= */}

      {error && (

        <div className="mb-6 rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">

          <div className="flex items-start gap-3">

            <span>⚠️</span>

            <div>

              <p className="text-sm font-medium text-yellow-400">
                Campaign data notice
              </p>

              <p className="mt-1 text-xs leading-5 text-slate-500">
                {error}
              </p>

            </div>

          </div>

        </div>

      )}

      {/* =========================================
          CAMPAIGN STATISTICS
      ========================================= */}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

        <StatCard
          label="Active Campaigns"
          value={
            statistics.activeCampaigns
          }
          subtitle={
            tickets.length > 0
              ? 'Generated from investigations'
              : 'Currently monitored'
          }
          icon="🕸"
          valueClass="text-cyan-400"
        />

        <StatCard
          label="Correlated Emails"
          value={
            statistics.correlatedEmails
          }
          subtitle={
            tickets.length > 0
              ? 'Backend investigations'
              : 'Linked investigations'
          }
          icon="✉"
          valueClass="text-slate-100"
        />

        <StatCard
          label="Related Domains"
          value={
            statistics.relatedDomains
          }
          subtitle="Suspicious infrastructure"
          icon="◈"
          valueClass="text-yellow-400"
        />

        <StatCard
          label="High Risk Campaigns"
          value={
            statistics.highRiskCampaigns
          }
          subtitle="Require attention"
          icon="⚠"
          valueClass="text-red-400"
        />

      </div>

      {/* =========================================
          CAMPAIGN OVERVIEW
      ========================================= */}

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">

        {/* Detection Summary */}

        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 xl:col-span-2">

          <div className="mb-6 flex items-start justify-between">

            <div>

              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Campaign Detection
              </p>

              <h2 className="mt-1 text-lg font-semibold text-slate-100">
                Campaign Intelligence
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Current correlation activity across analyzed email threats.
              </p>

            </div>

            <span className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] text-slate-600">
              LAST 30 DAYS
            </span>

          </div>

          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">

            <Metric
              label="Emails"
              value={
                statistics.correlatedEmails
              }
            />

            <Metric
              label="Domains"
              value={
                statistics.relatedDomains
              }
            />

            <Metric
              label="IPs"
              value={
                statistics.totalIps
              }
            />

            <Metric
              label="IOCs"
              value={
                statistics.totalIocs
              }
            />

          </div>

          <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/60 p-5">

            <div className="mb-4 flex items-center justify-between">

              <div>

                <p className="text-xs text-slate-600">
                  CORRELATION CONFIDENCE
                </p>

                <p className="mt-1 text-lg font-semibold text-cyan-400">
                  {realCampaigns.length >
                  0
                    ? `${Math.round(
                        realCampaigns.reduce(
                          (
                            sum,
                            campaign
                          ) =>
                            sum +
                            campaign.confidence,
                          0
                        ) /
                          realCampaigns.length
                      )}%`
                    : '91.4%'}
                </p>

              </div>

              <span className="rounded-lg bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-400">
                HIGH CONFIDENCE
              </span>

            </div>

            <div className="h-2 overflow-hidden rounded-full bg-slate-800">

              <div
                className="h-full rounded-full bg-cyan-500"
                style={{
                  width: `${
                    realCampaigns.length >
                    0
                      ? Math.min(
                          100,
                          Math.round(
                            realCampaigns.reduce(
                              (
                                sum,
                                campaign
                              ) =>
                                sum +
                                campaign.confidence,
                              0
                            ) /
                              realCampaigns.length
                          )
                        )
                      : 91
                  }%`,
                }}
              ></div>

            </div>

            <p className="mt-3 text-xs leading-5 text-slate-600">
              Campaign relationships are generated from shared infrastructure,
              sender patterns, domains, authentication anomalies and extracted indicators.
            </p>

          </div>

        </div>

        {/* Threat Distribution */}

        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-6">

            <p className="text-xs font-medium uppercase tracking-wider text-yellow-500">
              Threat Distribution
            </p>

            <h2 className="mt-1 text-lg font-semibold text-slate-100">
              Campaign Types
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Detected campaign categories.
            </p>

          </div>

          <div className="space-y-5">

            {distribution.map(
              (item, index) => {

                const classes = [
                  {
                    className:
                      'bg-red-500',
                    textClass:
                      'text-red-400',
                  },
                  {
                    className:
                      'bg-orange-500',
                    textClass:
                      'text-orange-400',
                  },
                  {
                    className:
                      'bg-yellow-500',
                    textClass:
                      'text-yellow-400',
                  },
                  {
                    className:
                      'bg-cyan-500',
                    textClass:
                      'text-cyan-400',
                  },
                ]

                const style =
                  classes[
                    index %
                      classes.length
                  ]

                return (
                  <DistributionRow
                    key={
                      item.label
                    }
                    label={
                      item.label
                    }
                    value={`${item.value}%`}
                    width={`${item.value}%`}
                    className={
                      style.className
                    }
                    textClass={
                      style.textClass
                    }
                  />
                )
              }
            )}

          </div>

        </div>

      </div>

      {/* =========================================
          CAMPAIGN LIST
      ========================================= */}

      <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">

        <div className="mb-6 flex flex-col justify-between gap-3 md:flex-row md:items-center">

          <div>

            <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
              Correlated Threats
            </p>

            <h2 className="mt-1 text-lg font-semibold text-slate-100">
              Detected Campaigns
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Groups of related suspicious activity identified by the platform.
            </p>

          </div>

          <button
            onClick={() =>
              setSelectedCampaign(
                null
              )
            }
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-xs text-slate-400 transition hover:border-cyan-500/30 hover:text-cyan-400"
          >
            Clear Selection
          </button>

        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">

          <table className="w-full min-w-[950px] text-left">

            <thead className="bg-slate-950">

              <tr>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Campaign
                </th>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Type
                </th>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Risk
                </th>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Emails
                </th>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Domains
                </th>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Source IPs
                </th>

                <th className="px-5 py-4 text-[10px] font-medium uppercase tracking-wider text-slate-600">
                  Status
                </th>

              </tr>

            </thead>

            <tbody className="divide-y divide-slate-800">

              {campaigns.map(
                (campaign) => (

                  <tr
                    key={
                      campaign.id
                    }
                    onClick={() =>
                      handleCampaignSelect(
                        campaign
                      )
                    }
                    className={`cursor-pointer transition hover:bg-slate-950/70 ${
                      selectedCampaign?.id ===
                      campaign.id
                        ? 'bg-cyan-500/5'
                        : ''
                    }`}
                  >

                    <td className="px-5 py-4">

                      <div>

                        <div className="flex items-center gap-2">

                          <p className="text-sm font-medium text-cyan-400">
                            {
                              campaign.name
                            }
                          </p>

                          {campaign.real && (
                            <span className="rounded-md bg-green-500/10 px-2 py-0.5 text-[9px] text-green-400">
                              LIVE
                            </span>
                          )}

                        </div>

                        <p className="mt-1 font-mono text-[10px] text-slate-600">
                          {
                            campaign.id
                          }
                        </p>

                      </div>

                    </td>

                    <td className="px-5 py-4">

                      <span className="rounded-lg bg-slate-800 px-2.5 py-1 text-xs text-slate-400">
                        {
                          campaign.type
                        }
                      </span>

                    </td>

                    <td className="px-5 py-4">

                      <RiskBadge
                        risk={
                          campaign.risk
                        }
                      />

                      <p className="mt-1 text-[10px] text-slate-600">
                        Score{' '}
                        {
                          campaign.score
                        }
                        /100
                      </p>

                    </td>

                    <td className="px-5 py-4 text-sm text-slate-300">
                      {
                        campaign.emails
                      }
                    </td>

                    <td className="px-5 py-4 text-sm text-slate-300">
                      {
                        campaign.domains
                      }
                    </td>

                    <td className="px-5 py-4 text-sm text-slate-300">
                      {
                        campaign.ips
                      }
                    </td>

                    <td className="px-5 py-4">

                      <StatusBadge
                        status={
                          campaign.status
                        }
                      />

                    </td>

                  </tr>

                )
              )}

            </tbody>

          </table>

        </div>

      </div>

      {/* =========================================
          SELECTED CAMPAIGN DETAILS
      ========================================= */}

      {selectedCampaign && (

        <div className="mt-6 rounded-2xl border border-cyan-500/20 bg-slate-900 p-6">

          <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">

            <div>

              <div className="flex items-center gap-3">

                <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                  Campaign Investigation
                </p>

                {selectedCampaign.real && (
                  <span className="rounded-md bg-green-500/10 px-2 py-1 text-[9px] font-medium text-green-400">
                    LIVE BACKEND DATA
                  </span>
                )}

              </div>

              <h2 className="mt-1 text-xl font-semibold text-slate-100">
                {
                  selectedCampaign.name
                }
              </h2>

              <p className="mt-1 font-mono text-xs text-slate-600">
                {
                  selectedCampaign.id
                }
              </p>

            </div>

            <RiskBadge
              risk={
                selectedCampaign.risk
              }
            />

          </div>

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

            <DetailCard
              label="Threat Score"
              value={`${selectedCampaign.score}/100`}
              valueClass="text-red-400"
            />

            <DetailCard
              label="Correlated Emails"
              value={
                selectedCampaign.emails
              }
            />

            <DetailCard
              label="Related Domains"
              value={
                selectedCampaign.domains
              }
              valueClass="text-yellow-400"
            />

            <DetailCard
              label="Source IPs"
              value={
                selectedCampaign.ips
              }
              valueClass="text-cyan-400"
            />

          </div>

          {/* =========================================
              LIVE CORRELATION DATA
          ========================================= */}

          {selectedCampaign.real && (

            <div className="mt-6 rounded-xl border border-green-500/20 bg-green-500/5 p-5">

              <div className="flex items-start gap-3">

                <span className="text-lg">
                  🔗
                </span>

                <div>

                  <p className="text-sm font-medium text-green-400">
                    Live Correlation Evidence
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    This campaign was generated from real investigation records stored in the TraceMail backend.
                  </p>

                </div>

              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">

                <CorrelationList
                  title="Related Domains"
                  items={
                    selectedCampaign.domainsList
                  }
                />

                <CorrelationList
                  title="Related Source IPs"
                  items={
                    selectedCampaign.ipsList
                  }
                />

              </div>

              <div className="mt-4">

                <CorrelationList
                  title="Extracted Indicators"
                  items={
                    selectedCampaign.indicators
                  }
                />

              </div>

            </div>

          )}

          {/* =========================================
              INVESTIGATION RELATIONSHIP GRAPH
          ========================================= */}

          <div className="mt-6 rounded-xl border border-cyan-500/20 bg-slate-950/60 p-5">

            <div className="flex flex-col justify-between gap-3 md:flex-row md:items-start">

              <div>

                <div className="flex items-center gap-2">

                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 text-lg">
                    🕸
                  </span>

                  <div>

                    <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                      Investigation Relationship Graph
                    </p>

                    <h3 className="mt-1 text-sm font-semibold text-slate-200">
                      Correlated Evidence Network
                    </h3>

                  </div>

                </div>

                <p className="mt-3 max-w-3xl text-xs leading-5 text-slate-500">
                  Visual relationship between this campaign and its
                  correlated email cases, sender domains, source IPs
                  and extracted indicators.
                </p>

              </div>

              <span className="rounded-lg border border-green-500/20 bg-green-500/5 px-3 py-1.5 text-[10px] uppercase tracking-wider text-green-400">
                {selectedCampaign.real
                  ? 'LIVE RELATIONSHIPS'
                  : 'DEMO RELATIONSHIPS'}
              </span>

            </div>

            <RelationshipGraph
              campaign={
                selectedCampaign
              }
            />

          </div>

          {/* =========================================
              CAMPAIGN DETAILS
          ========================================= */}

          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">

              <p className="text-xs font-medium uppercase tracking-wider text-yellow-500">
                Investigation Details
              </p>

              <h3 className="mt-1 text-sm font-semibold text-slate-200">
                Campaign Activity
              </h3>

              <div className="mt-6 space-y-4">

                <DetailRow
                  label="First Observed"
                  value={
                    selectedCampaign.firstSeen
                  }
                />

                <DetailRow
                  label="Last Observed"
                  value={
                    selectedCampaign.lastSeen
                  }
                />

                <DetailRow
                  label="Campaign Type"
                  value={
                    selectedCampaign.type
                  }
                />

                <DetailRow
                  label="Current Status"
                  value={
                    selectedCampaign.status
                  }
                />

                <DetailRow
                  label="Correlation Confidence"
                  value={`${selectedCampaign.confidence}%`}
                />

                <DetailRow
                  label="Correlation Method"
                  value={
                    selectedCampaign.real
                      ? 'Domain / IP / Category'
                      : 'Demonstration'
                  }
                />

              </div>

              <div className="mt-6 rounded-xl border border-yellow-500/10 bg-yellow-500/5 p-4">

                <div className="flex gap-3">

                  <span>⚠️</span>

                  <div>

                    <p className="text-xs font-semibold text-yellow-400">
                      Analyst Attention
                    </p>

                    <p className="mt-1 text-xs leading-5 text-slate-500">
                      Correlated indicators suggest this campaign may represent
                      coordinated malicious activity. Correlation should support,
                      not replace, analyst investigation.
                    </p>

                  </div>

                </div>

              </div>

            </div>

            {/* Graph Explanation */}

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">

              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Relationship Intelligence
              </p>

              <h3 className="mt-1 text-sm font-semibold text-slate-200">
                How This Graph Works
              </h3>

              <div className="mt-5 space-y-3">

                <GraphLegend
                  icon="✉"
                  title="Email Cases"
                  description="Investigation records correlated with this campaign."
                  className="border-blue-500/20 bg-blue-500/5"
                />

                <GraphLegend
                  icon="🌐"
                  title="Sender Domains"
                  description="Domains associated with correlated investigations."
                  className="border-yellow-500/20 bg-yellow-500/5"
                />

                <GraphLegend
                  icon="◉"
                  title="Source IPs"
                  description="Infrastructure observed in the investigation records."
                  className="border-cyan-500/20 bg-cyan-500/5"
                />

                <GraphLegend
                  icon="⚠"
                  title="Indicators"
                  description="Extracted forensic signals linked to the campaign."
                  className="border-red-500/20 bg-red-500/5"
                />

              </div>

              <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900 p-4">

                <p className="text-[10px] uppercase tracking-wider text-slate-600">
                  Correlation Logic
                </p>

                <p className="mt-2 text-xs leading-5 text-slate-500">
                  TraceMail correlates investigations using shared
                  sender domains, source IP addresses and threat
                  categories. The graph provides an explainable
                  visual representation of these relationships.
                </p>

              </div>

            </div>

          </div>

          {/* =========================================
              REAL CASES
          ========================================= */}

          {selectedCampaign.real &&
            selectedCampaign.tickets?.length >
              0 && (

              <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/60 p-5">

                <div className="mb-5">

                  <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                    Correlated Investigations
                  </p>

                  <h3 className="mt-1 text-sm font-semibold text-slate-200">
                    Related Cases
                  </h3>

                </div>

                <div className="space-y-3">

                  {selectedCampaign.tickets.map(
                    (
                      ticket,
                      index
                    ) => {

                      const normalized =
                        normalizeTicket(
                          ticket,
                          index
                        )

                      return (
                        <div
                          key={
                            normalized.normalizedId
                          }
                          className="rounded-xl border border-slate-800 bg-slate-900 p-4"
                        >

                          <div className="flex flex-col justify-between gap-3 md:flex-row md:items-center">

                            <div>

                              <p className="text-sm font-medium text-cyan-400">
                                {
                                  normalized.normalizedSubject
                                }
                              </p>

                              <p className="mt-1 font-mono text-[10px] text-slate-600">
                                {
                                  normalized.normalizedId
                                }
                              </p>

                            </div>

                            <div className="flex flex-wrap items-center gap-2">

                              <RiskBadge
                                risk={
                                  getRiskFromScore(
                                    normalized.normalizedScore
                                  )
                                }
                              />

                              <span className="rounded-lg bg-slate-800 px-2.5 py-1 text-[10px] text-slate-400">
                                {
                                  normalized.normalizedCategory
                                }
                              </span>

                            </div>

                          </div>

                          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">

                            <SmallDetail
                              label="Source IP"
                              value={
                                normalized.normalizedIp ||
                                'Unknown'
                              }
                            />

                            <SmallDetail
                              label="Domain"
                              value={
                                normalized.normalizedDomain ||
                                'Unknown'
                              }
                            />

                            <SmallDetail
                              label="Threat Score"
                              value={`${normalized.normalizedScore}/100`}
                            />

                          </div>

                        </div>
                      )
                    }
                  )}

                </div>

              </div>

            )}

        </div>

      )}

      {/* =========================================
          FOOTER
      ========================================= */}

      <div className="mt-8 flex flex-col justify-between gap-2 border-t border-slate-800 pt-5 text-xs text-slate-600 md:flex-row">

        <p>
          TraceMail AI • Campaign Correlation Engine
        </p>

        <p>
          {tickets.length > 0
            ? 'Live backend correlation enabled'
            : 'Demo correlation data active'}
        </p>

      </div>

    </div>
  )
}


/* =========================================
   RELATIONSHIP GRAPH
========================================= */

function RelationshipGraph({
  campaign,
}) {
  const graphData = useMemo(() => {
    const emails =
      campaign.tickets?.length > 0
        ? campaign.tickets
            .map(
              (ticket, index) =>
                normalizeGraphTicket(
                  ticket,
                  index
                )
            )
        : createDemoEmails(
            campaign
          )

    const domains = unique(
      campaign.domainsList ||
        []
    )

    const ips = unique(
      campaign.ipsList ||
        []
    )

    const indicators = unique(
      campaign.indicators ||
        []
    )

    return {
      emails: emails.slice(0, 5),
      domains: domains.slice(0, 4),
      ips: ips.slice(0, 3),
      indicators:
        indicators.slice(0, 5),
    }
  }, [campaign])

  const emailPositions =
    getCircularPositions(
      graphData.emails.length,
      110,
      180,
      180
    )

  const domainPositions =
    getTopPositions(
      graphData.domains.length
    )

  const ipPositions =
    getRightPositions(
      graphData.ips.length
    )

  const indicatorPositions =
    getBottomPositions(
      graphData.indicators.length
    )

  const allNodes = [
    {
      id: 'campaign',
      x: 400,
      y: 180,
      type: 'campaign',
      label: 'CAMPAIGN',
      value: truncate(
        campaign.name,
        20
      ),
    },

    ...graphData.emails.map(
      (email, index) => ({
        id: `email-${index}`,
        ...emailPositions[index],
        type: 'email',
        label: 'EMAIL',
        value: truncate(
          email.subject,
          22
        ),
      })
    ),

    ...graphData.domains.map(
      (domain, index) => ({
        id: `domain-${index}`,
        ...domainPositions[index],
        type: 'domain',
        label: 'DOMAIN',
        value: truncate(
          domain,
          22
        ),
      })
    ),

    ...graphData.ips.map(
      (ip, index) => ({
        id: `ip-${index}`,
        ...ipPositions[index],
        type: 'ip',
        label: 'SOURCE IP',
        value: truncate(
          ip,
          20
        ),
      })
    ),

    ...graphData.indicators.map(
      (indicator, index) => ({
        id: `indicator-${index}`,
        ...indicatorPositions[index],
        type: 'indicator',
        label: 'IOC',
        value: truncate(
          indicator,
          22
        ),
      })
    ),
  ]

  const center =
    allNodes.find(
      (node) =>
        node.id ===
        'campaign'
    )

  return (
    <div className="mt-6">

      {/* Graph Stats */}

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">

        <GraphStat
          label="Email Cases"
          value={
            graphData.emails.length
          }
          icon="✉"
        />

        <GraphStat
          label="Domains"
          value={
            graphData.domains.length
          }
          icon="🌐"
        />

        <GraphStat
          label="Source IPs"
          value={
            graphData.ips.length
          }
          icon="◉"
        />

        <GraphStat
          label="IOCs"
          value={
            graphData.indicators.length
          }
          icon="⚠"
        />

      </div>

      {/* Actual SVG Graph */}

      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950">

        <div className="min-w-[820px]">

          <svg
            viewBox="0 0 800 430"
            className="h-[430px] w-full"
            role="img"
            aria-label="Investigation relationship graph"
          >

            {/* Background */}

            <defs>

              <radialGradient
                id="graphGlow"
                cx="50%"
                cy="42%"
                r="55%"
              >
                <stop
                  offset="0%"
                  stopColor="#22d3ee"
                  stopOpacity="0.10"
                />

                <stop
                  offset="100%"
                  stopColor="#020617"
                  stopOpacity="0"
                />
              </radialGradient>

              <filter
                id="nodeGlow"
              >
                <feGaussianBlur
                  stdDeviation="3"
                  result="blur"
                />

                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

            </defs>

            <rect
              width="800"
              height="430"
              fill="url(#graphGlow)"
            />

            {/* Grid */}

            {Array.from({
              length: 9,
            }).map((_, index) => (
              <line
                key={`vertical-${index}`}
                x1={
                  index * 100
                }
                y1="0"
                x2={
                  index * 100
                }
                y2="430"
                stroke="#1e293b"
                strokeOpacity="0.25"
              />
            ))}

            {Array.from({
              length: 6,
            }).map((_, index) => (
              <line
                key={`horizontal-${index}`}
                x1="0"
                y1={
                  index * 86
                }
                x2="800"
                y2={
                  index * 86
                }
                stroke="#1e293b"
                strokeOpacity="0.25"
              />
            ))}

            {/* Connection Lines */}

            {allNodes
              .filter(
                (node) =>
                  node.id !==
                  'campaign'
              )
              .map((node) => (
                <line
                  key={`line-${node.id}`}
                  x1={center.x}
                  y1={center.y}
                  x2={node.x}
                  y2={node.y}
                  stroke={
                    getNodeColor(
                      node.type
                    )
                  }
                  strokeOpacity="0.38"
                  strokeWidth="1.5"
                />
              ))}

            {/* Connection Dots */}

            {allNodes
              .filter(
                (node) =>
                  node.id !==
                  'campaign'
              )
              .map((node) => (
                <circle
                  key={`dot-${node.id}`}
                  cx={
                    center.x +
                    (node.x -
                      center.x) *
                      0.72
                  }
                  cy={
                    center.y +
                    (node.y -
                      center.y) *
                      0.72
                  }
                  r="3"
                  fill={getNodeColor(
                    node.type
                  )}
                  opacity="0.75"
                />
              ))}

            {/* Nodes */}

            {allNodes.map(
              (node) => (
                <GraphNode
                  key={
                    node.id
                  }
                  node={node}
                />
              )
            )}

          </svg>

        </div>

      </div>

      {/* Relationship explanation */}

      <div className="mt-4 flex flex-wrap items-center gap-3">

        <RelationshipPill
          color="bg-cyan-400"
          label="Campaign"
        />

        <RelationshipPill
          color="bg-blue-400"
          label="Email"
        />

        <RelationshipPill
          color="bg-yellow-400"
          label="Domain"
        />

        <RelationshipPill
          color="bg-purple-400"
          label="Source IP"
        />

        <RelationshipPill
          color="bg-red-400"
          label="IOC"
        />

      </div>

      <p className="mt-3 text-[10px] leading-5 text-slate-600">
        Showing the most relevant correlated nodes for readability.
        Counts above represent the complete campaign relationship set.
      </p>

    </div>
  )
}


/* =========================================
   GRAPH NODE
========================================= */

function GraphNode({
  node,
}) {
  const color =
    getNodeColor(
      node.type
    )

  const isCenter =
    node.type ===
    'campaign'

  const radius =
    isCenter ? 43 : 30

  return (
    <g
      transform={`translate(${node.x}, ${node.y})`}
      filter={
        isCenter
          ? 'url(#nodeGlow)'
          : undefined
      }
    >

      {/* Outer ring */}

      <circle
        r={radius + 7}
        fill="none"
        stroke={color}
        strokeOpacity={
          isCenter
            ? '0.18'
            : '0.10'
        }
        strokeWidth="1"
      />

      {/* Node */}

      <circle
        r={radius}
        fill="#0f172a"
        stroke={color}
        strokeOpacity={
          isCenter
            ? '0.75'
            : '0.45'
        }
        strokeWidth={
          isCenter ? 2 : 1.5
        }
      />

      {/* Inner */}

      <circle
        r={
          isCenter
            ? 34
            : 22
        }
        fill={color}
        fillOpacity={
          isCenter
            ? '0.10'
            : '0.06'
        }
      />

      {/* Icon */}

      <text
        textAnchor="middle"
        dominantBaseline="middle"
        y={
          isCenter
            ? -4
            : -2
        }
        fontSize={
          isCenter ? 20 : 15
        }
      >
        {getNodeIcon(
          node.type
        )}
      </text>

      {/* Label */}

      <text
        textAnchor="middle"
        y={
          isCenter
            ? 15
            : 12
        }
        fill="#94a3b8"
        fontSize={
          isCenter ? 8 : 7
        }
        fontWeight="600"
        letterSpacing="1"
      >
        {node.label}
      </text>

      {/* External value */}

      <g>

        <rect
          x={
            isCenter
              ? -90
              : -78
          }
          y={
            radius + 12
          }
          width={
            isCenter
              ? 180
              : 156
          }
          height="30"
          rx="6"
          fill="#0f172a"
          stroke="#1e293b"
        />

        <text
          textAnchor="middle"
          y={
            radius + 31
          }
          fill={
            isCenter
              ? '#22d3ee'
              : '#cbd5e1'
          }
          fontSize="9"
          fontFamily="monospace"
        >
          {node.value}
        </text>

      </g>

    </g>
  )
}


/* =========================================
   GRAPH POSITION HELPERS
========================================= */

function getCircularPositions(
  count,
  radius,
  centerX,
  centerY
) {
  if (count === 0) {
    return []
  }

  return Array.from(
    { length: count },
    (_, index) => {
      const angle =
        (-Math.PI / 2) +
        (Math.PI * 2 * index) /
          count

      return {
        x:
          centerX +
          Math.cos(angle) *
            radius,
        y:
          centerY +
          Math.sin(angle) *
            radius,
      }
    }
  )
}


function getTopPositions(
  count
) {
  const positions = [
    { x: 180, y: 62 },
    { x: 320, y: 48 },
    { x: 480, y: 48 },
    { x: 620, y: 62 },
  ]

  return positions.slice(
    0,
    count
  )
}


function getRightPositions(
  count
) {
  const positions = [
    { x: 650, y: 150 },
    { x: 680, y: 240 },
    { x: 610, y: 330 },
  ]

  return positions.slice(
    0,
    count
  )
}


function getBottomPositions(
  count
) {
  const positions = [
    { x: 180, y: 350 },
    { x: 320, y: 382 },
    { x: 480, y: 382 },
    { x: 620, y: 350 },
    { x: 400, y: 400 },
  ]

  return positions.slice(
    0,
    count
  )
}


function normalizeGraphTicket(
  ticket,
  index
) {
  return {
    id:
      ticket.ticketId ||
      ticket.caseId ||
      ticket._id ||
      `CASE-${index + 1}`,

    subject:
      ticket.subject ||
      'Suspicious Email',
  }
}


function createDemoEmails(
  campaign
) {
  const count =
    Math.min(
      Number(
        campaign.emails || 0
      ),
      5
    )

  return Array.from(
    {
      length:
        Math.max(
          count,
          1
        ),
    },
    (_, index) => ({
      id: `DEMO-${index + 1}`,
      subject:
        index === 0
          ? campaign.name
          : `${campaign.type} Investigation ${index + 1}`,
    })
  )
}


/* =========================================
   GRAPH UI HELPERS
========================================= */

function getNodeColor(
  type
) {
  const colors = {
    campaign: '#22d3ee',
    email: '#60a5fa',
    domain: '#facc15',
    ip: '#c084fc',
    indicator: '#f87171',
  }

  return (
    colors[type] ||
    '#94a3b8'
  )
}


function getNodeIcon(
  type
) {
  const icons = {
    campaign: '🕸',
    email: '✉',
    domain: '🌐',
    ip: '◉',
    indicator: '⚠',
  }

  return (
    icons[type] ||
    '•'
  )
}


function truncate(
  value,
  maxLength
) {
  const text =
    String(value || '')

  if (
    text.length <=
    maxLength
  ) {
    return text
  }

  return `${text.slice(
    0,
    maxLength - 3
  )}...`
}


function GraphStat({
  label,
  value,
  icon,
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">

      <div className="flex items-center justify-between">

        <p className="text-[9px] uppercase tracking-wider text-slate-600">
          {label}
        </p>

        <span className="text-sm">
          {icon}
        </span>

      </div>

      <p className="mt-2 text-lg font-bold text-slate-200">
        {value}
      </p>

    </div>
  )
}


function RelationshipPill({
  color,
  label,
}) {
  return (
    <span className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] text-slate-500">

      <span
        className={`h-2 w-2 rounded-full ${color}`}
      />

      {label}

    </span>
  )
}


function GraphLegend({
  icon,
  title,
  description,
  className,
}) {
  return (
    <div
      className={`rounded-xl border p-3 ${className}`}
    >

      <div className="flex items-start gap-3">

        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-950 text-sm">
          {icon}
        </span>

        <div>

          <p className="text-xs font-medium text-slate-300">
            {title}
          </p>

          <p className="mt-1 text-[10px] leading-4 text-slate-600">
            {description}
          </p>

        </div>

      </div>

    </div>
  )
}


/* =========================================
   GENERAL HELPERS
========================================= */

function unique(values) {
  return [
    ...new Set(
      values.filter(
        (value) =>
          value &&
          String(value).trim()
      )
    ),
  ]
}


function extractDomain(value) {
  const text = String(
    value || ''
  )

  const match =
    text.match(
      /@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/
    )

  return match
    ? match[1].toLowerCase()
    : ''
}


function getCampaignType(
  categories
) {
  const text =
    categories
      .join(' ')
      .toLowerCase()

  if (
    text.includes('credential') ||
    text.includes('password') ||
    text.includes('account')
  ) {
    return 'Credential Theft'
  }

  if (
    text.includes('bec') ||
    text.includes('business') ||
    text.includes('fraud') ||
    text.includes('payment') ||
    text.includes('finance')
  ) {
    return 'BEC / Fraud'
  }

  if (
    text.includes('phishing')
  ) {
    return 'Phishing'
  }

  if (
    text.includes('malware')
  ) {
    return 'Malware'
  }

  return (
    categories[0] ||
    'Suspicious'
  )
}


function getRiskFromScore(
  score
) {
  if (score >= 85) {
    return 'Critical'
  }

  if (score >= 70) {
    return 'High'
  }

  if (score >= 45) {
    return 'Medium'
  }

  return 'Low'
}


function buildCampaignName(
  category,
  domains,
  tickets
) {
  if (
    domains.length > 0
  ) {
    const domain =
      domains[0]

    if (
      domain.includes(
        'micros0ft'
      ) ||
      domain.includes(
        'microsoft'
      )
    ) {
      return 'Microsoft Account Phishing'
    }

    if (
      domain.includes(
        'finance'
      ) ||
      domain.includes(
        'invoice'
      )
    ) {
      return 'Finance / Payment Fraud'
    }

    return `${category} — ${domain}`
  }

  if (
    tickets.length > 0
  ) {
    return `${category} Campaign`
  }

  return 'Suspicious Email Campaign'
}


function formatDate(
  date
) {
  try {
    return date.toLocaleString(
      'en-IN',
      {
        day: '2-digit',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit',
      }
    )
  } catch {
    return 'Recently'
  }
}


/* =========================================
   STAT CARD
========================================= */

function StatCard({
  label,
  value,
  subtitle,
  icon,
  valueClass,
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">

      <div className="flex items-start justify-between">

        <p className="text-xs uppercase tracking-wider text-slate-600">
          {label}
        </p>

        <span className="rounded-lg bg-slate-950 px-2 py-1 text-sm">
          {icon}
        </span>

      </div>

      <p
        className={`mt-3 text-3xl font-bold ${valueClass}`}
      >
        {value}
      </p>

      <p className="mt-2 text-xs text-slate-600">
        {subtitle}
      </p>

    </div>
  )
}


/* =========================================
   METRIC
========================================= */

function Metric({
  label,
  value,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-2 text-xl font-bold text-slate-200">
        {value}
      </p>

    </div>
  )
}


/* =========================================
   DISTRIBUTION ROW
========================================= */

function DistributionRow({
  label,
  value,
  width,
  className,
  textClass,
}) {
  return (
    <div>

      <div className="mb-2 flex items-center justify-between">

        <span className="text-sm text-slate-400">
          {label}
        </span>

        <span
          className={`text-xs font-medium ${textClass}`}
        >
          {value}
        </span>

      </div>

      <div className="h-2 overflow-hidden rounded-full bg-slate-800">

        <div
          className={`h-full rounded-full ${className}`}
          style={{
            width,
          }}
        ></div>

      </div>

    </div>
  )
}


/* =========================================
   RISK BADGE
========================================= */

function RiskBadge({
  risk,
}) {
  const styles = {
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
      className={`inline-flex rounded-lg border px-2.5 py-1 text-[10px] font-medium ${
        styles[risk] ||
        'bg-slate-800 text-slate-400 border-slate-700'
      }`}
    >
      {risk}
    </span>
  )
}


/* =========================================
   STATUS BADGE
========================================= */

function StatusBadge({
  status,
}) {
  const isActive =
    status === 'Active'

  return (
    <span
      className={`inline-flex items-center gap-2 text-xs ${
        isActive
          ? 'text-green-400'
          : 'text-yellow-400'
      }`}
    >

      <span
        className={`h-1.5 w-1.5 rounded-full ${
          isActive
            ? 'bg-green-400'
            : 'bg-yellow-400'
        }`}
      />

      {status}

    </span>
  )
}


/* =========================================
   DETAIL CARD
========================================= */

function DetailCard({
  label,
  value,
  valueClass = 'text-slate-200',
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p
        className={`mt-2 text-xl font-bold ${valueClass}`}
      >
        {value}
      </p>

    </div>
  )
}


/* =========================================
   DETAIL ROW
========================================= */

function DetailRow({
  label,
  value,
}) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 pb-3">

      <span className="text-sm text-slate-500">
        {label}
      </span>

      <span className="text-right text-sm font-medium text-slate-300">
        {value}
      </span>

    </div>
  )
}


/* =========================================
   CORRELATION LIST
========================================= */

function CorrelationList({
  title,
  items,
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">

      <p className="text-xs font-medium uppercase tracking-wider text-slate-600">
        {title}
      </p>

      {items?.length > 0 ? (

        <div className="mt-3 flex flex-wrap gap-2">

          {items.map(
            (item, index) => (

              <span
                key={`${item}-${index}`}
                className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 font-mono text-[10px] text-cyan-400"
              >
                {item}
              </span>

            )
          )}

        </div>

      ) : (

        <p className="mt-3 text-xs text-slate-600">
          No correlated data available.
        </p>

      )}

    </div>
  )
}


/* =========================================
   SMALL DETAIL
========================================= */

function SmallDetail({
  label,
  value,
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">

      <p className="text-[9px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-1 break-all font-mono text-xs text-slate-300">
        {value}
      </p>

    </div>
  )
}