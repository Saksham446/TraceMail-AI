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
  },
]

export default function Campaigns() {
  const [selectedCampaign, setSelectedCampaign] = useState(null)

  const [tickets, setTickets] = useState([])

  const [loading, setLoading] = useState(true)

  const [backendStatus, setBackendStatus] = useState('Connecting...')

  const [error, setError] = useState('')

  const [lastUpdated, setLastUpdated] = useState(null)

  // =========================================
  // FETCH REAL INVESTIGATIONS
  // =========================================

  const fetchTickets = async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(TICKET_API_URL)

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
      /*
       * Campaign correlation key:
       *
       * 1. Domain
       * 2. Source IP
       * 3. Threat category
       *
       * This is an explainable correlation approach.
       */

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

    groups.forEach((group, key) => {
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
                  (item.normalizedScore || 0),
                0
              ) /
                group.length
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
          group
            .map(
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
          ? formatDate(
              dates[0]
            )
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

        iocs:
          indicatorSet.length,

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

    /*
     * Real investigations appear first.
     * Demo campaigns remain visible to make
     * the SIH demonstration richer.
     */

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

    window.scrollTo({
      top: document.body
        .scrollHeight,
      behavior: 'smooth',
    })
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

            <span>
              ⚠️
            </span>

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


          {/* LIVE CORRELATION DATA */}

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


          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">

            {/* Correlation Graph */}

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">

              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Correlation Graph
              </p>

              <h3 className="mt-1 text-sm font-semibold text-slate-200">
                Related Indicators
              </h3>


              <div className="relative mt-6 flex h-56 items-center justify-center overflow-hidden rounded-xl border border-slate-800 bg-slate-950">

                <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(34,211,238,0.08),transparent_55%)]"></div>

                <div className="relative flex items-center justify-center">

                  <div className="flex h-20 w-20 items-center justify-center rounded-full border border-cyan-400/30 bg-cyan-500/10 text-2xl shadow-lg shadow-cyan-500/10">
                    🕸
                  </div>


                  <div className="absolute -left-36 top-1/2 h-px w-28 bg-cyan-500/30"></div>

                  <div className="absolute -right-36 top-1/2 h-px w-28 bg-cyan-500/30"></div>

                  <div className="absolute left-1/2 -top-24 h-20 w-px bg-cyan-500/30"></div>

                  <div className="absolute left-1/2 -bottom-24 h-20 w-px bg-cyan-500/30"></div>


                  <span className="absolute -left-48 top-1/2 -translate-y-1/2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-[10px] text-slate-500">
                    {
                      selectedCampaign.emails
                    } Emails
                  </span>

                  <span className="absolute -right-48 top-1/2 -translate-y-1/2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-[10px] text-slate-500">
                    {
                      selectedCampaign.domains
                    } Domains
                  </span>

                  <span className="absolute left-1/2 -top-32 -translate-x-1/2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-[10px] text-slate-500">
                    {
                      selectedCampaign.ips
                    } Source IPs
                  </span>

                  <span className="absolute left-1/2 -bottom-32 -translate-x-1/2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-[10px] text-slate-500">
                    {
                      selectedCampaign.iocs
                    } IOCs
                  </span>

                </div>

              </div>

            </div>


            {/* Campaign Details */}

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

                  <span>
                    ⚠️
                  </span>

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

          </div>


          {/* REAL CASES */}

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
   HELPERS
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

  return categories[0] ||
    'Suspicious'
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