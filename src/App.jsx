import { useEffect, useMemo, useState } from 'react'
import {
  Routes,
  Route,
  NavLink,
  Navigate,
  useNavigate,
  useLocation,
} from 'react-router-dom'

import Login from './pages/Login'
import AnalyzeEmail from './pages/AnalyzeEmail'
import HeaderForensics from './pages/HeaderForensics'
import Campaigns from './pages/Campaigns'
import GeoIntelligence from './pages/GeoIntelligence'
import Cases from './pages/Cases'
import Reports from './pages/Reports'

const TICKET_API_URL = 'http://localhost:5001/api/tickets'


/* =========================================
   AUTH HELPERS
========================================= */

function getStoredUser() {

  try {

    return JSON.parse(
      localStorage.getItem('tracemail_user')
    )

  } catch {

    return null

  }

}


/* =========================================
   SIDEBAR
========================================= */

function Sidebar() {

  const navigate = useNavigate()

  const [user, setUser] = useState(getStoredUser())


  useEffect(() => {

    const handleAuthChange = () => {

      setUser(getStoredUser())

    }


    window.addEventListener(
      'tracemail-auth-change',
      handleAuthChange
    )


    return () => {

      window.removeEventListener(
        'tracemail-auth-change',
        handleAuthChange
      )

    }

  }, [])


  const role = user?.role || 'Viewer'


  const allNavItems = [

    {
      label: 'Dashboard',
      icon: '◉',
      path: '/',
      roles: ['Admin', 'Analyst', 'Viewer'],
    },

    {
      label: 'Analyze Email',
      icon: '✉',
      path: '/analyze',
      roles: ['Admin', 'Analyst'],
    },

    {
      label: 'Header Forensics',
      icon: '🔍',
      path: '/forensics',
      roles: ['Admin', 'Analyst'],
    },

    {
      label: 'Geo Intelligence',
      icon: '🌍',
      path: '/geo',
      roles: ['Admin', 'Analyst'],
    },

    {
      label: 'Campaigns',
      icon: '🕸',
      path: '/campaigns',
      roles: ['Admin', 'Analyst'],
    },

    {
      label: 'Cases',
      icon: '📁',
      path: '/cases',
      roles: ['Admin', 'Analyst', 'Viewer'],
    },

    {
      label: 'Reports',
      icon: '📄',
      path: '/reports',
      roles: ['Admin', 'Analyst', 'Viewer'],
    },

  ]


  const navItems = allNavItems.filter(
    (item) =>
      item.roles.includes(role)
  )


  const handleLogout = () => {

    localStorage.removeItem(
      'tracemail_auth_token'
    )

    localStorage.removeItem(
      'tracemail_user'
    )

    window.dispatchEvent(
      new Event('tracemail-auth-change')
    )

    navigate('/login', {
      replace: true,
    })

  }


  return (

    <aside className="fixed left-0 top-0 z-20 h-screen w-64 border-r border-slate-800 bg-slate-900/95 p-5">

      {/* LOGO */}

      <div className="mb-8">

        <NavLink
          to="/"
          className="flex items-center gap-3"
        >

          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-xl">
            🛡️
          </div>

          <div>

            <h1 className="text-lg font-bold text-cyan-400">
              TraceMail AI
            </h1>

            <p className="text-xs text-slate-500">
              Email Forensics Platform
            </p>

          </div>

        </NavLink>

      </div>


      {/* NAVIGATION */}

      <div className="mb-3 px-2">

        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">
          Investigation
        </p>

      </div>


      <nav className="space-y-1">

        {navItems.map((item) => (

          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) =>
              `group flex w-full items-center rounded-lg px-4 py-3 text-sm transition ${
                isActive
                  ? 'border border-cyan-500/10 bg-cyan-500/10 font-medium text-cyan-400'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
              }`
            }
          >

            <span className="mr-3 text-base">
              {item.icon}
            </span>

            {item.label}

          </NavLink>

        ))}

      </nav>


      {/* USER / SYSTEM STATUS */}

      <div className="absolute bottom-5 left-5 right-5">

        <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">

          {/* USER */}

          <div className="mb-3 flex items-center gap-3">

            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-sm font-semibold text-cyan-400">

              {user?.name
                ?.charAt(0)
                ?.toUpperCase() || 'U'}

            </div>

            <div className="min-w-0">

              <p className="truncate text-xs font-medium text-slate-300">
                {user?.name || 'User'}
              </p>

              <p className="text-[10px] font-medium text-cyan-400">
                {role}
              </p>

            </div>

          </div>


          {/* SYSTEM */}

          <div className="mb-3 border-t border-slate-800 pt-3">

            <div className="mb-2 flex items-center gap-2">

              <span className="relative flex h-2 w-2">

                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-50"></span>

                <span className="relative inline-flex h-2 w-2 rounded-full bg-green-400"></span>

              </span>

              <span className="text-xs font-medium text-slate-300">
                System Operational
              </span>

            </div>

            <p className="text-[10px] leading-4 text-slate-600">
              Threat intelligence engine ready
            </p>

          </div>


          {/* LOGOUT */}

          <button
            onClick={handleLogout}
            className="w-full rounded-lg border border-slate-800 px-3 py-2 text-xs font-medium text-slate-500 transition hover:border-red-500/20 hover:bg-red-500/5 hover:text-red-400"
          >
            Sign Out
          </button>

        </div>

      </div>

    </aside>

  )

}


/* =========================================
   PROTECTED ROUTE
========================================= */

function ProtectedRoute({
  children,
  allowedRoles = [
    'Admin',
    'Analyst',
    'Viewer',
  ],
}) {

  const token = localStorage.getItem(
    'tracemail_auth_token'
  )

  const userData = localStorage.getItem(
    'tracemail_user'
  )


  if (!token || !userData) {

    return (
      <Navigate
        to="/login"
        replace
      />
    )

  }


  let user = null


  try {

    user = JSON.parse(userData)

  } catch {

    localStorage.removeItem(
      'tracemail_auth_token'
    )

    localStorage.removeItem(
      'tracemail_user'
    )

    return (
      <Navigate
        to="/login"
        replace
      />
    )

  }


  if (!user?.role) {

    return (
      <Navigate
        to="/login"
        replace
      />
    )

  }


  if (!allowedRoles.includes(user.role)) {

    return (

      <div className="min-h-screen bg-slate-950 p-8">

        <div className="max-w-2xl rounded-xl border border-red-500/20 bg-slate-900 p-8">

          <p className="text-xs font-medium uppercase tracking-wider text-red-400">
            Access Control
          </p>

          <h2 className="mt-2 text-2xl font-bold text-slate-100">
            Access Denied
          </h2>

          <p className="mt-3 text-sm leading-6 text-slate-500">
            Your current role does not have permission
            to access this investigation module.
          </p>

          <div className="mt-5 rounded-lg border border-slate-800 bg-slate-950 p-4">

            <p className="text-xs text-slate-600">
              Current Role
            </p>

            <p className="mt-1 text-sm font-semibold text-cyan-400">
              {user.role}
            </p>

          </div>

        </div>

      </div>

    )

  }


  return children

}


/* =========================================
   DASHBOARD
========================================= */

function Dashboard() {

  const navigate = useNavigate()

  const currentUser = getStoredUser()

  const canAnalyze =
    currentUser?.role === 'Admin' ||
    currentUser?.role === 'Analyst'


  const [tickets, setTickets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')


  /* =========================================
     FETCH REAL CASE DATA
  ========================================= */

  useEffect(() => {

    const fetchTickets = async () => {

      try {

        setLoading(true)
        setError('')

        const token = localStorage.getItem(
          'tracemail_auth_token'
        )

        const response = await fetch(
          TICKET_API_URL,
          {
            headers: {
              ...(token
                ? {
                    Authorization: `Bearer ${token}`,
                  }
                : {}),
            },
          }
        )

        if (!response.ok) {

          throw new Error(
            `Backend returned ${response.status}`
          )

        }

        const data =
          await response.json()


        const ticketList =
          Array.isArray(data)
            ? data
            : Array.isArray(data.tickets)
              ? data.tickets
              : Array.isArray(data.data)
                ? data.data
                : []


        setTickets(ticketList)

      } catch (err) {

        console.error(
          'Dashboard ticket fetch error:',
          err
        )

        setError(
          'Unable to load live investigation statistics from the backend.'
        )

        setTickets([])

      } finally {

        setLoading(false)

      }

    }


    fetchTickets()

  }, [])


  /* =========================================
     REAL DASHBOARD STATISTICS
  ========================================= */

  const statistics = useMemo(() => {

    const total =
      tickets.length


    const critical =
      tickets.filter(
        (ticket) =>
          ticket.priority === 'Critical'
      ).length


    const high =
      tickets.filter(
        (ticket) =>
          ticket.priority === 'High'
      ).length


    const medium =
      tickets.filter(
        (ticket) =>
          ticket.priority === 'Medium'
      ).length


    const low =
      tickets.filter(
        (ticket) =>
          ticket.priority === 'Low'
      ).length


    const open =
      tickets.filter(
        (ticket) =>
          ticket.status === 'Open'
      ).length


    const investigating =
      tickets.filter(
        (ticket) =>
          ticket.status === 'Investigating'
      ).length


    const resolved =
      tickets.filter(
        (ticket) =>
          ticket.status === 'Resolved'
      ).length


    const activeCases =
      open + investigating


    const threatsDetected =
      tickets.filter(
        (ticket) =>
          Number(
            ticket.threatScore || 0
          ) >= 70 ||
          ticket.priority === 'High' ||
          ticket.priority === 'Critical'
      ).length


    const suspiciousDomains =
      new Set(
        tickets
          .map(
            (ticket) =>
              String(
                ticket.domain || ''
              )
                .trim()
                .toLowerCase()
          )
          .filter(Boolean)
      ).size


    const indicatorCount =
      tickets.reduce(
        (
          totalIndicators,
          ticket
        ) =>
          totalIndicators +
          (
            Array.isArray(
              ticket.indicators
            )
              ? ticket.indicators.length
              : 0
          ),
        0
      )


    const categoryCounts = {}


    tickets.forEach((ticket) => {

      const category =
        ticket.category || 'Other'


      categoryCounts[category] =
        (
          categoryCounts[category] ||
          0
        ) + 1

    })


    const getCategoryCount =
      (...names) => {

        return names.reduce(
          (sum, name) =>
            sum +
            (
              categoryCounts[name] ||
              0
            ),
          0
        )

      }


    const phishingCount =
      getCategoryCount('Phishing')


    const impersonationCount =
      getCategoryCount(
        'Impersonation'
      )


    const becCount =
      getCategoryCount(
        'BEC / Fraud'
      )


    const credentialCount =
      getCategoryCount(
        'Credential Theft'
      )


    const otherCount =
      Math.max(
        total -
        phishingCount -
        impersonationCount -
        becCount -
        credentialCount,
        0
      )


    const percentage =
      (count) => {

        if (!total) return 0

        return Math.round(
          (count / total) * 100
        )

      }


    const scores =
      tickets
        .map(
          (ticket) =>
            Number(
              ticket.threatScore
            )
        )
        .filter(
          (score) =>
            Number.isFinite(score)
        )


    const averageThreatScore =
      scores.length
        ? Math.round(
            scores.reduce(
              (sum, score) =>
                sum + score,
              0
            ) / scores.length
          )
        : 0


    const detectionRate =
      total
        ? Math.round(
            (
              threatsDetected /
              total
            ) * 1000
          ) / 10
        : 0


    let riskLevel = 'Low'


    if (
      averageThreatScore >= 70
    ) {

      riskLevel = 'Critical'

    } else if (
      averageThreatScore >= 50
    ) {

      riskLevel = 'Elevated'

    } else if (
      averageThreatScore >= 30
    ) {

      riskLevel = 'Moderate'

    }


    const campaignKeys =
      new Set()


    tickets.forEach((ticket) => {

      const domain =
        String(
          ticket.domain || ''
        )
          .trim()
          .toLowerCase()


      const sourceIp =
        String(
          ticket.sourceIp || ''
        ).trim()


      if (domain) {

        campaignKeys.add(
          `domain:${domain}`
        )

      } else if (sourceIp) {

        campaignKeys.add(
          `ip:${sourceIp}`
        )

      }

    })


    const automaticCases =
      tickets.filter(
        (ticket) =>
          ticket.autoCreated === true ||
          ticket.caseType === 'Automatic'
      ).length


    return {

      total,
      threatsDetected,
      suspiciousDomains,
      activeCases,

      critical,
      high,
      medium,
      low,

      open,
      investigating,
      resolved,

      indicatorCount,

      phishingCount,
      impersonationCount,
      becCount,
      credentialCount,
      otherCount,

      phishingPercentage:
        percentage(
          phishingCount
        ),

      impersonationPercentage:
        percentage(
          impersonationCount
        ),

      becPercentage:
        percentage(
          becCount
        ),

      credentialPercentage:
        percentage(
          credentialCount
        ),

      otherPercentage:
        percentage(
          otherCount
        ),

      averageThreatScore,
      detectionRate,
      riskLevel,

      campaignCount:
        campaignKeys.size,

      automaticCases,

    }

  }, [tickets])


  /* =========================================
     RECENT CASES
  ========================================= */

  const recentTickets =
    useMemo(() => {

      return [...tickets]
        .sort((a, b) => {

          const dateA =
            new Date(
              a.createdAt ||
              a.updatedAt ||
              0
            ).getTime()


          const dateB =
            new Date(
              b.createdAt ||
              b.updatedAt ||
              0
            ).getTime()


          return dateB - dateA

        })
        .slice(0, 5)

    }, [tickets])


  /* =========================================
     CATEGORY DISPLAY
  ========================================= */

  const classificationInfo =
    (category) => {

      switch (category) {

        case 'Phishing':

          return {
            label: 'Phishing',
            className:
              'bg-red-500/10 text-red-400'
          }


        case 'BEC / Fraud':

          return {
            label: 'BEC / Fraud',
            className:
              'bg-orange-500/10 text-orange-400'
          }


        case 'Credential Theft':

          return {
            label: 'Credential Theft',
            className:
              'bg-red-500/10 text-red-400'
          }


        case 'Malware':

          return {
            label: 'Malware',
            className:
              'bg-purple-500/10 text-purple-400'
          }


        case 'Spam':

          return {
            label: 'Spam',
            className:
              'bg-slate-500/10 text-slate-400'
          }


        case 'Suspicious':

          return {
            label: 'Suspicious',
            className:
              'bg-yellow-500/10 text-yellow-400'
          }


        default:

          return {
            label:
              category || 'Other',
            className:
              'bg-cyan-500/10 text-cyan-400'
          }

      }

    }


  /* =========================================
     RISK DISPLAY
========================================= */

  const getRiskColor =
    (score) => {

      const value =
        Number(score || 0)


      if (value >= 80) {

        return 'text-red-400'

      }


      if (value >= 60) {

        return 'text-orange-400'

      }


      if (value >= 40) {

        return 'text-yellow-400'

      }


      return 'text-green-400'

    }


  /* =========================================
     STATUS DISPLAY
========================================= */

  const getStatusColor =
    (status) => {

      if (status === 'Open') {

        return 'text-cyan-400'

      }


      if (status === 'Resolved') {

        return 'text-green-400'

      }


      return 'text-yellow-400'

    }


  return (

    <>

      {/* TOP HEADER */}

      <header className="sticky top-0 z-10 flex h-20 items-center justify-between border-b border-slate-800 bg-slate-950/95 px-8 backdrop-blur">

        <div>

          <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
            Security Operations Center
          </p>

          <h2 className="mt-1 text-xl font-semibold text-slate-100">
            Threat Intelligence Dashboard
          </h2>

        </div>


        <div className="flex items-center gap-4">

          <div className="rounded-lg border border-slate-800 bg-slate-900 px-4 py-2">

            <span className="text-[10px] uppercase tracking-wider text-slate-600">
              Environment
            </span>

            <p className="mt-0.5 text-sm font-medium text-green-400">
              ● Secure
            </p>

          </div>


          <div className="flex h-10 w-10 items-center justify-center rounded-full border border-slate-700 bg-slate-800 text-sm font-semibold text-slate-300">

            {currentUser
              ?.name
              ?.charAt(0)
              ?.toUpperCase() || 'U'}

          </div>

        </div>

      </header>


      {/* DASHBOARD CONTENT */}

      <section className="p-8">


        {/* WELCOME */}

        <div className="mb-8">

          <div className="flex items-end justify-between">

            <div>

              <p className="text-sm font-medium text-cyan-400">
                OVERVIEW
              </p>

              <h3 className="mt-2 text-2xl font-bold text-slate-100">
                Email Threat Overview
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Monitor, analyze and investigate suspicious email activity.
              </p>

            </div>


            {/* ONLY ADMIN / ANALYST */}

            {canAnalyze && (

              <button
                onClick={() =>
                  navigate('/analyze')
                }
                className="rounded-lg bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                + Analyze Email
              </button>

            )}

          </div>

        </div>


        {/* BACKEND STATUS */}

        {error && (

          <div className="mb-5 rounded-xl border border-red-500/20 bg-red-500/5 p-4">

            <div className="flex items-center justify-between">

              <div>

                <p className="text-sm font-semibold text-red-400">
                  Live Statistics Unavailable
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  {error}
                </p>

              </div>

              <span className="rounded-full bg-red-500/10 px-3 py-1 text-[10px] font-medium text-red-400">
                BACKEND OFFLINE
              </span>

            </div>

          </div>

        )}


        {/* LIVE DATA BADGE */}

        <div className="mb-5 flex items-center justify-between">

          <div className="flex items-center gap-2">

            <span className="relative flex h-2.5 w-2.5">

              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-50"></span>

              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-400"></span>

            </span>

            <span className="text-xs font-medium text-green-400">
              LIVE DATABASE STATISTICS
            </span>

          </div>

          <span className="text-[10px] text-slate-600">

            {loading
              ? 'Synchronizing...'
              : `${statistics.total} investigations loaded`}

          </span>

        </div>


        {/* STATISTICS */}

        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">

          <DashboardStatCard
            label="Emails Analyzed"
            value={
              loading
                ? '...'
                : statistics.total
            }
            icon="✉"
            iconClass="bg-cyan-500/10 text-cyan-400"
            borderClass="border-slate-800 hover:border-slate-700"
            trend="LIVE"
            trendClass="text-green-400"
            description="database records"
          />


          <DashboardStatCard
            label="Threats Detected"
            value={
              loading
                ? '...'
                : statistics.threatsDetected
            }
            icon="⚠"
            iconClass="bg-red-500/10 text-red-400"
            borderClass="border-red-500/10 hover:border-red-500/20"
            valueClass="text-red-400"
            trend="≥70 risk"
            trendClass="text-red-400"
            description="high-risk cases"
          />


          <DashboardStatCard
            label="Suspicious Domains"
            value={
              loading
                ? '...'
                : statistics.suspiciousDomains
            }
            icon="◈"
            iconClass="bg-yellow-500/10 text-yellow-400"
            borderClass="border-yellow-500/10 hover:border-yellow-500/20"
            valueClass="text-yellow-400"
            trend="UNIQUE"
            trendClass="text-yellow-400"
            description="domains observed"
          />


          <DashboardStatCard
            label="Active Cases"
            value={
              loading
                ? '...'
                : statistics.activeCases
            }
            icon="📁"
            iconClass="bg-cyan-500/10 text-cyan-400"
            borderClass="border-cyan-500/10 hover:border-cyan-500/20"
            valueClass="text-cyan-400"
            trend={`${statistics.open} open`}
            trendClass="text-cyan-400"
            description={`${statistics.investigating} investigating`}
          />

        </div>


        {/* =========================================
            THREAT SUMMARY
            QUICK ANALYZE ONLY FOR ADMIN / ANALYST
        ========================================= */}

        <div
          className={
            canAnalyze
              ? "mt-6 grid grid-cols-1 gap-5 xl:grid-cols-3"
              : "mt-6"
          }
        >

          <div
            className={
              canAnalyze
                ? "xl:col-span-2 rounded-xl border border-slate-800 bg-slate-900 p-6"
                : "rounded-xl border border-slate-800 bg-slate-900 p-6"
            }
          >

            <div className="mb-6 flex items-start justify-between">

              <div>

                <h4 className="font-semibold text-slate-100">
                  Threat Detection Summary
                </h4>

                <p className="mt-1 text-xs text-slate-500">
                  Current email threat classification
                </p>

              </div>

              <span className="rounded-full border border-slate-800 bg-slate-950 px-3 py-1 text-[10px] text-slate-500">
                LIVE PERIOD
              </span>

            </div>


            <div className="space-y-5">

              <ThreatBar
                label="Phishing"
                value={`${statistics.phishingPercentage}%`}
                width={`${statistics.phishingPercentage}%`}
                color="bg-red-500"
                textColor="text-red-400"
              />

              <ThreatBar
                label="Impersonation"
                value={`${statistics.impersonationPercentage}%`}
                width={`${statistics.impersonationPercentage}%`}
                color="bg-yellow-500"
                textColor="text-yellow-400"
              />

              <ThreatBar
                label="BEC / Fraud"
                value={`${statistics.becPercentage}%`}
                width={`${statistics.becPercentage}%`}
                color="bg-orange-500"
                textColor="text-orange-400"
              />

              <ThreatBar
                label="Credential Theft"
                value={`${statistics.credentialPercentage}%`}
                width={`${statistics.credentialPercentage}%`}
                color="bg-purple-500"
                textColor="text-purple-400"
              />

              <ThreatBar
                label="Other / Suspicious"
                value={`${statistics.otherPercentage}%`}
                width={`${statistics.otherPercentage}%`}
                color="bg-cyan-500"
                textColor="text-cyan-400"
              />

            </div>


            <div className="mt-6 grid grid-cols-1 gap-3 border-t border-slate-800 pt-5 md:grid-cols-3">

              <SummaryItem
                label="Primary Threat"
                value={
                  statistics.total
                    ? getPrimaryThreat(
                        statistics
                      )
                    : 'No data'
                }
                color="text-red-400"
              />

              <SummaryItem
                label="Detection Rate"
                value={`${statistics.detectionRate}%`}
                color="text-green-400"
              />

              <SummaryItem
                label="Risk Level"
                value={
                  statistics.total
                    ? statistics.riskLevel
                    : 'No data'
                }
                color="text-yellow-400"
              />

            </div>

          </div>


          {/* =========================================
              QUICK ANALYZE
              HIDDEN FOR VIEWER
          ========================================= */}

          {canAnalyze && (

            <div className="relative overflow-hidden rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-6">

              <div className="absolute -right-8 -top-8 h-32 w-32 rounded-full bg-cyan-500/5 blur-2xl"></div>

              <div className="relative">

                <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 text-xl">
                  ✉️
                </div>

                <p className="text-xs font-medium uppercase tracking-wider text-cyan-400">
                  Forensic Analysis
                </p>

                <h4 className="mt-2 text-lg font-semibold text-slate-100">
                  Analyze an Email
                </h4>

                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Upload a raw email or paste email headers to start
                  a forensic threat investigation.
                </p>


                <div className="mt-5 space-y-2">

                  <Feature text="Header analysis" />
                  <Feature text="Threat detection" />
                  <Feature text="IOC extraction" />

                </div>


                <button
                  onClick={() =>
                    navigate('/analyze')
                  }
                  className="mt-6 w-full rounded-lg bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
                >
                  Start Analysis →
                </button>

              </div>

            </div>

          )}

        </div>


        {/* SECURITY ACTIVITY */}

        <div className="mt-6 grid grid-cols-1 gap-5 xl:grid-cols-3">


          {/* RISK OVERVIEW */}

          <DashboardPanel
            title="Risk Overview"
            description="Current investigation severity"
          >

            <DashboardRow
              label="Critical"
              value={statistics.critical}
              color="text-red-400"
              dot="bg-red-400"
            />

            <DashboardRow
              label="High"
              value={statistics.high}
              color="text-orange-400"
              dot="bg-orange-400"
            />

            <DashboardRow
              label="Medium"
              value={statistics.medium}
              color="text-yellow-400"
              dot="bg-yellow-400"
            />

            <DashboardRow
              label="Low"
              value={statistics.low}
              color="text-green-400"
              dot="bg-green-400"
            />

            <div className="mt-5 border-t border-slate-800 pt-4">

              <div className="flex justify-between">

                <span className="text-xs text-slate-600">
                  Total investigations
                </span>

                <span className="text-xs font-medium text-slate-400">
                  {statistics.total}
                </span>

              </div>

            </div>

          </DashboardPanel>


          {/* INTELLIGENCE STATUS */}

          <DashboardPanel
            title="Intelligence Status"
            description="Analysis services"
          >

            <ServiceRow
              label="Header Engine"
              status="Online"
              color="text-green-400"
            />

            <ServiceRow
              label="Threat Engine"
              status="Online"
              color="text-green-400"
            />

            <ServiceRow
              label="IOC Engine"
              status="Online"
              color="text-green-400"
            />

            <ServiceRow
              label="Geo Intelligence"
              status="Online"
              color="text-green-400"
            />

          </DashboardPanel>


          {/* INVESTIGATION SNAPSHOT */}

          <DashboardPanel
            title="Investigation Snapshot"
            description="Live platform activity"
          >

            <DashboardRow
              label="Active investigations"
              value={statistics.activeCases}
              color="text-cyan-400"
            />

            <DashboardRow
              label="Campaign indicators"
              value={statistics.campaignCount}
              color="text-yellow-400"
            />

            <DashboardRow
              label="IOCs extracted"
              value={statistics.indicatorCount}
              color="text-orange-400"
            />

            <DashboardRow
              label="Automatic cases"
              value={statistics.automaticCases}
              color="text-red-400"
            />

          </DashboardPanel>

        </div>


        {/* PLATFORM WORKFLOW */}

        <div className="mt-6 rounded-xl border border-cyan-500/10 bg-slate-900 p-6">

          <div className="mb-6">

            <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
              INVESTIGATION WORKFLOW
            </p>

            <h4 className="mt-1 font-semibold text-slate-100">
              From Email to Forensic Intelligence
            </h4>

            <p className="mt-1 text-xs text-slate-500">
              TraceMail AI connects the complete email investigation workflow.
            </p>

          </div>


          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6">

            <WorkflowStep
              number="01"
              icon="✉"
              title="Analyze"
              description="Inspect email"
            />

            <WorkflowStep
              number="02"
              icon="🔍"
              title="Forensics"
              description="Analyze headers"
            />

            <WorkflowStep
              number="03"
              icon="🌍"
              title="Geo Intel"
              description="Trace source"
            />

            <WorkflowStep
              number="04"
              icon="🕸"
              title="Campaigns"
              description="Link threats"
            />

            <WorkflowStep
              number="05"
              icon="📁"
              title="Cases"
              description="Investigate"
            />

            <WorkflowStep
              number="06"
              icon="📄"
              title="Reports"
              description="Document"
            />

          </div>

        </div>


        {/* RECENT INVESTIGATIONS */}

        <div className="mt-6 rounded-xl border border-slate-800 bg-slate-900 p-6">

          <div className="mb-5 flex items-center justify-between">

            <div>

              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Case Activity
              </p>

              <h4 className="mt-1 font-semibold text-slate-100">
                Recent Investigations
              </h4>

              <p className="mt-1 text-xs text-slate-500">
                Latest email security investigations from MongoDB
              </p>

            </div>


            <button
              onClick={() =>
                navigate('/cases')
              }
              className="text-sm text-cyan-400 transition hover:text-cyan-300"
            >
              View All →
            </button>

          </div>


          <div className="overflow-x-auto rounded-lg border border-slate-800">

            {loading ? (

              <div className="p-8 text-center text-sm text-slate-500">
                Loading live investigations...
              </div>

            ) : recentTickets.length === 0 ? (

              <div className="p-8 text-center">

                <p className="text-sm text-slate-400">
                  No investigations found.
                </p>

                {/* ONLY ADMIN / ANALYST */}

                {canAnalyze && (

                  <button
                    onClick={() =>
                      navigate('/analyze')
                    }
                    className="mt-3 text-sm text-cyan-400 hover:text-cyan-300"
                  >
                    Analyze your first email →
                  </button>

                )}

              </div>

            ) : (

              <table className="w-full min-w-[800px] text-left text-sm">

                <thead className="bg-slate-950">

                  <tr>

                    <th className="px-4 py-3 text-xs font-medium text-slate-500">
                      Case
                    </th>

                    <th className="px-4 py-3 text-xs font-medium text-slate-500">
                      Sender
                    </th>

                    <th className="px-4 py-3 text-xs font-medium text-slate-500">
                      Classification
                    </th>

                    <th className="px-4 py-3 text-xs font-medium text-slate-500">
                      Risk
                    </th>

                    <th className="px-4 py-3 text-xs font-medium text-slate-500">
                      Status
                    </th>

                  </tr>

                </thead>


                <tbody className="divide-y divide-slate-800">

                  {recentTickets.map(
                    (ticket) => {

                      const classification =
                        classificationInfo(
                          ticket.category
                        )


                      return (

                        <InvestigationRow
                          key={
                            ticket._id ||
                            ticket.ticketId
                          }
                          id={
                            ticket.ticketId ||
                            'Unknown'
                          }
                          sender={
                            ticket.sender ||
                            'Unknown sender'
                          }
                          classification={
                            classification.label
                          }
                          classificationColor={
                            classification.className
                          }
                          risk={
                            `${Number(
                              ticket.threatScore ||
                              0
                            )}/100`
                          }
                          riskColor={
                            getRiskColor(
                              ticket.threatScore
                            )
                          }
                          status={
                            ticket.status ||
                            'Investigating'
                          }
                          statusColor={
                            getStatusColor(
                              ticket.status
                            )
                          }
                        />

                      )

                    }
                  )}

                </tbody>

              </table>

            )}

          </div>

        </div>


        {/* FOOTER */}

        <div className="mt-6 flex flex-col gap-3 border-t border-slate-800 pt-5 md:flex-row md:items-center md:justify-between">

          <p className="text-xs text-slate-600">
            TraceMail AI • AI-Powered Email Threat Detection & Forensic Intelligence
          </p>

          <div className="flex items-center gap-2 text-xs text-slate-600">

            <span className="h-1.5 w-1.5 rounded-full bg-green-400"></span>

            Platform Operational

          </div>

        </div>

      </section>

    </>

  )

}


/* =========================================
   PRIMARY THREAT HELPER
========================================= */

function getPrimaryThreat(statistics) {

  const threats = [

    {
      label: 'Phishing',
      value: statistics.phishingCount,
    },

    {
      label: 'BEC / Fraud',
      value: statistics.becCount,
    },

    {
      label: 'Credential Theft',
      value: statistics.credentialCount,
    },

    {
      label: 'Impersonation',
      value: statistics.impersonationCount,
    },

    {
      label: 'Other / Suspicious',
      value: statistics.otherCount,
    },

  ]


  threats.sort(
    (a, b) =>
      b.value - a.value
  )


  return threats[0]?.value
    ? threats[0].label
    : 'No data'

}


/* =========================================
   DASHBOARD STAT CARD
========================================= */

function DashboardStatCard({
  label,
  value,
  icon,
  iconClass,
  borderClass,
  valueClass = 'text-slate-100',
  trend,
  trendClass,
  description,
}) {

  return (

    <div
      className={`group rounded-xl border bg-slate-900 p-5 transition ${borderClass}`}
    >

      <div className="flex items-start justify-between">

        <p className="text-sm text-slate-500">
          {label}
        </p>

        <span
          className={`rounded-lg px-2 py-1 text-xs ${iconClass}`}
        >
          {icon}
        </span>

      </div>


      <p
        className={`mt-3 text-3xl font-bold ${valueClass}`}
      >
        {value}
      </p>


      <div className="mt-3 flex items-center gap-2">

        <span
          className={`text-xs ${trendClass}`}
        >
          {trend}
        </span>

        <span className="text-xs text-slate-600">
          {description}
        </span>

      </div>

    </div>

  )

}


/* =========================================
   THREAT BAR
========================================= */

function ThreatBar({
  label,
  value,
  width,
  color,
  textColor,
}) {

  return (

    <div>

      <div className="mb-2 flex justify-between text-sm">

        <span className="text-slate-300">
          {label}
        </span>

        <span
          className={`font-medium ${textColor}`}
        >
          {value}
        </span>

      </div>


      <div className="h-2 overflow-hidden rounded-full bg-slate-800">

        <div
          className={`h-full rounded-full ${color}`}
          style={{
            width,
          }}
        />

      </div>

    </div>

  )

}


/* =========================================
   SUMMARY ITEM
========================================= */

function SummaryItem({
  label,
  value,
  color,
}) {

  return (

    <div>

      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p
        className={`mt-1 text-sm font-medium ${color}`}
      >
        {value}

      </p>

    </div>

  )

}


/* =========================================
   FEATURE
========================================= */

function Feature({ text }) {

  return (

    <div className="flex items-center gap-2 text-xs text-slate-500">

      <span className="text-green-400">
        ✓
      </span>

      {text}

    </div>

  )

}


/* =========================================
   DASHBOARD PANEL
========================================= */

function DashboardPanel({
  title,
  description,
  children,
}) {

  return (

    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">

      <div className="mb-5">

        <h4 className="font-semibold text-slate-100">
          {title}
        </h4>

        <p className="mt-1 text-xs text-slate-500">
          {description}
        </p>

      </div>


      <div className="space-y-4">
        {children}
      </div>

    </div>

  )

}


/* =========================================
   DASHBOARD ROW
========================================= */

function DashboardRow({
  label,
  value,
  color,
  dot,
}) {

  return (

    <div className="flex items-center justify-between">

      <div className="flex items-center gap-3">

        {dot && (

          <span
            className={`h-2.5 w-2.5 rounded-full ${dot}`}
          ></span>

        )}

        <span className="text-sm text-slate-400">
          {label}
        </span>

      </div>


      <span
        className={`text-sm font-semibold ${color}`}
      >
        {value}
      </span>

    </div>

  )

}


/* =========================================
   SERVICE ROW
========================================= */

function ServiceRow({
  label,
  status,
  color,
}) {

  return (

    <div className="flex items-center justify-between">

      <span className="text-sm text-slate-400">
        {label}
      </span>

      <span
        className={`flex items-center gap-2 text-xs ${color}`}
      >

        <span className="h-1.5 w-1.5 rounded-full bg-current"></span>

        {status}

      </span>

    </div>

  )

}


/* =========================================
   WORKFLOW STEP
========================================= */

function WorkflowStep({
  number,
  icon,
  title,
  description,
}) {

  return (

    <div className="group rounded-xl border border-slate-800 bg-slate-950/50 p-4 transition hover:border-cyan-500/20 hover:bg-cyan-500/5">

      <div className="flex items-center justify-between">

        <span className="text-[10px] font-semibold tracking-wider text-slate-700">
          {number}
        </span>

        <span className="text-lg">
          {icon}
        </span>

      </div>


      <p className="mt-4 text-sm font-semibold text-slate-300">
        {title}
      </p>

      <p className="mt-1 text-xs text-slate-600">
        {description}
      </p>

    </div>

  )

}


/* =========================================
   INVESTIGATION ROW
========================================= */

function InvestigationRow({
  id,
  sender,
  classification,
  classificationColor,
  risk,
  riskColor,
  status,
  statusColor,
}) {

  const navigate = useNavigate()


  return (

    <tr
      onClick={() =>
        navigate('/cases')
      }
      className="cursor-pointer transition hover:bg-slate-950/50"
    >

      <td className="px-4 py-4 font-medium text-cyan-400">
        {id}
      </td>

      <td className="px-4 py-4 text-slate-300">
        {sender}
      </td>

      <td className="px-4 py-4">

        <span
          className={`rounded-full px-3 py-1 text-xs ${classificationColor}`}
        >
          {classification}
        </span>

      </td>

      <td
        className={`px-4 py-4 font-semibold ${riskColor}`}
      >
        {risk}
      </td>

      <td className="px-4 py-4">

        <span
          className={`flex items-center gap-2 text-xs ${statusColor}`}
        >

          <span className="h-1.5 w-1.5 rounded-full bg-current"></span>

          {status}

        </span>

      </td>

    </tr>

  )

}


/* =========================================
   SIMPLE PAGE
========================================= */

function SimplePage({
  title,
  description,
}) {

  return (

    <div className="p-8">

      <p className="text-sm font-medium text-cyan-400">
        TRACEMAIL AI
      </p>

      <h2 className="mt-2 text-3xl font-bold text-slate-100">
        {title}
      </h2>

      <p className="mt-3 max-w-2xl leading-6 text-slate-400">
        {description}
      </p>

    </div>

  )

}


/* =========================================
   MAIN APP
========================================= */

function App() {

  /*
    IMPORTANT:
    useLocation makes App re-render whenever the
    route changes.

    Therefore, after Login.jsx stores the JWT and
    navigates to "/", App immediately sees the token
    and renders the Sidebar without requiring refresh.
  */

  const location = useLocation()


  const isLoginPage =
    location.pathname === '/login'


  const isAuthenticated =
    Boolean(
      localStorage.getItem(
        'tracemail_auth_token'
      )
    )


  const showSidebar =
    !isLoginPage &&
    isAuthenticated


  return (

    <div className="min-h-screen bg-slate-950 text-slate-100">

      {showSidebar && <Sidebar />}


      <main
        className={
          showSidebar
            ? 'ml-64 min-h-screen'
            : 'min-h-screen'
        }
      >

        <Routes>

          {/* =====================================
              PUBLIC LOGIN
          ===================================== */}

          <Route
            path="/login"
            element={<Login />}
          />


          {/* =====================================
              DASHBOARD
          ===================================== */}

          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              ANALYZE EMAIL
          ===================================== */}

          <Route
            path="/analyze"
            element={
              <ProtectedRoute
                allowedRoles={[
                  'Admin',
                  'Analyst',
                ]}
              >
                <AnalyzeEmail />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              HEADER FORENSICS
          ===================================== */}

          <Route
            path="/forensics"
            element={
              <ProtectedRoute
                allowedRoles={[
                  'Admin',
                  'Analyst',
                ]}
              >
                <HeaderForensics />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              GEO INTELLIGENCE
          ===================================== */}

          <Route
            path="/geo"
            element={
              <ProtectedRoute
                allowedRoles={[
                  'Admin',
                  'Analyst',
                ]}
              >
                <GeoIntelligence />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              CAMPAIGNS
          ===================================== */}

          <Route
            path="/campaigns"
            element={
              <ProtectedRoute
                allowedRoles={[
                  'Admin',
                  'Analyst',
                ]}
              >
                <Campaigns />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              CASES
          ===================================== */}

          <Route
            path="/cases"
            element={
              <ProtectedRoute
                allowedRoles={[
                  'Admin',
                  'Analyst',
                  'Viewer',
                ]}
              >
                <Cases />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              REPORTS
          ===================================== */}

          <Route
            path="/reports"
            element={
              <ProtectedRoute
                allowedRoles={[
                  'Admin',
                  'Analyst',
                  'Viewer',
                ]}
              >
                <Reports />
              </ProtectedRoute>
            }
          />


          {/* =====================================
              FALLBACK
          ===================================== */}

          <Route
            path="*"
            element={
              <ProtectedRoute>
                <SimplePage
                  title="Page Not Found"
                  description="The requested TraceMail AI investigation module could not be found."
                />
              </ProtectedRoute>
            }
          />

        </Routes>

      </main>

    </div>

  )

}


export default App