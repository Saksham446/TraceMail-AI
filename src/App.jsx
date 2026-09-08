import { Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import AnalyzeEmail from './pages/AnalyzeEmail'
import HeaderForensics from './pages/HeaderForensics'
import Campaigns from './pages/Campaigns'
import GeoIntelligence from './pages/GeoIntelligence'
import Cases from './pages/Cases'
import Reports from './pages/Reports'


/* =========================================
   SIDEBAR
========================================= */

function Sidebar() {

  const navItems = [
    { label: 'Dashboard', icon: '◉', path: '/' },
    { label: 'Analyze Email', icon: '✉', path: '/analyze' },
    { label: 'Header Forensics', icon: '🔍', path: '/forensics' },
    { label: 'Geo Intelligence', icon: '🌍', path: '/geo' },
    { label: 'Campaigns', icon: '🕸', path: '/campaigns' },
    { label: 'Cases', icon: '📁', path: '/cases' },
    { label: 'Reports', icon: '📄', path: '/reports' },
  ]

  return (
    <aside className="fixed left-0 top-0 z-20 h-screen w-64 border-r border-slate-800 bg-slate-900/95 p-5">

      {/* Logo */}

      <div className="mb-8">

        <NavLink to="/" className="flex items-center gap-3">

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


      {/* Navigation */}

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


      {/* System Status */}

      <div className="absolute bottom-5 left-5 right-5 rounded-xl border border-slate-800 bg-slate-950 p-4">

        <div className="mb-2 flex items-center gap-2">

          <span className="relative flex h-2 w-2">

            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-50"></span>

            <span className="relative inline-flex h-2 w-2 rounded-full bg-green-400"></span>

          </span>

          <span className="text-xs font-medium text-slate-300">
            System Operational
          </span>

        </div>


        <p className="text-xs leading-5 text-slate-500">
          Threat intelligence engine ready
        </p>


        <div className="mt-3 border-t border-slate-800 pt-3">

          <div className="flex items-center justify-between">

            <span className="text-[10px] text-slate-600">
              ENGINE
            </span>

            <span className="text-[10px] font-medium text-green-400">
              ONLINE
            </span>

          </div>

        </div>

      </div>

    </aside>
  )
}


/* =========================================
   DASHBOARD
========================================= */

function Dashboard() {

  const navigate = useNavigate()

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
            A
          </div>

        </div>

      </header>


      {/* DASHBOARD CONTENT */}

      <section className="p-8">


        {/* Welcome */}

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


            <button
              onClick={() => navigate('/analyze')}
              className="rounded-lg bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
            >
              + Analyze Email
            </button>

          </div>

        </div>


        {/* STATISTICS */}

        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">


          {/* Emails */}

          <DashboardStatCard
            label="Emails Analyzed"
            value="1,284"
            icon="✉"
            iconClass="bg-cyan-500/10 text-cyan-400"
            borderClass="border-slate-800 hover:border-slate-700"
            trend="↑ 12.4%"
            trendClass="text-green-400"
            description="this week"
          />


          {/* Threats */}

          <DashboardStatCard
            label="Threats Detected"
            value="87"
            icon="⚠"
            iconClass="bg-red-500/10 text-red-400"
            borderClass="border-red-500/10 hover:border-red-500/20"
            valueClass="text-red-400"
            trend="High risk"
            trendClass="text-red-400"
            description="threats"
          />


          {/* Domains */}

          <DashboardStatCard
            label="Suspicious Domains"
            value="34"
            icon="◈"
            iconClass="bg-yellow-500/10 text-yellow-400"
            borderClass="border-yellow-500/10 hover:border-yellow-500/20"
            valueClass="text-yellow-400"
            trend="Monitoring"
            trendClass="text-yellow-400"
            description="domains"
          />


          {/* Cases */}

          <DashboardStatCard
            label="Active Cases"
            value="16"
            icon="📁"
            iconClass="bg-cyan-500/10 text-cyan-400"
            borderClass="border-cyan-500/10 hover:border-cyan-500/20"
            valueClass="text-cyan-400"
            trend="Open"
            trendClass="text-cyan-400"
            description="investigations"
          />

        </div>


        {/* THREAT SUMMARY + QUICK ANALYZE */}

        <div className="mt-6 grid grid-cols-1 gap-5 xl:grid-cols-3">


          {/* Threat Summary */}

          <div className="xl:col-span-2 rounded-xl border border-slate-800 bg-slate-900 p-6">

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
                CURRENT PERIOD
              </span>

            </div>


            <div className="space-y-5">

              <ThreatBar
                label="Phishing"
                value="42%"
                width="42%"
                color="bg-red-500"
                textColor="text-red-400"
              />

              <ThreatBar
                label="Impersonation"
                value="26%"
                width="26%"
                color="bg-yellow-500"
                textColor="text-yellow-400"
              />

              <ThreatBar
                label="BEC / Fraud"
                value="18%"
                width="18%"
                color="bg-orange-500"
                textColor="text-orange-400"
              />

              <ThreatBar
                label="Other Suspicious"
                value="14%"
                width="14%"
                color="bg-cyan-500"
                textColor="text-cyan-400"
              />

            </div>


            <div className="mt-6 grid grid-cols-1 gap-3 border-t border-slate-800 pt-5 md:grid-cols-3">

              <SummaryItem
                label="Primary Threat"
                value="Phishing"
                color="text-red-400"
              />

              <SummaryItem
                label="Detection Rate"
                value="93.8%"
                color="text-green-400"
              />

              <SummaryItem
                label="Risk Level"
                value="Elevated"
                color="text-yellow-400"
              />

            </div>

          </div>


          {/* Quick Analyze */}

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
                onClick={() => navigate('/analyze')}
                className="mt-6 w-full rounded-lg bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                Start Analysis →
              </button>

            </div>

          </div>

        </div>


        {/* SECURITY ACTIVITY */}

        <div className="mt-6 grid grid-cols-1 gap-5 xl:grid-cols-3">


          {/* Risk Overview */}

          <DashboardPanel
            title="Risk Overview"
            description="Current investigation severity"
          >

            <DashboardRow
              label="Critical"
              value="12"
              color="text-red-400"
              dot="bg-red-400"
            />

            <DashboardRow
              label="High"
              value="28"
              color="text-orange-400"
              dot="bg-orange-400"
            />

            <DashboardRow
              label="Medium"
              value="31"
              color="text-yellow-400"
              dot="bg-yellow-400"
            />

            <DashboardRow
              label="Low"
              value="16"
              color="text-green-400"
              dot="bg-green-400"
            />

            <div className="mt-5 border-t border-slate-800 pt-4">

              <div className="flex justify-between">

                <span className="text-xs text-slate-600">
                  Total detected
                </span>

                <span className="text-xs font-medium text-slate-400">
                  87
                </span>

              </div>

            </div>

          </DashboardPanel>


          {/* Intelligence Status */}

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


          {/* Investigation Snapshot */}

          <DashboardPanel
            title="Investigation Snapshot"
            description="Platform activity"
          >

            <DashboardRow
              label="Active investigations"
              value="16"
              color="text-cyan-400"
            />

            <DashboardRow
              label="Campaigns identified"
              value="7"
              color="text-yellow-400"
            />

            <DashboardRow
              label="IOCs extracted"
              value="143"
              color="text-orange-400"
            />

            <DashboardRow
              label="Reports generated"
              value="38"
              color="text-slate-300"
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
                Latest email security investigations
              </p>

            </div>


            <button
              onClick={() => navigate('/cases')}
              className="text-sm text-cyan-400 transition hover:text-cyan-300"
            >
              View All →
            </button>

          </div>


          <div className="overflow-x-auto rounded-lg border border-slate-800">

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

                <InvestigationRow
                  id="TM-2026-001"
                  sender="security@example.com"
                  classification="Phishing"
                  classificationColor="bg-red-500/10 text-red-400"
                  risk="94/100"
                  riskColor="text-red-400"
                  status="Investigating"
                  statusColor="text-green-400"
                />

                <InvestigationRow
                  id="TM-2026-002"
                  sender="finance@company.net"
                  classification="Impersonation"
                  classificationColor="bg-yellow-500/10 text-yellow-400"
                  risk="76/100"
                  riskColor="text-yellow-400"
                  status="Investigating"
                  statusColor="text-green-400"
                />

                <InvestigationRow
                  id="TM-2026-003"
                  sender="admin@portal.org"
                  classification="BEC / Fraud"
                  classificationColor="bg-orange-500/10 text-orange-400"
                  risk="81/100"
                  riskColor="text-orange-400"
                  status="Open"
                  statusColor="text-green-400"
                />

                <InvestigationRow
                  id="TM-2026-004"
                  sender="support@accounts-mail.com"
                  classification="Credential Theft"
                  classificationColor="bg-red-500/10 text-red-400"
                  risk="91/100"
                  riskColor="text-red-400"
                  status="Critical"
                  statusColor="text-red-400"
                />

              </tbody>

            </table>

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

        <span className={`rounded-lg px-2 py-1 text-xs ${iconClass}`}>
          {icon}
        </span>

      </div>

      <p className={`mt-3 text-3xl font-bold ${valueClass}`}>
        {value}
      </p>

      <div className="mt-3 flex items-center gap-2">

        <span className={`text-xs ${trendClass}`}>
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

        <span className={`font-medium ${textColor}`}>
          {value}
        </span>

      </div>

      <div className="h-2 overflow-hidden rounded-full bg-slate-800">

        <div
          className={`h-full rounded-full ${color}`}
          style={{ width }}
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

      <p className={`mt-1 text-sm font-medium ${color}`}>
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

      <span className={`text-sm font-semibold ${color}`}>
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

      <span className={`flex items-center gap-2 text-xs ${color}`}>

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
      onClick={() => navigate('/cases')}
      className="cursor-pointer transition hover:bg-slate-950/50"
    >

      <td className="px-4 py-4 font-medium text-cyan-400">
        {id}
      </td>

      <td className="px-4 py-4 text-slate-300">
        {sender}
      </td>

      <td className="px-4 py-4">

        <span className={`rounded-full px-3 py-1 text-xs ${classificationColor}`}>
          {classification}
        </span>

      </td>

      <td className={`px-4 py-4 font-semibold ${riskColor}`}>
        {risk}
      </td>

      <td className="px-4 py-4">

        <span className={`flex items-center gap-2 text-xs ${statusColor}`}>

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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">

      <Sidebar />

      <main className="ml-64 min-h-screen">

        <Routes>

          {/* Dashboard */}

          <Route
            path="/"
            element={<Dashboard />}
          />


          {/* Analyze Email */}

          <Route
            path="/analyze"
            element={<AnalyzeEmail />}
          />


          {/* Header Forensics */}

          <Route
            path="/forensics"
            element={<HeaderForensics />}
          />


          {/* Geo Intelligence */}

          <Route
            path="/geo"
            element={<GeoIntelligence />}
          />


          {/* Campaigns */}

          <Route
            path="/campaigns"
            element={<Campaigns />}
          />


          {/* Cases */}

          <Route
            path="/cases"
            element={<Cases />}
          />


          {/* Reports */}

          <Route
            path="/reports"
            element={<Reports />}
          />


          {/* Fallback */}

          <Route
            path="*"
            element={
              <SimplePage
                title="Page Not Found"
                description="The requested TraceMail AI investigation module could not be found."
              />
            }
          />

        </Routes>

      </main>

    </div>
  )
}

export default App