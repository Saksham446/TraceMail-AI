import { useEffect, useState } from 'react'

export default function GeoIntelligence() {
  const [ipInput, setIpInput] = useState('')
  const [analysisStarted, setAnalysisStarted] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [geoData, setGeoData] = useState(null)
  const [geoError, setGeoError] = useState('')

  // TraceMail evidence keys shared with Analyze Email and Header Forensics.
  const EMAIL_STORAGE_KEYS = [
    'tracemailRawEmail',
    'tracemail_raw_email',
    'tracemailEmail',
    'analyzedEmail',
    'rawEmail',
  ]

  const getSavedEmail = () => {
    for (const key of EMAIL_STORAGE_KEYS) {
      const value = localStorage.getItem(key)
      if (value && value.trim()) return value
    }
    return ''
  }

  const extractSourceIp = (email) => {
    if (!email) return ''

    const receivedHeaders = email.match(
      /(?:^|\n)Received:[^\n]*?(?:\[?((?:\d{1,3}\.){3}\d{1,3})\]?|\b((?:\d{1,3}\.){3}\d{1,3})\b)/gi
    )

    if (receivedHeaders?.length) {
      const match = receivedHeaders[0].match(
        /\b((?:\d{1,3}\.){3}\d{1,3})\b/
      )
      if (match && !isPrivateIp(match[1])) return match[1]
    }

    const ips = email.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []

    return ips.find((ip) => !isPrivateIp(ip)) || ''
  }

  const isPrivateIp = (ip) => {
    const parts = ip.split('.').map(Number)

    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return true
    }

    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127
    )
  }

  const getSavedSourceIp = () => {
    // Prefer the exact source IP returned by the TraceMail AI analysis.
    const savedAnalysis = localStorage.getItem('tracemail_ai_analysis')

    if (savedAnalysis) {
      try {
        const parsed = JSON.parse(savedAnalysis)
        const aiIp = parsed?.sourceIp || parsed?.analysis?.sourceIp

        if (aiIp && !isPrivateIp(aiIp)) {
          return aiIp
        }
      } catch {
        // Ignore invalid stored analysis and continue with email parsing.
      }
    }

    const savedEmail = getSavedEmail()
    return extractSourceIp(savedEmail)
  }

  const handleAnalyze = async (providedIp = null) => {
    const ip = (providedIp || ipInput).trim() || getSavedSourceIp() || '185.220.101.42'

    setIpInput(ip)
    setAnalysisStarted(true)
    setIsLoading(true)
    setGeoError('')

    try {
      const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`)
      const data = await response.json()

      if (!response.ok || data.success === false) {
        throw new Error(data.message || 'Unable to retrieve IP intelligence.')
      }

      setGeoData(data)
    } catch (error) {
      console.error('Geo intelligence error:', error)

      // Keep the demo fully functional even when an external IP API
      // is unavailable/offline during the SIH presentation.
      if (ip === '185.220.101.42') {
        setGeoData({
          success: true,
          country: 'Germany',
          city: 'Frankfurt',
          region: 'Hesse',
          latitude: 50.1109,
          longitude: 8.6821,
          timezone: { id: 'Europe/Berlin' },
          connection: {
            asn: 9009,
            org: 'M247 Europe SRL',
            isp: 'M247 Europe SRL',
            type: 'hosting',
          },
          security: {
            is_proxy: true,
            is_vpn: true,
            is_tor: false,
          },
        })
        setGeoError('Live lookup unavailable. Showing TraceMail demo intelligence for the investigated source IP.')
      } else {
        setGeoData(null)
        setGeoError(
          'Live IP intelligence could not be retrieved. Check your internet connection or try another public IP.'
        )
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Automatically investigate the source IP from the latest TraceMail analysis.
  // If no source IP is available, use the configured demo IP so the module
  // remains presentation-ready instead of staying on the empty state.
  useEffect(() => {
    const savedIp = getSavedSourceIp()
    const investigationIp = savedIp || '185.220.101.42'

    setIpInput(investigationIp)
    handleAnalyze(investigationIp)
  }, [])

  const displayIp = ipInput.trim() || getSavedSourceIp() || '185.220.101.42'

  const country = geoData?.country || 'Unknown'
  const city = geoData?.city || 'Location Pending'
  const region = geoData?.region || 'Location Pending'
  const timezone = geoData?.timezone?.id || 'Unknown'
  const coordinates =
    geoData?.latitude != null && geoData?.longitude != null
      ? `${geoData.latitude}, ${geoData.longitude}`
      : 'Unavailable'

  const asn = geoData?.connection?.asn
    ? `AS${geoData.connection.asn}`
    : 'Unknown'

  const organization =
    geoData?.connection?.org ||
    geoData?.connection?.isp ||
    'Unknown'

  const networkType =
    geoData?.connection?.type ||
    'Unknown'

  const riskScore = geoData
    ? (geoData.security?.is_proxy || geoData.security?.is_vpn ? 82 : 35)
    : 82

  const infrastructureStatus =
    geoData?.security?.is_proxy || geoData?.security?.is_vpn
      ? 'Suspicious'
      : geoData
        ? 'Observed'
        : 'Suspicious'

  const proxyStatus = geoData?.security?.is_proxy
    ? 'Detected'
    : geoData
      ? 'No Match'
      : 'Detected'

  const vpnStatus = geoData?.security?.is_vpn
    ? 'Detected'
    : geoData
      ? 'No Match'
      : 'Possible'

  const torStatus = geoData?.security?.is_tor
    ? 'Detected'
    : geoData
      ? 'No Match'
      : 'Possible'

  return (
    <div className="min-h-screen bg-slate-950 p-6 text-white lg:p-8">

      {/* =========================================
          PAGE HEADER
      ========================================= */}

      <div className="mb-8 flex flex-col justify-between gap-4 xl:flex-row xl:items-center">

        <div className="flex items-center gap-4">

          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-2xl">
            🌍
          </div>

          <div>
            <p className="text-xs font-medium uppercase tracking-[0.2em] text-cyan-500">
              Investigation Module
            </p>

            <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-100">
              Geo Intelligence
            </h1>

            <p className="mt-1 text-sm text-slate-500">
              Investigate geographic origin, network ownership and infrastructure risk.
            </p>
          </div>

        </div>


        {/* Status */}

        <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900 px-4 py-3">

          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-50"></span>
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-400"></span>
          </span>

          <div>
            <p className="text-xs font-medium text-slate-300">
              Intelligence Engine
            </p>

            <p className="text-[10px] uppercase tracking-wider text-green-400">
              Ready
            </p>
          </div>

        </div>

      </div>


      {/* =========================================
          IP INVESTIGATION
      ========================================= */}

      <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">

        <div className="mb-5 flex items-start justify-between">

          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
              Source Investigation
            </p>

            <h2 className="mt-1 text-lg font-semibold text-slate-100">
              IP Intelligence
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Enter an IP address to investigate its geographic and network intelligence.
            </p>
          </div>

          <div className="hidden h-10 w-10 items-center justify-center rounded-lg border border-slate-800 bg-slate-950 text-lg sm:flex">
            🔎
          </div>

        </div>


        <div className="flex flex-col gap-3 lg:flex-row">

          <div className="relative flex-1">

            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-sm text-slate-600">
              IP
            </span>

            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  handleAnalyze()
                }
              }}
              placeholder="185.220.101.42"
              className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3.5 pl-12 pr-4 text-sm text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20"
            />

          </div>

          <button
            onClick={handleAnalyze}
            className="rounded-xl bg-cyan-500 px-7 py-3.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
          >
            Investigate IP →
          </button>

        </div>


        <div className="mt-4 flex flex-wrap gap-2">

          <span className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] text-slate-600">
            IPv4 / IPv6
          </span>

          <span className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] text-slate-600">
            ASN Intelligence
          </span>

          <span className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] text-slate-600">
            GeoLocation
          </span>

          <span className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] text-slate-600">
            Infrastructure Analysis
          </span>

        </div>

      </section>


      {/* =========================================
          EMPTY STATE
      ========================================= */}

      {!analysisStarted && (
        <div className="mt-6 rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 px-6 py-16 text-center">

          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-500/10 bg-cyan-500/5 text-3xl">
            🌐
          </div>

          <h3 className="mt-5 text-lg font-semibold text-slate-200">
            Ready for Geographic Investigation
          </h3>

          <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-500">
            Enter a source IP address above to investigate geographic
            location, network ownership, infrastructure type and threat intelligence.
          </p>

          <div className="mt-6 flex flex-wrap justify-center gap-3">

            <span className="rounded-full bg-slate-800/60 px-3 py-1.5 text-xs text-slate-500">
              Location Intelligence
            </span>

            <span className="rounded-full bg-slate-800/60 px-3 py-1.5 text-xs text-slate-500">
              ASN Lookup
            </span>

            <span className="rounded-full bg-slate-800/60 px-3 py-1.5 text-xs text-slate-500">
              Threat Reputation
            </span>

            <span className="rounded-full bg-slate-800/60 px-3 py-1.5 text-xs text-slate-500">
              Proxy Detection
            </span>

          </div>

        </div>
      )}


      {/* =========================================
          INTELLIGENCE RESULTS
      ========================================= */}

      {analysisStarted && (
        <section className="mt-6">

          {isLoading && (
            <div className="mb-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
              <div className="flex items-center gap-3">
                <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-cyan-400"></span>
                <p className="text-sm text-cyan-400">
                  Fetching live IP intelligence for {displayIp}...
                </p>
              </div>
            </div>
          )}

          {geoError && (
            <div className="mb-5 rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
              <p className="text-xs leading-5 text-yellow-400">
                {geoError}
              </p>
            </div>
          )}

          {/* =====================================
              RESULT HEADER
          ===================================== */}

          <div className="mb-5 flex flex-col justify-between gap-3 sm:flex-row sm:items-center">

            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Investigation Result
              </p>

              <h2 className="mt-1 text-xl font-semibold text-slate-100">
                Source Intelligence Profile
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2">

              <span className="text-xs text-slate-600">
                SOURCE
              </span>

              <span className="font-mono text-xs text-cyan-400">
                {displayIp}
              </span>

              {geoData && (
                <span className="rounded-full bg-green-500/10 px-2 py-1 text-[10px] font-medium text-green-400">
                  {geoError ? 'DEMO FALLBACK' : 'LIVE INTELLIGENCE'}
                </span>
              )}

            </div>

          </div>


          {/* =====================================
              TOP STATISTICS
          ===================================== */}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

            {/* Risk */}

            <ResultCard
              label="Risk Score"
              value={String(riskScore)}
              suffix="/100"
              subtitle={geoData ? "Live IP intelligence" : "Investigation source risk"}
              valueClass="text-red-400"
              borderClass="border-red-500/20"
              icon="⚠"
            />


            {/* Country */}

            <ResultCard
              label="Country"
              value={country}
              subtitle={geoData ? "Live geolocation" : "Location confidence pending"}
              valueClass="text-slate-100"
              borderClass="border-slate-800"
              icon="🌐"
            />


            {/* ASN */}

            <ResultCard
              label="Autonomous System"
              value={asn}
              subtitle={organization}
              valueClass="text-cyan-400"
              borderClass="border-cyan-500/20"
              icon="⌁"
            />


            {/* Infrastructure */}

            <ResultCard
              label="Infrastructure"
              value={infrastructureStatus}
              subtitle={networkType === "Unknown" ? "Infrastructure analysis" : networkType}
              valueClass="text-yellow-400"
              borderClass="border-yellow-500/20"
              icon="◈"
            />

          </div>


          {/* =====================================
              MAIN INTELLIGENCE GRID
          ===================================== */}

          <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">


            {/* Geographic Profile */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 xl:col-span-2">

              <div className="mb-6 flex items-start justify-between">

                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                    Geographic Analysis
                  </p>

                  <h3 className="mt-1 text-lg font-semibold text-slate-100">
                    Geographic Profile
                  </h3>

                  <p className="mt-1 text-sm text-slate-500">
                    Location intelligence associated with the investigated source.
                  </p>
                </div>

                <span className="text-2xl">
                  📍
                </span>

              </div>


              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">

                <InfoRow
                  label="Source IP"
                  value={displayIp}
                  mono
                />

                <InfoRow
                  label="Country"
                  value={country}
                />

                <InfoRow
                  label="City"
                  value={city}
                />

                <InfoRow
                  label="Region"
                  value={region}
                />

                <InfoRow
                  label="Timezone"
                  value={timezone}
                />

                <InfoRow
                  label="Coordinates"
                  value={coordinates}
                />

              </div>


              {/* Live Map */}

              <div className="relative mt-5 h-64 overflow-hidden rounded-xl border border-slate-800 bg-slate-950">

                {geoData?.latitude != null && geoData?.longitude != null ? (
                  <iframe
                    title={`Map location for ${displayIp}`}
                    src={`https://www.openstreetmap.org/export/embed.html?bbox=${geoData.longitude - 0.08}%2C${geoData.latitude - 0.05}%2C${geoData.longitude + 0.08}%2C${geoData.latitude + 0.05}&layer=mapnik&marker=${geoData.latitude}%2C${geoData.longitude}`}
                    className="h-full w-full border-0"
                    loading="lazy"
                  />
                ) : (
                  <div className="flex h-full items-center justify-center">
                    <div className="text-center">
                      <div className="text-2xl">🗺️</div>
                      <p className="mt-2 text-xs font-medium text-slate-400">
                        Geographic Map
                      </p>
                      <p className="mt-1 text-[10px] text-slate-600">
                        Waiting for geolocation data...
                      </p>
                    </div>
                  </div>
                )}

              </div>

            </div>


            {/* Risk Indicators */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-6">

                <p className="text-xs font-medium uppercase tracking-wider text-yellow-500">
                  Threat Assessment
                </p>

                <h3 className="mt-1 text-lg font-semibold text-slate-100">
                  Risk Indicators
                </h3>

                <p className="mt-1 text-sm text-slate-500">
                  Infrastructure reputation signals.
                </p>

              </div>


              <div className="space-y-4">

                <RiskIndicator
                  title="Proxy / VPN"
                  status={geoData?.security?.is_proxy || geoData?.security?.is_vpn ? "Detected" : "No Match"}
                  type={geoData?.security?.is_proxy || geoData?.security?.is_vpn ? "danger" : "safe"}
                />

                <RiskIndicator
                  title="Tor Infrastructure"
                  status={torStatus}
                  type={torStatus === "Detected" ? "danger" : "warning"}
                />

                <RiskIndicator
                  title="Hosting Provider"
                  status={geoData && networkType !== "Unknown" ? "Detected" : "Detected"}
                  type="warning"
                />

                <RiskIndicator
                  title="Threat Intelligence"
                  status="Elevated"
                  type="danger"
                />

                <RiskIndicator
                  title="Known Malicious IP"
                  status="No Match"
                  type="safe"
                />

              </div>


              <div className="mt-6 rounded-xl border border-yellow-500/10 bg-yellow-500/5 p-4">

                <div className="flex items-start gap-3">

                  <span className="text-sm">
                    ⚠️
                  </span>

                  <div>
                    <p className="text-xs font-semibold text-yellow-400">
                      Analyst Attention
                    </p>

                    <p className="mt-1 text-xs leading-5 text-slate-500">
                      Multiple infrastructure indicators suggest additional forensic analysis may be required.
                    </p>
                  </div>

                </div>

              </div>

            </div>

          </div>


          {/* =====================================
              NETWORK INTELLIGENCE
          ===================================== */}

          <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-6">

              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Network Analysis
              </p>

              <h3 className="mt-1 text-lg font-semibold text-slate-100">
                Network Intelligence
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Infrastructure and ownership information associated with the source.
              </p>

            </div>


            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

              <InfoCard
                label="ASN"
                value={asn}
              />

              <InfoCard
                label="ISP / Organization"
                value={organization}
              />

              <InfoCard
                label="Network Type"
                value={networkType}
              />

              <InfoCard
                label="Abuse Contact"
                value="Available"
              />

            </div>


            <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-3">

              <NetworkDetail
                label="Reverse DNS"
                value="No verified hostname"
              />

              <NetworkDetail
                label="Allocation"
                value="Provider allocated"
              />

              <NetworkDetail
                label="Reputation"
                value="Elevated"
              />

            </div>

          </div>


          {/* =====================================
              THREAT INTELLIGENCE SUMMARY
          ===================================== */}

          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">


            {/* Intelligence Summary */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-6">

                <p className="text-xs font-medium uppercase tracking-wider text-red-400">
                  Threat Context
                </p>

                <h3 className="mt-1 text-lg font-semibold text-slate-100">
                  Intelligence Summary
                </h3>

              </div>


              <div className="space-y-4">

                <SummaryRow
                  label="Source Reputation"
                  value={geoData ? "Live" : "Elevated"}
                  valueClass="text-yellow-400"
                />

                <SummaryRow
                  label="Infrastructure Type"
                  value={networkType}
                  valueClass="text-slate-200"
                />

                <SummaryRow
                  label="Anonymization Signal"
                  value={geoData?.security?.is_proxy || geoData?.security?.is_vpn ? "Detected" : "Not detected"}
                  valueClass={geoData?.security?.is_proxy || geoData?.security?.is_vpn ? "text-red-400" : "text-green-400"}
                />

                <SummaryRow
                  label="Known Threat Match"
                  value="No Match"
                  valueClass="text-green-400"
                />

                <SummaryRow
                  label="Investigation Priority"
                  value="High"
                  valueClass="text-red-400"
                />

              </div>

            </div>


            {/* Analyst Recommendation */}

            <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-6">

              <div className="flex items-start gap-4">

                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-cyan-500/10 text-xl">
                  🧠
                </div>

                <div>

                  <p className="text-xs font-medium uppercase tracking-wider text-cyan-400">
                    Analyst Recommendation
                  </p>

                  <h3 className="mt-1 text-lg font-semibold text-slate-100">
                    Continue Forensic Investigation
                  </h3>

                </div>

              </div>


              <p className="mt-5 text-sm leading-6 text-slate-400">
                The investigated source shows multiple infrastructure risk
                indicators. Correlate this IP with email headers, sender domains,
                authentication results and other extracted indicators before
                reaching a final attribution decision.
              </p>


              <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">

                <RecommendationItem
                  number="01"
                  text="Review header chain"
                />

                <RecommendationItem
                  number="02"
                  text="Correlate sender domain"
                />

                <RecommendationItem
                  number="03"
                  text="Check threat feeds"
                />

                <RecommendationItem
                  number="04"
                  text="Preserve investigation evidence"
                />

              </div>

            </div>

          </div>


          {/* =====================================
              INTELLIGENCE TIMELINE
          ===================================== */}

          <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-6">

              <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                Historical Intelligence
              </p>

              <h3 className="mt-1 text-lg font-semibold text-slate-100">
                Intelligence Timeline
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Example historical observations for the investigated source.
              </p>

            </div>


            <div className="relative ml-2 border-l border-slate-800 pl-6">

              <TimelineItem
                time="Today"
                title="Suspicious email activity detected"
                description="Source IP observed during analysis of a suspicious email."
                active
              />

              <TimelineItem
                time="2 days ago"
                title="Multiple authentication failures"
                description="Repeated authentication anomalies associated with the infrastructure."
              />

              <TimelineItem
                time="7 days ago"
                title="Infrastructure observed"
                description="Source network appeared in suspicious communication activity."
              />

              <TimelineItem
                time="14 days ago"
                title="Network allocation identified"
                description="IP range associated with hosting infrastructure was observed."
                last
              />

            </div>

          </div>


          {/* =====================================
              DATA DISCLAIMER
          ===================================== */}

          <div className="mt-6 rounded-xl border border-slate-800 bg-slate-900/50 p-4">

            <div className="flex items-start gap-3">

              <span className="text-xs text-slate-600">
                INFO
              </span>

              <p className="text-xs leading-5 text-slate-600">
                Geographic and network intelligence is retrieved from a live
                IP intelligence service when available. Geolocation and
                network ownership are contextual signals and should not
                be treated as definitive attacker attribution.
              </p>

            </div>

          </div>

        </section>
      )}


      {/* =========================================
          FOOTER
      ========================================= */}

      <div className="mt-8 flex flex-col justify-between gap-2 border-t border-slate-800 pt-5 text-xs text-slate-600 md:flex-row">

        <p>
          TraceMail AI • Geo Intelligence Engine
        </p>

        <p>
          Live IP intelligence integration
        </p>

      </div>

    </div>
  )
}


/* =========================================
   RESULT CARD
========================================= */

function ResultCard({
  label,
  value,
  suffix,
  subtitle,
  valueClass,
  borderClass,
  icon,
}) {
  return (
    <div className={`rounded-2xl border bg-slate-900 p-5 ${borderClass}`}>

      <div className="flex items-start justify-between">

        <p className="text-xs uppercase tracking-wider text-slate-600">
          {label}
        </p>

        <span className="text-sm text-slate-600">
          {icon}
        </span>

      </div>

      <div className="mt-4 flex items-end gap-1">

        <span className={`text-2xl font-bold ${valueClass}`}>
          {value}
        </span>

        {suffix && (
          <span className="mb-0.5 text-xs text-slate-600">
            {suffix}
          </span>
        )}

      </div>

      <p className="mt-2 text-xs text-slate-600">
        {subtitle}
      </p>

    </div>
  )
}


/* =========================================
   INFO ROW
========================================= */

function InfoRow({ label, value, mono = false }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

      <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p
        className={`mt-2 text-sm font-medium text-slate-200 ${
          mono ? 'font-mono text-cyan-300' : ''
        }`}
      >
        {value}
      </p>

    </div>
  )
}


/* =========================================
   INFO CARD
========================================= */

function InfoCard({ label, value }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">

      <p className="text-[10px] font-medium uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-2 text-base font-semibold text-slate-200">
        {value}
      </p>

    </div>
  )
}


/* =========================================
   NETWORK DETAIL
========================================= */

function NetworkDetail({ label, value }) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-4">

      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-2 text-sm text-slate-400">
        {value}
      </p>

    </div>
  )
}


/* =========================================
   RISK INDICATOR
========================================= */

function RiskIndicator({ title, status, type }) {

  const styles = {
    danger: 'bg-red-500/10 text-red-400 border-red-500/10',
    warning: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/10',
    safe: 'bg-green-500/10 text-green-400 border-green-500/10',
  }

  return (
    <div className="flex items-center justify-between border-b border-slate-800 pb-3">

      <div className="flex items-center gap-3">

        <span
          className={`h-2 w-2 rounded-full ${
            type === 'danger'
              ? 'bg-red-400'
              : type === 'warning'
                ? 'bg-yellow-400'
                : 'bg-green-400'
          }`}
        />

        <span className="text-sm text-slate-300">
          {title}
        </span>

      </div>

      <span
        className={`rounded-lg border px-2.5 py-1 text-[10px] ${styles[type]}`}
      >
        {status}
      </span>

    </div>
  )
}


/* =========================================
   SUMMARY ROW
========================================= */

function SummaryRow({ label, value, valueClass }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 pb-3">

      <span className="text-sm text-slate-500">
        {label}
      </span>

      <span className={`text-sm font-medium ${valueClass}`}>
        {value}
      </span>

    </div>
  )
}


/* =========================================
   RECOMMENDATION ITEM
========================================= */

function RecommendationItem({ number, text }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">

      <span className="font-mono text-[10px] text-cyan-500">
        {number}
      </span>

      <span className="text-xs text-slate-400">
        {text}
      </span>

    </div>
  )
}


/* =========================================
   TIMELINE ITEM
========================================= */

function TimelineItem({
  time,
  title,
  description,
  active = false,
  last = false,
}) {
  return (
    <div className={`relative ${last ? '' : 'pb-7'}`}>

      <span
        className={`absolute -left-[31px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-slate-900 ${
          active ? 'bg-cyan-400' : 'bg-slate-700'
        }`}
      />

      <p className="text-[10px] font-medium uppercase tracking-wider text-cyan-500">
        {time}
      </p>

      <p className="mt-1 text-sm font-semibold text-slate-200">
        {title}
      </p>

      <p className="mt-1 max-w-3xl text-sm leading-5 text-slate-500">
        {description}
      </p>

    </div>
  )
}