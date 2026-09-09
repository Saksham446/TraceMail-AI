import { useEffect, useState } from 'react'

function HeaderForensics() {
  const [headerInput, setHeaderInput] = useState('')
  const [analysisStarted, setAnalysisStarted] = useState(false)
  const [analysisResult, setAnalysisResult] = useState(null)
  const [aiAuthentication, setAiAuthentication] = useState(null)

  // =========================================
  // LOAD EMAIL SAVED FROM ANALYZE EMAIL
  // =========================================

  useEffect(() => {
    const savedEmail =
      localStorage.getItem('tracemailRawEmail') ||
      localStorage.getItem('tracemailEmail') ||
      localStorage.getItem('analyzedEmail') ||
      localStorage.getItem('rawEmail')

    // Load the latest AI analysis saved by Analyze Email.
    let savedAiAnalysis = null

    try {
      const rawAiAnalysis =
        localStorage.getItem('tracemail_ai_analysis')

      if (rawAiAnalysis) {
        const parsed = JSON.parse(rawAiAnalysis)

        savedAiAnalysis =
          parsed?.analysis ||
          parsed ||
          null
      }
    } catch (error) {
      console.warn(
        'Unable to read saved AI analysis:',
        error
      )
    }

    if (savedAiAnalysis?.authentication) {
      setAiAuthentication(savedAiAnalysis.authentication)
    }

    if (savedEmail && savedEmail.trim()) {
      setHeaderInput(savedEmail)

      const result = analyzeHeaders(
        savedEmail,
        savedAiAnalysis
      )

      setAnalysisResult(result)
      setAnalysisStarted(true)
    }
  }, [])

  // =========================================
  // GET SINGLE HEADER VALUE
  // =========================================

  const getHeaderValue = (email, headerName) => {
    if (!email) {
      return ''
    }

    const regex = new RegExp(
      `^${headerName}:\\s*(.+)$`,
      'im'
    )

    const match = email.match(regex)

    return match ? match[1].trim() : ''
  }

  // =========================================
  // GET ALL HEADER VALUES
  // =========================================

  const getAllHeaderValues = (email, headerName) => {
    if (!email) {
      return []
    }

    const regex = new RegExp(
      `^${headerName}:\\s*(.+)$`,
      'gim'
    )

    return [...email.matchAll(regex)].map(
      (match) => match[1].trim()
    )
  }

  // =========================================
  // EXTRACT EMAIL ADDRESS
  // =========================================

  const extractEmailAddress = (value) => {
    if (!value) {
      return ''
    }

    const match = value.match(
      /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
    )

    return match ? match[0] : value
  }

  // =========================================
  // EXTRACT DOMAIN
  // =========================================

  const extractDomain = (value) => {
    const email = extractEmailAddress(value)

    const match = email.match(
      /@([a-zA-Z0-9.-]+)/
    )

    return match
      ? match[1].toLowerCase()
      : ''
  }

  // =========================================
  // EXTRACT IP ADDRESSES
  // =========================================

  const extractIps = (text) => {
    if (!text) {
      return []
    }

    const matches = text.match(
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
    )

    return matches || []
  }

  // =========================================
  // PRIVATE IP CHECK
  // =========================================

  const isPrivateIp = (ip) => {
    const parts = ip.split('.').map(Number)

    if (parts.length !== 4) {
      return false
    }

    const [a, b] = parts

    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 127
    )
  }

  // =========================================
  // AUTHENTICATION ANALYSIS
  // =========================================

  const getAuthentication = (email) => {
    const authenticationHeaders =
      getAllHeaderValues(
        email,
        'Authentication-Results'
      )

    const text =
      authenticationHeaders
        .join(' ')
        .toLowerCase()

    const spf =
      text.includes('spf=pass')
        ? 'PASS'
        : text.includes('spf=fail')
          ? 'FAIL'
          : text.includes('spf=softfail')
            ? 'SOFTFAIL'
            : 'UNKNOWN'

    const dkim =
      text.includes('dkim=pass')
        ? 'PASS'
        : text.includes('dkim=fail')
          ? 'FAIL'
          : 'UNKNOWN'

    const dmarc =
      text.includes('dmarc=pass')
        ? 'PASS'
        : text.includes('dmarc=fail')
          ? 'FAIL'
          : 'UNKNOWN'

    return {
      spf,
      dkim,
      dmarc,
    }
  }

  // =========================================
  // PARSE RECEIVED HEADERS
  // =========================================

  const parseReceivedHeaders = (email) => {
    const receivedHeaders =
      getAllHeaderValues(email, 'Received')

    return receivedHeaders.map(
      (header, index) => {
        const ips = extractIps(header)

        const publicIps = ips.filter(
          (ip) => !isPrivateIp(ip)
        )

        const hostnameMatch =
          header.match(
            /from\s+([^\s(]+)/i
          )

        const hostname =
          hostnameMatch
            ? hostnameMatch[1]
            : 'Unknown mail host'

        const sourceIp =
          publicIps[0] ||
          ips[0] ||
          'IP not available'

        return {
          number: index + 1,
          hostname,
          sourceIp,
          suspicious: publicIps.length > 0,
          raw: header,
        }
      }
    )
  }

  // =========================================
  // LOOKALIKE DOMAIN DETECTION
  // =========================================

  const detectLookalikeDomain = (domain) => {
    if (!domain) {
      return ''
    }

    const lowerDomain =
      domain.toLowerCase()

    const patterns = [
      'micros0ft',
      'paypa1',
      'g00gle',
      'app1e',
      'amaz0n',
      'faceb00k',
      'secure-login',
      'account-verify',
      'support-security',
      'microsoft-support',
      'google-security',
      'paypal-security',
    ]

    return patterns.find(
      (pattern) =>
        lowerDomain.includes(pattern)
    ) || ''
  }

  // =========================================
  // ANALYZE HEADERS
  // =========================================

  const analyzeHeaders = (email, savedAiAnalysis = null) => {
    const from =
      getHeaderValue(email, 'From')

    const to =
      getHeaderValue(email, 'To')

    const returnPath =
      getHeaderValue(email, 'Return-Path')

    const replyTo =
      getHeaderValue(email, 'Reply-To')

    const subject =
      getHeaderValue(email, 'Subject')

    const messageId =
      getHeaderValue(email, 'Message-ID')

    const date =
      getHeaderValue(email, 'Date')

    const parsedAuthentication =
      getAuthentication(email)

    // If the submitted email does not contain real
    // Authentication-Results headers, use the authentication
    // result already produced by the TraceMail AI analysis.
    const aiAuthenticationResult =
      savedAiAnalysis?.authentication ||
      aiAuthentication ||
      null

    const authentication = {
      spf:
        parsedAuthentication.spf !== 'UNKNOWN'
          ? parsedAuthentication.spf
          : aiAuthenticationResult?.spf || 'UNKNOWN',

      dkim:
        parsedAuthentication.dkim !== 'UNKNOWN'
          ? parsedAuthentication.dkim
          : aiAuthenticationResult?.dkim || 'UNKNOWN',

      dmarc:
        parsedAuthentication.dmarc !== 'UNKNOWN'
          ? parsedAuthentication.dmarc
          : aiAuthenticationResult?.dmarc || 'UNKNOWN',
    }

    const authenticationSource =
      parsedAuthentication.spf !== 'UNKNOWN' ||
      parsedAuthentication.dkim !== 'UNKNOWN' ||
      parsedAuthentication.dmarc !== 'UNKNOWN'
        ? 'Header evidence'
        : aiAuthenticationResult
          ? 'AI analysis'
          : 'Not available'

    const receivedChain =
      parseReceivedHeaders(email)

    const fromDomain =
      extractDomain(from)

    const returnPathDomain =
      extractDomain(returnPath)

    const replyToDomain =
      extractDomain(replyTo)

    const allIps =
      extractIps(email)

    const publicIps =
      allIps.filter(
        (ip) => !isPrivateIp(ip)
      )

    const findings = []

    let riskScore = 0

    // =========================================
    // SPF
    // =========================================

    if (authentication.spf === 'FAIL') {
      riskScore += 20

      findings.push({
        type: 'danger',
        title: 'SPF authentication failed',
        description:
          'The sending server failed SPF validation. This can indicate unauthorized sending infrastructure or sender spoofing.',
      })
    }

    // =========================================
    // DKIM
    // =========================================

    if (authentication.dkim === 'FAIL') {
      riskScore += 20

      findings.push({
        type: 'danger',
        title: 'DKIM authentication failed',
        description:
          'The email failed DKIM signature verification. Message integrity or sender authenticity requires further investigation.',
      })
    }

    // =========================================
    // DMARC
    // =========================================

    if (authentication.dmarc === 'FAIL') {
      riskScore += 25

      findings.push({
        type: 'danger',
        title: 'DMARC authentication failed',
        description:
          'DMARC failed, indicating a possible domain-alignment or authentication problem.',
      })
    }

    // =========================================
    // RETURN PATH MISMATCH
    // =========================================

    if (
      fromDomain &&
      returnPathDomain &&
      fromDomain !== returnPathDomain
    ) {
      riskScore += 15

      findings.push({
        type: 'warning',
        title: 'From and Return-Path domains differ',
        description:
          `The From domain is ${fromDomain}, while the Return-Path domain is ${returnPathDomain}. This mismatch should be investigated.`,
      })
    }

    // =========================================
    // REPLY-TO MISMATCH
    // =========================================

    if (
      fromDomain &&
      replyToDomain &&
      fromDomain !== replyToDomain
    ) {
      riskScore += 10

      findings.push({
        type: 'warning',
        title: 'Reply-To domain differs from sender',
        description:
          `The Reply-To address uses ${replyToDomain}, which differs from the sender domain ${fromDomain}.`,
      })
    }

    // =========================================
    // LOOKALIKE DOMAIN
    // =========================================

    const lookalike =
      detectLookalikeDomain(fromDomain)

    if (lookalike) {
      riskScore += 20

      findings.push({
        type: 'danger',
        title: 'Potential lookalike domain detected',
        description:
          `The sender domain contains a pattern associated with impersonation: ${lookalike}.`,
      })
    }

    // =========================================
    // PUBLIC INFRASTRUCTURE
    // =========================================

    if (publicIps.length > 0) {
      findings.push({
        type: 'warning',
        title: 'Public routing infrastructure detected',
        description:
          `${publicIps.length} public IP address${publicIps.length === 1 ? '' : 'es'} were extracted from the submitted email headers.`,
      })
    }

    // =========================================
    // MULTIPLE ROUTING HOPS
    // =========================================

    if (receivedChain.length >= 3) {
      findings.push({
        type: 'info',
        title: 'Multiple routing hops detected',
        description:
          `The message contains ${receivedChain.length} Received headers. The complete route should be correlated with infrastructure intelligence.`,
      })
    }

    // =========================================
    // AUTHENTICATION UNKNOWN
    // =========================================

    if (
      authentication.spf === 'UNKNOWN' &&
      authentication.dkim === 'UNKNOWN' &&
      authentication.dmarc === 'UNKNOWN'
    ) {
      riskScore += 10

      findings.push({
        type: 'warning',
        title: 'Authentication results unavailable',
        description:
          'No SPF, DKIM or DMARC result was found in the submitted evidence or the saved AI analysis.',
      })
    }

    // =========================================
    // MESSAGE ID
    // =========================================

    if (!messageId) {
      riskScore += 5

      findings.push({
        type: 'warning',
        title: 'Message-ID header missing',
        description:
          'The submitted evidence does not contain a Message-ID header.',
      })
    }

    // =========================================
    // RECEIVED HEADER
    // =========================================

    if (receivedChain.length === 0) {
      riskScore += 10

      findings.push({
        type: 'warning',
        title: 'Received header chain unavailable',
        description:
          'No Received headers were detected, so the email routing path cannot be reconstructed.',
      })
    }

    // =========================================
    // RISK LIMIT
    // =========================================

    riskScore =
      Math.min(100, riskScore)

    let riskLevel = 'Low'

    if (riskScore >= 75) {
      riskLevel = 'Critical'
    } else if (riskScore >= 50) {
      riskLevel = 'High'
    } else if (riskScore >= 25) {
      riskLevel = 'Medium'
    }

    // =========================================
    // SOURCE IP
    // =========================================

    const sourceIp =
      receivedChain.find(
        (hop) =>
          hop.sourceIp !== 'IP not available'
      )?.sourceIp ||
      publicIps[0] ||
      'Not available'

    return {
      from:
        from || 'Not available',

      to:
        to || 'Not available',

      returnPath:
        returnPath || 'Not available',

      replyTo:
        replyTo || 'Not available',

      subject:
        subject || 'Not available',

      messageId:
        messageId || 'Not available',

      date:
        date || 'Not available',

      fromDomain:
        fromDomain || 'Not available',

      sourceIp,

      authentication,

      authenticationSource,

      receivedChain,

      riskScore,

      riskLevel,

      findings,
    }
  }

  // =========================================
  // ANALYZE BUTTON
  // =========================================

  const handleAnalyze = () => {
    if (!headerInput.trim()) {
      return
    }

    // Save the email so other pages can use it
    localStorage.setItem(
      'tracemailRawEmail',
      headerInput
    )

    localStorage.setItem(
      'tracemailEmail',
      headerInput
    )

    let savedAiAnalysis = null

    try {
      const rawAiAnalysis =
        localStorage.getItem('tracemail_ai_analysis')

      if (rawAiAnalysis) {
        const parsed = JSON.parse(rawAiAnalysis)

        savedAiAnalysis =
          parsed?.analysis ||
          parsed ||
          null
      }
    } catch (error) {
      console.warn(
        'Unable to read saved AI analysis:',
        error
      )
    }

    if (savedAiAnalysis?.authentication) {
      setAiAuthentication(savedAiAnalysis.authentication)
    }

    const result =
      analyzeHeaders(
        headerInput,
        savedAiAnalysis
      )

    setAnalysisResult(result)
    setAnalysisStarted(true)
  }

  // =========================================
  // CLEAR
  // =========================================

  const clearHeaders = () => {
    setHeaderInput('')
    setAnalysisStarted(false)
    setAnalysisResult(null)
    setAiAuthentication(null)

    localStorage.removeItem(
      'tracemailRawEmail'
    )

    localStorage.removeItem(
      'tracemailEmail'
    )

    localStorage.removeItem(
      'analyzedEmail'
    )

    localStorage.removeItem(
      'rawEmail'
    )
  }

  // =========================================
  // AUTHENTICATION COLOR
  // =========================================

  const getAuthClass = (status) => {
    if (status === 'PASS') {
      return 'text-green-400 bg-green-500/10'
    }

    if (
      status === 'UNKNOWN' ||
      status === 'SOFTFAIL'
    ) {
      return 'text-yellow-400 bg-yellow-500/10'
    }

    return 'text-red-400 bg-red-500/10'
  }

  // =========================================
  // RISK COLOR
  // =========================================

  const getRiskClass = (level) => {
    if (level === 'Critical') {
      return 'text-red-400 bg-red-500/10 border-red-500/20'
    }

    if (level === 'High') {
      return 'text-orange-400 bg-orange-500/10 border-orange-500/20'
    }

    if (level === 'Medium') {
      return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
    }

    return 'text-green-400 bg-green-500/10 border-green-500/20'
  }

  // =========================================
  // AUTHENTICATION RISK
  // =========================================

  const hasAuthenticationRisk =
    analysisResult &&
    (
      analysisResult.authentication.spf === 'FAIL' ||
      analysisResult.authentication.dkim === 'FAIL' ||
      analysisResult.authentication.dmarc === 'FAIL'
    )

  return (
    <div className="p-8">

      {/* =========================================
          PAGE HEADER
      ========================================= */}

      <div className="mb-8">

        <p className="text-sm font-medium text-cyan-400">
          EMAIL FORENSICS
        </p>

        <h1 className="mt-2 text-3xl font-bold text-slate-100">
          Header Forensics
        </h1>

        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Examine email routing headers, sender infrastructure,
          authentication results and delivery anomalies to identify
          potential spoofing and malicious activity.
        </p>

      </div>

      {/* =========================================
          MAIN GRID
      ========================================= */}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">

        {/* =========================================
            LEFT SIDE
        ========================================= */}

        <div className="space-y-6 xl:col-span-2">

          {/* =========================================
              HEADER INPUT
          ========================================= */}

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-5 flex items-start justify-between gap-4">

              <div>

                <h2 className="text-lg font-semibold text-slate-100">
                  Raw Email Headers
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Email evidence from Analyze Email is loaded automatically.
                </p>

              </div>

              {headerInput && (
                <button
                  type="button"
                  onClick={clearHeaders}
                  className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-400 transition hover:border-red-500/40 hover:text-red-400"
                >
                  Clear
                </button>
              )}

            </div>

            <textarea
              rows="18"
              value={headerInput}
              onChange={(event) => {
                setHeaderInput(event.target.value)
                setAnalysisStarted(false)
                setAnalysisResult(null)

                localStorage.setItem(
                  'tracemailRawEmail',
                  event.target.value
                )

                localStorage.setItem(
                  'tracemailEmail',
                  event.target.value
                )
              }}
              placeholder={`Return-Path: <sender@example.com>
Received: from mail.example.com (192.168.1.10)
Received: from smtp.example.net (185.220.101.42)
From: sender@example.com
To: recipient@example.com
Subject: Urgent Account Verification
Date: Fri, 04 Sep 2026 10:30:00 +0530
Message-ID: <example@email.com>
Reply-To: support@example.com
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Paste complete email headers here...`}
              className="w-full resize-none rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-sm leading-6 text-slate-300 outline-none placeholder:text-slate-700 focus:border-cyan-500/50"
            />

            <div className="mt-3 flex items-center justify-between">

              <p className="text-xs text-slate-600">
                Header evidence
              </p>

              <p className="text-xs text-slate-600">
                {headerInput.length.toLocaleString()} characters
              </p>

            </div>

            <button
              type="button"
              onClick={handleAnalyze}
              disabled={!headerInput.trim()}
              className="mt-5 w-full rounded-lg bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {analysisStarted
                ? 'Forensic Analysis Completed ✓'
                : 'Analyze Headers →'}
            </button>

            {analysisStarted && (
              <div className="mt-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">

                <div className="flex items-center gap-3">

                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10">
                    🔍
                  </div>

                  <div>

                    <p className="text-sm font-medium text-cyan-400">
                      Header analysis completed
                    </p>

                    <p className="mt-1 text-xs text-slate-500">
                      Routing, sender identity and authentication evidence
                      has been extracted from the submitted headers.
                    </p>

                  </div>

                </div>

              </div>
            )}

          </div>

          {/* =========================================
              HEADER OVERVIEW
          ========================================= */}

          {analysisStarted && analysisResult && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-5">

                <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                  Header Intelligence
                </p>

                <h2 className="mt-1 text-lg font-semibold text-slate-100">
                  Header Overview
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Key fields extracted directly from the submitted email.
                </p>

              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs text-slate-600">From</p>
                  <p className="mt-2 break-all text-sm text-slate-300">
                    {analysisResult.from}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs text-slate-600">To</p>
                  <p className="mt-2 break-all text-sm text-slate-300">
                    {analysisResult.to}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs text-slate-600">Return-Path</p>
                  <p className="mt-2 break-all text-sm text-slate-300">
                    {analysisResult.returnPath}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs text-slate-600">Reply-To</p>
                  <p className="mt-2 break-all text-sm text-slate-300">
                    {analysisResult.replyTo}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs text-slate-600">Message-ID</p>
                  <p className="mt-2 break-all font-mono text-sm text-slate-300">
                    {analysisResult.messageId}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <p className="text-xs text-slate-600">Date</p>
                  <p className="mt-2 text-sm text-slate-300">
                    {analysisResult.date}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 sm:col-span-2">
                  <p className="text-xs text-slate-600">Subject</p>
                  <p className="mt-2 text-sm text-slate-300">
                    {analysisResult.subject}
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 sm:col-span-2">
                  <p className="text-xs text-slate-600">
                    Sender Domain
                  </p>
                  <p className="mt-2 break-all font-mono text-sm text-cyan-400">
                    {analysisResult.fromDomain}
                  </p>
                </div>

              </div>

            </div>
          )}

          {/* =========================================
              RECEIVED CHAIN
          ========================================= */}

          {analysisStarted && analysisResult && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-6">

                <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
                  Routing Analysis
                </p>

                <h2 className="mt-1 text-lg font-semibold text-slate-100">
                  Received Header Chain
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Mail servers encountered during message delivery.
                </p>

              </div>

              {analysisResult.receivedChain.length === 0 ? (

                <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-5">

                  <p className="text-sm font-medium text-yellow-400">
                    No Received headers detected
                  </p>

                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    The supplied header evidence does not contain a
                    reconstructable mail routing chain.
                  </p>

                </div>

              ) : (

                <div className="space-y-4">

                  {analysisResult.receivedChain.map(
                    (hop) => (
                      <div
                        key={hop.number}
                        className="relative flex gap-4"
                      >

                        <div
                          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm ${
                            hop.suspicious
                              ? 'bg-yellow-500/10 text-yellow-400'
                              : 'bg-cyan-500/10 text-cyan-400'
                          }`}
                        >
                          {hop.number}
                        </div>

                        <div
                          className={`flex-1 rounded-xl border bg-slate-950 p-4 ${
                            hop.suspicious
                              ? 'border-yellow-500/10'
                              : 'border-slate-800'
                          }`}
                        >

                          <div className="flex flex-col items-start justify-between gap-2 sm:flex-row sm:items-center">

                            <p className="break-all text-sm font-medium text-slate-200">
                              {hop.hostname}
                            </p>

                            <span
                              className={`text-xs ${
                                hop.suspicious
                                  ? 'text-yellow-400'
                                  : 'text-green-400'
                              }`}
                            >
                              {hop.suspicious
                                ? 'External'
                                : 'Internal'}
                            </span>

                          </div>

                          <p className="mt-2 font-mono text-xs text-slate-500">
                            {hop.sourceIp}
                          </p>

                          <p className="mt-2 break-all text-xs text-slate-600">
                            {hop.raw}
                          </p>

                        </div>

                      </div>
                    )
                  )}

                </div>

              )}

            </div>
          )}

          {/* =========================================
              FORENSIC FINDINGS
          ========================================= */}

          {analysisStarted && analysisResult && (
            <div className="rounded-2xl border border-yellow-500/20 bg-slate-900 p-6">

              <div className="flex flex-col items-start justify-between gap-5 sm:flex-row">

                <div className="flex items-start gap-4">

                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-yellow-500/10 text-xl">
                    ⚠️
                  </div>

                  <div>

                    <p className="text-sm font-medium text-yellow-400">
                      Forensic Findings
                    </p>

                    <h2 className="mt-1 text-xl font-semibold text-slate-100">
                      Header Risk Assessment
                    </h2>

                    <p className="mt-2 text-sm leading-6 text-slate-500">
                      Findings are generated from the supplied routing,
                      identity and authentication headers.
                    </p>

                  </div>

                </div>

                <div
                  className={`rounded-xl border px-4 py-3 text-right ${getRiskClass(
                    analysisResult.riskLevel
                  )}`}
                >

                  <p className="text-xs opacity-70">
                    Header Risk
                  </p>

                  <p className="mt-1 text-lg font-bold">
                    {analysisResult.riskScore}/100
                  </p>

                  <p className="mt-1 text-xs">
                    {analysisResult.riskLevel}
                  </p>

                </div>

              </div>

              {analysisResult.findings.length === 0 ? (

                <div className="mt-6 rounded-xl border border-green-500/20 bg-green-500/5 p-5">

                  <p className="text-sm font-medium text-green-400">
                    No major header anomalies detected
                  </p>

                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    The supplied headers did not trigger the configured
                    forensic risk checks.
                  </p>

                </div>

              ) : (

                <div className="mt-6 space-y-3">

                  {analysisResult.findings.map(
                    (finding, index) => (

                      <div
                        key={index}
                        className={`rounded-xl border p-4 ${
                          finding.type === 'danger'
                            ? 'border-red-500/10 bg-red-500/5'
                            : finding.type === 'warning'
                              ? 'border-yellow-500/10 bg-yellow-500/5'
                              : 'border-cyan-500/10 bg-cyan-500/5'
                        }`}
                      >

                        <div className="flex items-start gap-3">

                          <span
                            className={
                              finding.type === 'danger'
                                ? 'text-red-400'
                                : finding.type === 'warning'
                                  ? 'text-yellow-400'
                                  : 'text-cyan-400'
                            }
                          >
                            {finding.type === 'danger'
                              ? '!'
                              : finding.type === 'warning'
                                ? '!'
                                : 'i'}
                          </span>

                          <div>

                            <p className="text-sm font-medium text-slate-300">
                              {finding.title}
                            </p>

                            <p className="mt-1 text-xs leading-5 text-slate-600">
                              {finding.description}
                            </p>

                          </div>

                        </div>

                      </div>

                    )
                  )}

                </div>

              )}

            </div>
          )}

        </div>

        {/* =========================================
            RIGHT SIDE
        ========================================= */}

        <div>

          <div className="sticky top-28 space-y-5">

            {/* =========================================
                AUTHENTICATION
            ========================================= */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-5">

                <h2 className="font-semibold text-slate-100">
                  Authentication
                </h2>

                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Sender authentication verification.
                </p>

              </div>

              <div className="space-y-3">

                {/* SPF */}

                <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-4">

                  <div>

                    <p className="text-sm font-medium text-slate-300">
                      SPF
                    </p>

                    <p className="mt-1 text-xs text-slate-600">
                      Sender Policy Framework
                    </p>

                  </div>

                  <span
                    className={`rounded-full px-3 py-1 text-xs font-medium ${getAuthClass(
                      analysisResult?.authentication.spf || 'UNKNOWN'
                    )}`}
                  >
                    {analysisResult?.authentication.spf || 'UNKNOWN'}
                  </span>

                </div>

                {/* DKIM */}

                <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-4">

                  <div>

                    <p className="text-sm font-medium text-slate-300">
                      DKIM
                    </p>

                    <p className="mt-1 text-xs text-slate-600">
                      DomainKeys Identified Mail
                    </p>

                  </div>

                  <span
                    className={`rounded-full px-3 py-1 text-xs font-medium ${getAuthClass(
                      analysisResult?.authentication.dkim || 'UNKNOWN'
                    )}`}
                  >
                    {analysisResult?.authentication.dkim || 'UNKNOWN'}
                  </span>

                </div>

                {/* DMARC */}

                <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-4">

                  <div>

                    <p className="text-sm font-medium text-slate-300">
                      DMARC
                    </p>

                    <p className="mt-1 text-xs text-slate-600">
                      Domain alignment
                    </p>

                  </div>

                  <span
                    className={`rounded-full px-3 py-1 text-xs font-medium ${getAuthClass(
                      analysisResult?.authentication.dmarc || 'UNKNOWN'
                    )}`}
                  >
                    {analysisResult?.authentication.dmarc || 'UNKNOWN'}
                  </span>

                </div>

              </div>

              {analysisStarted && analysisResult && (
                <div className="mt-4 flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">
                  <span className="text-xs text-slate-600">
                    Authentication source
                  </span>

                  <span className="text-xs font-medium text-cyan-400">
                    {analysisResult.authenticationSource || 'Not available'}
                  </span>
                </div>
              )}

              {analysisStarted && analysisResult && (
                <div
                  className={`mt-5 rounded-xl border p-4 ${
                    hasAuthenticationRisk
                      ? 'border-red-500/10 bg-red-500/5'
                      : 'border-green-500/10 bg-green-500/5'
                  }`}
                >

                  <p
                    className={`text-xs font-medium ${
                      hasAuthenticationRisk
                        ? 'text-red-400'
                        : 'text-green-400'
                    }`}
                  >
                    {hasAuthenticationRisk
                      ? 'Authentication Risk'
                      : 'Authentication Status'}
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    {hasAuthenticationRisk
                      ? 'One or more authentication checks failed and should be correlated with sender identity and routing evidence.'
                      : analysisResult.authenticationSource === 'AI analysis'
                        ? 'Authentication results were supplied by the TraceMail AI analysis because the pasted evidence does not contain Authentication-Results headers.'
                        : 'No authentication failures were detected in the supplied Authentication-Results header.'}
                  </p>

                </div>
              )}

            </div>

            {/* =========================================
                SOURCE INTELLIGENCE
            ========================================= */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <div className="mb-5">

                <h2 className="font-semibold text-slate-100">
                  Source Intelligence
                </h2>

                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Infrastructure extracted from routing headers.
                </p>

              </div>

              <div className="space-y-4">

                <div>

                  <p className="text-xs text-slate-600">
                    Source IP
                  </p>

                  <p className="mt-2 break-all font-mono text-sm text-slate-200">
                    {analysisResult?.sourceIp || 'Awaiting analysis'}
                  </p>

                </div>

                <div>

                  <p className="text-xs text-slate-600">
                    Sender Domain
                  </p>

                  <p className="mt-2 break-all font-mono text-sm text-slate-300">
                    {analysisResult?.fromDomain || 'Awaiting analysis'}
                  </p>

                </div>

                <div>

                  <p className="text-xs text-slate-600">
                    Routing Hops
                  </p>

                  <p className="mt-2 text-sm text-slate-300">
                    {analysisResult
                      ? analysisResult.receivedChain.length
                      : 'Awaiting analysis'}
                  </p>

                </div>

                <div>

                  <p className="text-xs text-slate-600">
                    Public IPs
                  </p>

                  <p className="mt-2 text-sm text-cyan-400">
                    {analysisResult
                      ? new Set(
                          analysisResult.receivedChain
                            .map((hop) => hop.sourceIp)
                            .filter(
                              (ip) =>
                                ip !== 'IP not available'
                            )
                        ).size
                      : 'Awaiting analysis'}
                  </p>

                </div>

              </div>

              <div className="mt-5 rounded-lg border border-yellow-500/10 bg-yellow-500/5 p-3">

                <p className="text-xs leading-5 text-slate-600">
                  IP extraction identifies infrastructure for further
                  investigation. It does not by itself identify the
                  person operating that infrastructure.
                </p>

              </div>

            </div>

            {/* =========================================
                FORENSIC CHECKS
            ========================================= */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <h2 className="font-semibold text-slate-100">
                Forensic Checks
              </h2>

              <div className="mt-4 space-y-3">

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Header structure
                  </span>

                  <span className="text-xs text-green-400">
                    {analysisStarted
                      ? '✓ Parsed'
                      : 'Ready'}
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Received chain
                  </span>

                  <span
                    className={`text-xs ${
                      analysisResult?.receivedChain.length
                        ? 'text-green-400'
                        : 'text-yellow-400'
                    }`}
                  >
                    {analysisResult
                      ? analysisResult.receivedChain.length
                        ? `${analysisResult.receivedChain.length} hops`
                        : 'Not found'
                      : 'Pending'}
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Authentication
                  </span>

                  <span
                    className={`text-xs ${
                      hasAuthenticationRisk
                        ? 'text-red-400'
                        : analysisResult
                          ? 'text-green-400'
                          : 'text-yellow-400'
                    }`}
                  >
                    {analysisResult
                      ? hasAuthenticationRisk
                        ? 'Risk'
                        : 'Checked'
                      : 'Pending'}
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Message-ID
                  </span>

                  <span
                    className={`text-xs ${
                      analysisResult?.messageId &&
                      analysisResult.messageId !== 'Not available'
                        ? 'text-green-400'
                        : 'text-yellow-400'
                    }`}
                  >
                    {analysisResult?.messageId &&
                    analysisResult.messageId !== 'Not available'
                      ? '✓ Present'
                      : analysisResult
                        ? 'Missing'
                        : 'Pending'}
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Risk assessment
                  </span>

                  <span
                    className={`text-xs ${
                      analysisResult?.riskLevel === 'Critical'
                        ? 'text-red-400'
                        : analysisResult?.riskLevel === 'High'
                          ? 'text-orange-400'
                          : analysisResult?.riskLevel === 'Medium'
                            ? 'text-yellow-400'
                            : analysisResult
                              ? 'text-green-400'
                              : 'text-yellow-400'
                    }`}
                  >
                    {analysisResult?.riskLevel || 'Pending'}
                  </span>

                </div>

              </div>

            </div>

            {/* =========================================
                FORENSIC PIPELINE
            ========================================= */}

            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

              <h2 className="font-semibold text-slate-100">
                Forensic Pipeline
              </h2>

              <div className="mt-5 space-y-4">

                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-green-500/10 text-xs text-green-400">
                    ✓
                  </div>
                  <span className="text-xs text-slate-400">
                    Parse headers
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-green-500/10 text-xs text-green-400">
                    ✓
                  </div>
                  <span className="text-xs text-slate-400">
                    Reconstruct routing
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-green-500/10 text-xs text-green-400">
                    ✓
                  </div>
                  <span className="text-xs text-slate-400">
                    Validate authentication
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-green-500/10 text-xs text-green-400">
                    ✓
                  </div>
                  <span className="text-xs text-slate-400">
                    Generate findings
                  </span>
                </div>

                <div className="flex items-center gap-3">

                  <div className="flex h-7 w-7 items-center justify-center rounded-full border border-slate-700 text-xs text-slate-500">
                    5
                  </div>

                  <span className="text-xs text-slate-500">
                    Threat-intelligence correlation
                  </span>

                </div>

              </div>

            </div>

          </div>

        </div>

      </div>

    </div>
  )
}

export default HeaderForensics