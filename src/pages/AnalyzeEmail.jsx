import { useEffect, useState } from 'react'

const TICKET_API_URL = 'http://localhost:5001/api/tickets'
const AI_API_URL = 'http://localhost:5001/api/ai/analyze'

const STORAGE_KEY = 'tracemailRawEmail'

const LEGACY_STORAGE_KEYS = [
  'tracemail_raw_email',
  'tracemailEmail',
  'analyzedEmail',
  'rawEmail',
]

const getSavedEmail = () => {
  const keys = [STORAGE_KEY, ...LEGACY_STORAGE_KEYS]

  for (const key of keys) {
    const value = localStorage.getItem(key)

    if (value && value.trim()) {
      return value
    }
  }

  return ''
}

const saveEmailEvidence = (email) => {
  if (!email || !email.trim()) return

  localStorage.setItem(STORAGE_KEY, email)
  localStorage.setItem('tracemail_raw_email', email)
  localStorage.setItem('tracemailEmail', email)
  localStorage.setItem('analyzedEmail', email)
  localStorage.setItem('rawEmail', email)
}

const clearSavedEmail = () => {
  localStorage.removeItem(STORAGE_KEY)

  LEGACY_STORAGE_KEYS.forEach((key) => {
    localStorage.removeItem(key)
  })
}

function AnalyzeEmail() {
  const [selectedFile, setSelectedFile] = useState(null)

  const [rawEmail, setRawEmail] = useState(
    () => localStorage.getItem(STORAGE_KEY) || ''
  )

  const [analysisStarted, setAnalysisStarted] = useState(false)
  const [analysisResult, setAnalysisResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState('')

  // =========================================
  // VOICE THREAT ALERT
  // =========================================

  const [voiceAlertsEnabled, setVoiceAlertsEnabled] = useState(true)
  const [voiceAlertStatus, setVoiceAlertStatus] = useState('Ready')

  const speakThreatAlert = (result) => {
    if (!result || !voiceAlertsEnabled) return

    const severity = String(result.severity || '').toLowerCase()

    // Voice alert is intentionally limited to high-risk threats.
    if (severity !== 'critical' && severity !== 'high') {
      return
    }

    if (
      typeof window === 'undefined' ||
      !('speechSynthesis' in window)
    ) {
      setVoiceAlertStatus('Voice not supported by browser')
      return
    }

    const classification =
      result.classification || 'suspicious'

    const category =
      result.category || 'email threat'

    const score =
      result.threatScore ?? 0

    const message =
      severity === 'critical'
        ? `Security Alert. Critical ${classification} email detected. Threat score ${score} out of 100. Category: ${category}. Immediate investigation is recommended.`
        : `Security Alert. High risk ${classification} email detected. Threat score ${score} out of 100. Category: ${category}. Investigation is recommended.`

    try {
      window.speechSynthesis.cancel()

      const utterance =
        new SpeechSynthesisUtterance(message)

      utterance.rate = 0.95
      utterance.pitch = 1
      utterance.volume = 1

      utterance.onstart = () => {
        setVoiceAlertStatus('Alert speaking...')
      }

      utterance.onend = () => {
        setVoiceAlertStatus('Alert spoken')
      }

      utterance.onerror = () => {
        setVoiceAlertStatus(
          'Voice blocked — click Enable Voice Alert'
        )
      }

      window.speechSynthesis.speak(utterance)

    } catch (voiceError) {
      console.error(
        'Voice alert error:',
        voiceError
      )

      setVoiceAlertStatus(
        'Voice alert unavailable'
      )
    }
  }

  const toggleVoiceAlerts = () => {
    if (
      typeof window === 'undefined' ||
      !('speechSynthesis' in window)
    ) {
      setVoiceAlertStatus('Voice not supported by browser')
      return
    }

    if (voiceAlertsEnabled) {
      window.speechSynthesis.cancel()
      setVoiceAlertsEnabled(false)
      setVoiceAlertStatus('Disabled')
      return
    }

    setVoiceAlertsEnabled(true)

    try {
      const testUtterance =
        new SpeechSynthesisUtterance(
          'TraceMail voice threat alerts are enabled.'
        )

      testUtterance.rate = 0.95
      testUtterance.volume = 1

      testUtterance.onend = () => {
        setVoiceAlertStatus('Ready')
      }

      testUtterance.onerror = () => {
        setVoiceAlertStatus(
          'Voice blocked by browser'
        )
      }

      window.speechSynthesis.cancel()
      window.speechSynthesis.speak(
        testUtterance
      )

    } catch {
      setVoiceAlertStatus(
        'Voice alert unavailable'
      )
    }
  }

  // Speak once whenever a new analysis result arrives.
  useEffect(() => {
    if (!analysisResult) return

    const severity = String(
      analysisResult.severity || ''
    ).toLowerCase()

    if (
      voiceAlertsEnabled &&
      (severity === 'critical' ||
        severity === 'high')
    ) {
      // Small delay gives the browser time to finish the
      // analysis/render cycle before starting speech.
      const timer = setTimeout(() => {
        speakThreatAlert(analysisResult)
      }, 250)

      return () => clearTimeout(timer)
    }
  }, [analysisResult])

  useEffect(() => {
    const savedEmail = getSavedEmail()

    if (savedEmail) {
      setRawEmail(savedEmail)
    }
  }, [])

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]

    if (file) {
      setSelectedFile(file)
      setAnalysisStarted(false)
      setAnalysisResult(null)
      setError('')
    }
  }

  const removeFile = () => {
    setSelectedFile(null)
    setAnalysisStarted(false)
    setAnalysisResult(null)
    setError('')
  }

  // =========================================
  // EXTRACT HEADER VALUE
  // =========================================

  const getHeaderValue = (email, headerName) => {
    const regex = new RegExp(`^${headerName}:\\s*(.+)$`, 'im')
    const match = email.match(regex)

    return match ? match[1].trim() : ''
  }

  // =========================================
  // EXTRACT DOMAIN
  // =========================================

  const getDomain = (email) => {
    const match = email.match(/@([a-zA-Z0-9.-]+)/)

    return match ? match[1] : ''
  }

  // =========================================
  // EXTRACT SOURCE IP
  // =========================================

  const getSourceIp = (email) => {
    const ipMatch = email.match(
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/
    )

    return ipMatch ? ipMatch[0] : ''
  }

  // =========================================
  // EXTRACT SPF / DKIM / DMARC
  // =========================================

  const getAuthentication = (email) => {
    const authenticationHeader = email.match(
      /Authentication-Results:[\s\S]*?(?=\n\S[^ \t]*:|\n\n|$)/i
    )

    const text = authenticationHeader
      ? authenticationHeader[0].toLowerCase()
      : email.toLowerCase()

    const spf = text.includes('spf=pass')
      ? 'PASS'
      : text.includes('spf=fail')
        ? 'FAIL'
        : 'UNKNOWN'

    const dkim = text.includes('dkim=pass')
      ? 'PASS'
      : text.includes('dkim=fail')
        ? 'FAIL'
        : 'UNKNOWN'

    const dmarc = text.includes('dmarc=pass')
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
  // ANALYZE EMAIL
  // =========================================

  const handleAnalyze = async () => {
    if (!selectedFile && !rawEmail.trim()) {
      setError('Please upload an email or paste email content first.')
      return
    }

    setIsAnalyzing(true)
    setAnalysisStarted(false)
    setAnalysisResult(null)
    setError('')

    try {
      let emailData = rawEmail.trim()

      // =========================================
      // READ .EML FILE
      // =========================================

      if (selectedFile) {
        emailData = await selectedFile.text()
      }

      if (!emailData.trim()) {
        throw new Error('Unable to read email content.')
      }

      // =========================================
      // SAVE EMAIL FOR OTHER MODULES
      // =========================================

      saveEmailEvidence(emailData)

      // =========================================
      // EXTRACT EMAIL INFORMATION
      // =========================================

      const subject =
        getHeaderValue(emailData, 'Subject') ||
        'Suspicious Email Investigation'

      const sender =
        getHeaderValue(emailData, 'From') ||
        'unknown@example.com'

      const recipient =
        getHeaderValue(emailData, 'To') ||
        'unknown@example.com'

      const sourceIp =
        getSourceIp(emailData) ||
        '185.220.101.42'

      const domain =
        getDomain(sender) ||
        'unknown-domain.com'

      const authentication =
        getAuthentication(emailData)

      // =========================================
      // STEP 1 — SEND EMAIL TO AI SERVICE
      // =========================================

      console.log('🤖 Sending email to TraceMail AI...')

      const aiResponse = await fetch(AI_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subject,
          sender,
          body: emailData,
          spf: authentication.spf,
          dkim: authentication.dkim,
          dmarc: authentication.dmarc,
          sourceIp,
          domain,
        }),
      })

      const aiData = await aiResponse.json()

      if (!aiResponse.ok || !aiData.success) {
        throw new Error(
          aiData.message || 'AI analysis failed.'
        )
      }

      console.log('✅ AI analysis received')

      const aiAnalysis = aiData.analysis

      // =========================================
      // STEP 2 — CREATE TICKET ID
      // =========================================

      const ticketId =
        `TM-${new Date().getFullYear()}-${Date.now()
          .toString()
          .slice(-6)}`

      // =========================================
      // STEP 3 — STORE RESULT IN MONGODB
      // =========================================

      console.log('🗄️ Saving investigation to backend...')

      const ticketResponse = await fetch(TICKET_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ticketId,
          subject,
          sender,
          recipient,
          emailBody: emailData,

          category:
            aiAnalysis.category || 'Suspicious',

          priority:
            aiAnalysis.priority || 'Medium',

          status: 'Investigating',

          threatScore:
            aiAnalysis.threatScore || 0,

          aiConfidence:
            aiAnalysis.confidence || 0,

          authentication: {
            spf:
              aiAnalysis.authentication?.spf ||
              authentication.spf,

            dkim:
              aiAnalysis.authentication?.dkim ||
              authentication.dkim,

            dmarc:
              aiAnalysis.authentication?.dmarc ||
              authentication.dmarc,
          },

          sourceIp:
            aiAnalysis.sourceIp || sourceIp,

          domain:
            aiAnalysis.domain || domain,

          indicators:
            aiAnalysis.indicators || [],

          assignedTeam:
            'Threat Intelligence',

          recommendedSolution:
            aiAnalysis.recommendedActions?.join(' ') ||
            'Verify sender identity, investigate source IP and suspicious indicators, and block malicious infrastructure if confirmed.',
        }),
      })

      const ticketData = await ticketResponse.json()

      if (!ticketResponse.ok || !ticketData.success) {
        throw new Error(
          ticketData.message ||
            'Failed to store investigation in database.'
        )
      }

      console.log('✅ Investigation stored successfully')

      // Save the exact analyzed evidence again so Header Forensics,
      // Geo Intelligence and other modules can reuse it.
      saveEmailEvidence(emailData)

      // =========================================
      // STEP 4 — SHOW RESULT ON FRONTEND
      // =========================================

      setAnalysisResult({
        threatScore:
          aiAnalysis.threatScore ?? 0,

        classification:
          aiAnalysis.classification || 'Unknown',

        confidence:
          aiAnalysis.confidence ?? 0,

        priority:
          aiAnalysis.priority || 'Medium',

        severity:
          aiAnalysis.severity || 'Medium',

        category:
          aiAnalysis.category || 'Suspicious',

        authentication:
          aiAnalysis.authentication || authentication,

        indicators:
          aiAnalysis.indicatorCount ??
          aiAnalysis.indicators?.length ??
          0,

        indicatorList:
          aiAnalysis.indicators || [],

        riskFactors:
          aiAnalysis.riskFactors || [],

        explanation:
          aiAnalysis.explanation ||
          'No additional explanation available.',

        recommendedActions:
          aiAnalysis.recommendedActions || [],

        urlsDetected:
          aiAnalysis.urlsDetected || [],

        urlCount:
          aiAnalysis.urlCount ||
          aiAnalysis.urlsDetected?.length ||
          0,

        sourceIp:
          aiAnalysis.sourceIp || sourceIp,

        domain:
          aiAnalysis.domain || domain,

        location:
          'Pending Geo Intelligence',
      })

      setAnalysisStarted(true)

    } catch (error) {
      console.error('Analysis error:', error)

      setError(
        error.message ||
          'Unable to connect to TraceMail AI services.'
      )
    } finally {
      setIsAnalyzing(false)
    }
  }

  // =========================================
  // SEVERITY COLOR
  // =========================================

  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'Critical':
        return 'text-red-400 bg-red-500/10 border-red-500/20'

      case 'High':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/20'

      case 'Medium':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'

      default:
        return 'text-green-400 bg-green-500/10 border-green-500/20'
    }
  }

  // =========================================
  // CLASSIFICATION COLOR
  // =========================================

  const getClassificationClass = (classification) => {
    if (classification === 'Malicious') {
      return 'text-red-400'
    }

    if (classification === 'Suspicious') {
      return 'text-yellow-400'
    }

    return 'text-green-400'
  }

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
          Analyze Email
        </h1>

        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Upload a raw email or paste complete email headers to detect
          phishing, impersonation, fraud indicators and suspicious
          sender infrastructure.
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
              UPLOAD EMAIL
          ========================================= */}

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-slate-100">
                Upload Email Evidence
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Supported format: .eml
              </p>

            </div>

            {!selectedFile ? (

              <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-slate-950/60 px-6 py-12 text-center transition hover:border-cyan-500/50 hover:bg-slate-950">

                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/10 text-2xl">
                  📤
                </div>

                <p className="font-medium text-slate-200">
                  Drop your .eml file here
                </p>

                <p className="mt-2 text-sm text-slate-500">
                  or click to browse from your computer
                </p>

                <p className="mt-4 text-xs text-slate-600">
                  Maximum recommended file size: 10 MB
                </p>

                <input
                  type="file"
                  accept=".eml,message/rfc822"
                  className="hidden"
                  onChange={handleFileChange}
                />

              </label>

            ) : (

              <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-5">

                <div className="flex items-start justify-between gap-4">

                  <div className="flex items-center gap-4">

                    <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-green-500/10 text-xl">
                      📧
                    </div>

                    <div className="min-w-0">

                      <p className="text-sm font-medium text-green-400">
                        Email evidence selected
                      </p>

                      <p className="mt-1 truncate text-sm text-slate-200">
                        {selectedFile.name}
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        {(selectedFile.size / 1024).toFixed(1)} KB
                        {' • '}
                        {selectedFile.type || '.eml'}
                      </p>

                    </div>

                  </div>

                  <button
                    type="button"
                    onClick={removeFile}
                    className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-400 transition hover:border-red-500/40 hover:text-red-400"
                  >
                    Remove
                  </button>

                </div>

                <div className="mt-5 border-t border-slate-800 pt-4">

                  <div className="flex items-center gap-2">

                    <span className="h-2 w-2 rounded-full bg-green-400"></span>

                    <span className="text-xs text-slate-400">
                      Ready for forensic analysis
                    </span>

                  </div>

                </div>

              </div>

            )}

          </div>

          {/* =========================================
              RAW EMAIL
          ========================================= */}

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-slate-100">
                Raw Email / Headers
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Paste the complete raw email including its headers.
              </p>

            </div>

            <textarea
              rows="14"
              value={rawEmail}
              onChange={(event) => {
                const value = event.target.value

                setRawEmail(value)

                // Save email so other investigation modules
                // can reuse the same evidence.
                if (value.trim()) {
                  saveEmailEvidence(value)
                } else {
                  clearSavedEmail()
                }

                setAnalysisStarted(false)
                setAnalysisResult(null)
                setError('')
              }}
              placeholder={`From: sender@example.com
To: recipient@example.com
Subject: Urgent Account Verification
Date: Fri, 04 Sep 2026 10:30:00 +0530
Message-ID: <example@email.com>
Received: from mail.example.com
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Paste the complete email content here...`}
              className="w-full resize-none rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-sm leading-6 text-slate-300 outline-none placeholder:text-slate-700 focus:border-cyan-500/50"
            />

            <div className="mt-3 flex justify-between">

              <p className="text-xs text-slate-600">
                Raw email data
              </p>

              <p className="text-xs text-slate-600">
                {rawEmail.length.toLocaleString()} characters
              </p>

            </div>

            {/* =========================================
                EVIDENCE SHARING STATUS
            ========================================= */}

            {rawEmail.trim() && (

              <div className="mt-3 flex items-center gap-2">

                <span className="h-2 w-2 rounded-full bg-green-400"></span>

                <p className="text-xs text-green-400">
                  Email evidence saved for cross-module investigation
                </p>

              </div>

            )}

            {/* ERROR */}

            {error && (

              <div className="mt-5 rounded-xl border border-red-500/20 bg-red-500/5 p-4">

                <div className="flex items-start gap-3">

                  <span className="text-lg">
                    ⚠️
                  </span>

                  <div>

                    <p className="text-sm font-medium text-red-400">
                      Analysis failed
                    </p>

                    <p className="mt-1 text-xs leading-5 text-slate-500">
                      {error}
                    </p>

                  </div>

                </div>

              </div>

            )}

            {/* ANALYZE CONTROLS */}

            <div className="mt-5 flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">

              <div>

                <p className="text-xs text-slate-500">
                  Evidence will be analyzed by the TraceMail AI backend.
                </p>

                <p className="mt-1 text-xs text-slate-600">
                  Upload a file or paste email content to continue.
                </p>

              </div>

              <div className="flex flex-wrap items-center gap-3">

                <button
                  type="button"
                  onClick={toggleVoiceAlerts}
                  className={`rounded-lg border px-4 py-3 text-sm font-semibold transition ${
                    voiceAlertsEnabled
                      ? 'border-green-500/30 bg-green-500/10 text-green-400 hover:bg-green-500/15'
                      : 'border-slate-700 bg-slate-950 text-slate-500 hover:border-cyan-500/30 hover:text-cyan-400'
                  }`}
                >
                  {voiceAlertsEnabled
                    ? '🔊 Voice Alert ON'
                    : '🔇 Voice Alert OFF'}
                </button>

                <button
                  type="button"
                  onClick={handleAnalyze}
                  disabled={
                    (!selectedFile && !rawEmail.trim()) ||
                    isAnalyzing
                  }
                  className="shrink-0 rounded-lg bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {isAnalyzing
                    ? 'Analyzing...'
                    : analysisStarted
                      ? 'Analysis Completed ✓'
                      : 'Analyze Email →'}
                </button>

              </div>

            {/* =========================================
                VOICE ALERT STATUS
            ========================================= */}

            <div className="mt-3 flex items-center gap-2">

              <span
                className={`h-2 w-2 rounded-full ${
                  voiceAlertsEnabled
                    ? 'bg-green-400'
                    : 'bg-slate-600'
                }`}
              ></span>

              <p className="text-xs text-slate-600">
                Voice threat alert: {voiceAlertStatus}
              </p>

              {voiceAlertsEnabled && (
                <p className="text-xs text-slate-700">
                  • High/Critical threats trigger a spoken security alert
                </p>
              )}

            </div>

            </div>

            {/* ANALYSIS COMPLETED */}

            {analysisStarted && (

              <div className="mt-5 rounded-xl border border-green-500/20 bg-green-500/5 p-4">

                <div className="flex items-center gap-3">

                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-green-500/10">
                    ✓
                  </div>

                  <div>

                    <p className="text-sm font-medium text-green-400">
                      Forensic analysis completed
                    </p>

                    <p className="mt-1 text-xs text-slate-500">
                      AI analysis result has been stored in the backend database.
                    </p>

                  </div>

                </div>

              </div>

            )}

          </div>

          {/* =========================================
              INPUT INFORMATION
          ========================================= */}

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

            <div className="flex gap-4">

              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-500/10">
                ℹ️
              </div>

              <div>

                <h3 className="text-sm font-medium text-slate-200">
                  What TraceMail AI analyzes
                </h3>

                <div className="mt-3 grid grid-cols-1 gap-x-8 gap-y-2 sm:grid-cols-2">

                  <p className="text-xs text-slate-500">
                    • Email headers and routing
                  </p>

                  <p className="text-xs text-slate-500">
                    • Sender identity indicators
                  </p>

                  <p className="text-xs text-slate-500">
                    • SPF / DKIM / DMARC
                  </p>

                  <p className="text-xs text-slate-500">
                    • Suspicious URLs and domains
                  </p>

                  <p className="text-xs text-slate-500">
                    • IP addresses and infrastructure
                  </p>

                  <p className="text-xs text-slate-500">
                    • Phishing and social engineering signals
                  </p>

                </div>

              </div>

            </div>

          </div>

          {/* =========================================
              ANALYSIS RESULT
          ========================================= */}

          {analysisStarted && analysisResult && (

            <div className="rounded-2xl border border-cyan-500/20 bg-slate-900 p-6">

              {/* RESULT HEADER */}

              <div className="flex flex-col items-start justify-between gap-6 lg:flex-row">

                <div className="flex items-start gap-4">

                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-cyan-500/10 text-xl">
                    🔬
                  </div>

                  <div>

                    <p className="text-sm font-medium text-cyan-400">
                      Forensic Analysis
                    </p>

                    <h2 className="mt-1 text-xl font-semibold text-slate-100">
                      Threat Intelligence Summary
                    </h2>

                    <p className="mt-2 text-sm leading-6 text-slate-500">
                      Explainable threat intelligence has been extracted
                      from the submitted email evidence.
                    </p>

                  </div>

                </div>

                <div className="flex gap-3">

                  <div className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-right">

                    <p className="text-xs text-slate-500">
                      Classification
                    </p>

                    <p
                      className={`mt-1 text-sm font-semibold ${getClassificationClass(
                        analysisResult.classification
                      )}`}
                    >
                      {analysisResult.classification}
                    </p>

                  </div>

                  <div
                    className={`rounded-xl border px-4 py-3 text-right ${getSeverityClass(
                      analysisResult.severity
                    )}`}
                  >

                    <p className="text-xs opacity-70">
                      Severity
                    </p>

                    <p className="mt-1 text-sm font-semibold">
                      {analysisResult.severity}
                    </p>

                  </div>

                </div>

              </div>

              {/* =========================================
                  VOICE THREAT ALERT BANNER
              ========================================= */}

              {(analysisResult.severity === 'Critical' ||
                analysisResult.severity === 'High') && (

                <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/5 p-5">

                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

                    <div className="flex items-start gap-3">

                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-red-500/10 text-lg">
                        🚨
                      </div>

                      <div>

                        <p className="text-sm font-semibold text-red-400">
                          Security Voice Alert Triggered
                        </p>

                        <p className="mt-1 text-xs leading-5 text-slate-500">
                          {analysisResult.severity} threat detected.
                          TraceMail has issued a spoken security warning.
                        </p>

                      </div>

                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        speakThreatAlert(
                          analysisResult
                        )
                      }
                      disabled={!voiceAlertsEnabled}
                      className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-2 text-xs font-medium text-red-400 transition hover:bg-red-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      🔊 Replay Alert
                    </button>

                  </div>

                </div>

              )}

              {/* =========================================
                  SCORE CARDS
              ========================================= */}

              <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

                {/* THREAT SCORE */}

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Threat Score
                  </p>

                  <div className="mt-3 flex items-end gap-2">

                    <span className="text-3xl font-bold text-yellow-400">
                      {analysisResult.threatScore}
                    </span>

                    <span className="pb-1 text-xs text-slate-600">
                      / 100
                    </span>

                  </div>

                  <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">

                    <div
                      className="h-full rounded-full bg-yellow-400 transition-all"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            0,
                            analysisResult.threatScore
                          )
                        )}%`,
                      }}
                    ></div>

                  </div>

                </div>

                {/* SEVERITY */}

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Severity
                  </p>

                  <p
                    className={`mt-3 text-2xl font-bold ${
                      analysisResult.severity === 'Critical'
                        ? 'text-red-400'
                        : analysisResult.severity === 'High'
                          ? 'text-orange-400'
                          : analysisResult.severity === 'Medium'
                            ? 'text-yellow-400'
                            : 'text-green-400'
                    }`}
                  >
                    {analysisResult.severity}
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    Investigation severity
                  </p>

                </div>

                {/* CONFIDENCE */}

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    AI Confidence
                  </p>

                  <p className="mt-3 text-3xl font-bold text-cyan-400">
                    {analysisResult.confidence}%
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    AI service confidence estimate
                  </p>

                </div>

                {/* INDICATORS */}

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Indicators Found
                  </p>

                  <p className="mt-3 text-3xl font-bold text-red-400">
                    {analysisResult.indicators}
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    Potential suspicious indicators
                  </p>

                </div>

              </div>

              {/* =========================================
                  CATEGORY / PRIORITY
              ========================================= */}

              <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Threat Category
                  </p>

                  <p className="mt-2 text-lg font-semibold text-cyan-400">
                    {analysisResult.category}
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    Primary threat classification generated by the AI engine.
                  </p>

                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Investigation Priority
                  </p>

                  <p
                    className={`mt-2 text-lg font-semibold ${
                      analysisResult.priority === 'Critical'
                        ? 'text-red-400'
                        : analysisResult.priority === 'High'
                          ? 'text-orange-400'
                          : analysisResult.priority === 'Medium'
                            ? 'text-yellow-400'
                            : 'text-green-400'
                    }`}
                  >
                    {analysisResult.priority}
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    Recommended handling priority for the investigation.
                  </p>

                </div>

              </div>

              {/* =========================================
                  AUTHENTICATION
              ========================================= */}

              <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950 p-5">

                <div className="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">

                  <div>

                    <p className="text-sm font-medium text-slate-200">
                      Email Authentication
                    </p>

                    <p className="mt-1 text-xs text-slate-600">
                      SPF, DKIM and DMARC verification status
                    </p>

                  </div>

                  <span className="rounded-full bg-red-500/10 px-3 py-1 text-xs font-medium text-red-400">
                    Authentication Risk
                  </span>

                </div>

                <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-3">

                  {/* SPF */}

                  <div className="rounded-lg border border-slate-800 p-4">

                    <p className="text-xs text-slate-500">
                      SPF
                    </p>

                    <p
                      className={`mt-2 text-sm font-semibold ${
                        analysisResult.authentication?.spf === 'PASS'
                          ? 'text-green-400'
                          : analysisResult.authentication?.spf === 'UNKNOWN'
                            ? 'text-yellow-400'
                            : 'text-red-400'
                      }`}
                    >
                      {analysisResult.authentication?.spf === 'PASS'
                        ? '✓'
                        : analysisResult.authentication?.spf === 'UNKNOWN'
                          ? '?'
                          : '✕'}{' '}
                      {analysisResult.authentication?.spf || 'UNKNOWN'}
                    </p>

                  </div>

                  {/* DKIM */}

                  <div className="rounded-lg border border-slate-800 p-4">

                    <p className="text-xs text-slate-500">
                      DKIM
                    </p>

                    <p
                      className={`mt-2 text-sm font-semibold ${
                        analysisResult.authentication?.dkim === 'PASS'
                          ? 'text-green-400'
                          : analysisResult.authentication?.dkim === 'UNKNOWN'
                            ? 'text-yellow-400'
                            : 'text-red-400'
                      }`}
                    >
                      {analysisResult.authentication?.dkim === 'PASS'
                        ? '✓'
                        : analysisResult.authentication?.dkim === 'UNKNOWN'
                          ? '?'
                          : '✕'}{' '}
                      {analysisResult.authentication?.dkim || 'UNKNOWN'}
                    </p>

                  </div>

                  {/* DMARC */}

                  <div className="rounded-lg border border-slate-800 p-4">

                    <p className="text-xs text-slate-500">
                      DMARC
                    </p>

                    <p
                      className={`mt-2 text-sm font-semibold ${
                        analysisResult.authentication?.dmarc === 'PASS'
                          ? 'text-green-400'
                          : analysisResult.authentication?.dmarc === 'UNKNOWN'
                            ? 'text-yellow-400'
                            : 'text-red-400'
                      }`}
                    >
                      {analysisResult.authentication?.dmarc === 'PASS'
                        ? '✓'
                        : analysisResult.authentication?.dmarc === 'UNKNOWN'
                          ? '?'
                          : '✕'}{' '}
                      {analysisResult.authentication?.dmarc || 'UNKNOWN'}
                    </p>

                  </div>

                </div>

              </div>

              {/* =========================================
                  AI EXPLANATION
              ========================================= */}

              <div className="mt-6 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">

                <div className="flex items-start gap-3">

                  <span className="text-lg">
                    🧠
                  </span>

                  <div>

                    <p className="text-sm font-medium text-cyan-400">
                      AI Investigation Explanation
                    </p>

                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      {analysisResult.explanation}
                    </p>

                  </div>

                </div>

              </div>

              {/* =========================================
                  RISK FACTORS
              ========================================= */}

              {analysisResult.riskFactors?.length > 0 && (

                <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/5 p-5">

                  <div className="flex items-center gap-3">

                    <span className="text-lg">
                      ⚠️
                    </span>

                    <p className="text-sm font-medium text-red-400">
                      Risk Factors
                    </p>

                  </div>

                  <div className="mt-4 space-y-3">

                    {analysisResult.riskFactors.map(
                      (factor, index) => (

                        <div
                          key={index}
                          className="flex items-start gap-3"
                        >

                          <span className="mt-1 text-red-400">
                            •
                          </span>

                          <p className="text-xs leading-5 text-slate-400">
                            {factor}
                          </p>

                        </div>

                      )
                    )}

                  </div>

                </div>

              )}

              {/* =========================================
                  DETECTED INDICATORS
              ========================================= */}

              {analysisResult.indicatorList?.length > 0 && (

                <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <div className="flex items-center justify-between">

                    <div>

                      <p className="text-sm font-medium text-slate-200">
                        Detected Threat Indicators
                      </p>

                      <p className="mt-1 text-xs text-slate-600">
                        Individual forensic signals detected in the email.
                      </p>

                    </div>

                    <span className="rounded-full bg-red-500/10 px-3 py-1 text-xs font-medium text-red-400">
                      {analysisResult.indicators} detected
                    </span>

                  </div>

                  <div className="mt-4 space-y-2">

                    {analysisResult.indicatorList.map(
                      (indicator, index) => (

                        <div
                          key={index}
                          className="rounded-lg border border-slate-800 bg-slate-900 px-4 py-3"
                        >

                          <p className="text-xs leading-5 text-slate-400">

                            <span className="mr-2 font-semibold text-red-400">
                              {index + 1}.
                            </span>

                            {indicator}

                          </p>

                        </div>

                      )
                    )}

                  </div>

                </div>

              )}

              {/* =========================================
                  URL INTELLIGENCE
              ========================================= */}

              {analysisResult.urlCount > 0 && (

                <div className="mt-4 rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-5">

                  <div className="flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">

                    <div>

                      <p className="text-sm font-medium text-yellow-400">
                        Suspicious URL Intelligence
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        {analysisResult.urlCount} URL detected in the email.
                      </p>

                    </div>

                    <span className="rounded-full bg-yellow-500/10 px-3 py-1 text-xs font-medium text-yellow-400">
                      {analysisResult.urlCount} URL
                    </span>

                  </div>

                  <div className="mt-4 space-y-2">

                    {analysisResult.urlsDetected.map(
                      (url, index) => (

                        <div
                          key={index}
                          className="rounded-lg border border-slate-800 bg-slate-950 px-4 py-3"
                        >

                          <p className="break-all font-mono text-xs text-slate-400">
                            {url}
                          </p>

                        </div>

                      )
                    )}

                  </div>

                </div>

              )}

              {/* =========================================
                  ORIGIN INTELLIGENCE
              ========================================= */}

              <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">

                {/* SOURCE IP */}

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Source IP
                  </p>

                  <p className="mt-2 font-mono text-sm text-slate-200">
                    {analysisResult.sourceIp}
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    Extracted from email routing information.
                  </p>

                </div>

                {/* DOMAIN */}

                <div className="rounded-xl border border-slate-800 bg-slate-950 p-5">

                  <p className="text-xs text-slate-500">
                    Sender Domain
                  </p>

                  <p className="mt-2 break-all font-mono text-sm text-slate-200">
                    {analysisResult.domain}
                  </p>

                  <p className="mt-2 text-xs text-slate-600">
                    Domain extracted from the sender identity.
                  </p>

                </div>

              </div>

              {/* ORIGIN STATUS */}

              <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-5">

                <p className="text-xs text-slate-500">
                  Origin Intelligence
                </p>

                <p className="mt-2 text-sm font-medium text-yellow-400">
                  {analysisResult.location}
                </p>

                <p className="mt-2 text-xs text-slate-600">
                  Detailed geolocation and infrastructure correlation
                  will be provided by the Geo Intelligence layer.
                </p>

              </div>

              {/* =========================================
                  RECOMMENDED ACTIONS
              ========================================= */}

              {analysisResult.recommendedActions?.length > 0 && (

                <div className="mt-6 rounded-xl border border-green-500/20 bg-green-500/5 p-5">

                  <div className="flex items-center gap-3">

                    <span className="text-lg">
                      🛡️
                    </span>

                    <div>

                      <p className="text-sm font-medium text-green-400">
                        Recommended Investigation Actions
                      </p>

                      <p className="mt-1 text-xs text-slate-600">
                        Actions suggested by the TraceMail intelligence engine.
                      </p>

                    </div>

                  </div>

                  <div className="mt-4 space-y-3">

                    {analysisResult.recommendedActions.map(
                      (action, index) => (

                        <div
                          key={index}
                          className="flex items-start gap-3"
                        >

                          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-green-500/10 text-xs font-medium text-green-400">
                            {index + 1}
                          </div>

                          <p className="text-xs leading-5 text-slate-400">
                            {action}
                          </p>

                        </div>

                      )
                    )}

                  </div>

                </div>

              )}

              {/* =========================================
                  BACKEND STATUS
              ========================================= */}

              <div className="mt-6 rounded-xl border border-green-500/20 bg-green-500/5 p-5">

                <div className="flex items-start gap-3">

                  <span className="text-lg">
                    🗄️
                  </span>

                  <div>

                    <p className="text-sm font-medium text-green-400">
                      AI + Backend + Database Connected
                    </p>

                    <p className="mt-1 text-xs leading-5 text-slate-500">
                      AI analysis has been completed and the investigation
                      has been stored in MongoDB.
                    </p>

                  </div>

                </div>

              </div>

              {/* =========================================
                  ADVANCED INTELLIGENCE
              ========================================= */}

              <div className="mt-4 rounded-xl border border-dashed border-slate-700 bg-slate-950/50 p-5">

                <div className="flex items-start gap-3">

                  <span className="text-lg">
                    🔎
                  </span>

                  <div>

                    <p className="text-sm font-medium text-slate-300">
                      Advanced Intelligence Layers
                    </p>

                    <p className="mt-1 text-xs leading-5 text-slate-600">
                      TraceMail can extend this analysis with live
                      geolocation, external threat intelligence,
                      campaign clustering and attribution analysis.
                    </p>

                  </div>

                </div>

              </div>

            </div>

          )}

        </div>

        {/* =========================================
            RIGHT SIDE — ANALYSIS PIPELINE
        ========================================= */}

        <div>

          <div className="sticky top-8 rounded-2xl border border-slate-800 bg-slate-900 p-6">

            <div className="mb-6">

              <h2 className="font-semibold text-slate-100">
                Analysis Pipeline
              </h2>

              <p className="mt-1 text-xs leading-5 text-slate-500">
                The email will pass through multiple forensic
                analysis stages.
              </p>

            </div>

            <div className="space-y-5">

              {/* STEP 1 */}

              <div className="flex gap-4">

                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-green-500/10 text-sm text-green-400">
                  ✓
                </div>

                <div>

                  <p className="text-sm font-medium text-slate-200">
                    Email Ingestion
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    Parse email content and metadata.
                  </p>

                </div>

              </div>

              {/* STEP 2 */}

              <div className="flex gap-4">

                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 text-xs text-slate-500">
                  2
                </div>

                <div>

                  <p className="text-sm font-medium text-slate-300">
                    Header Forensics
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Analyze Received, Return-Path and Message-ID.
                  </p>

                </div>

              </div>

              {/* STEP 3 */}

              <div className="flex gap-4">

                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 text-xs text-slate-500">
                  3
                </div>

                <div>

                  <p className="text-sm font-medium text-slate-300">
                    Authentication
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Validate SPF, DKIM and DMARC results.
                  </p>

                </div>

              </div>

              {/* STEP 4 */}

              <div className="flex gap-4">

                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 text-xs text-slate-500">
                  4
                </div>

                <div>

                  <p className="text-sm font-medium text-slate-300">
                    IOC Extraction
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Extract IPs, domains, URLs and hashes.
                  </p>

                </div>

              </div>

              {/* STEP 5 */}

              <div className="flex gap-4">

                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 text-xs text-slate-500">
                  5
                </div>

                <div>

                  <p className="text-sm font-medium text-slate-300">
                    AI Threat Detection
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Detect phishing, fraud and impersonation.
                  </p>

                </div>

              </div>

              {/* STEP 6 */}

              <div className="flex gap-4">

                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 text-xs text-slate-500">
                  6
                </div>

                <div>

                  <p className="text-sm font-medium text-slate-300">
                    Origin Intelligence
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Correlate IP, geolocation and infrastructure.
                  </p>

                </div>

              </div>

            </div>

            {/* =========================================
                CAPABILITIES
            ========================================= */}

            <div className="mt-8 rounded-xl border border-slate-800 bg-slate-950 p-4">

              <p className="text-xs font-medium text-slate-300">
                Investigation capabilities
              </p>

              <div className="mt-3 space-y-2">

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Header analysis
                  </span>

                  <span className="text-xs text-green-400">
                    Ready
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    IOC extraction
                  </span>

                  <span className="text-xs text-green-400">
                    Ready
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    AI threat scoring
                  </span>

                  <span className="text-xs text-green-400">
                    Ready
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Explainable analysis
                  </span>

                  <span className="text-xs text-green-400">
                    Ready
                  </span>

                </div>

                <div className="flex items-center justify-between">

                  <span className="text-xs text-slate-500">
                    Geo intelligence
                  </span>

                  <span className="text-xs text-yellow-400">
                    Pending
                  </span>

                </div>

              </div>

            </div>

            {/* =========================================
                PRIVACY
            ========================================= */}

            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950 p-4">

              <div className="flex gap-3">

                <span className="text-lg">
                  🔐
                </span>

                <div>

                  <p className="text-xs font-medium text-slate-300">
                    Privacy & Evidence Protection
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Investigation data should be handled according
                    to organizational privacy and retention policies.
                  </p>

                </div>

              </div>

            </div>

            {/* =========================================
                ENGINE STATUS
            ========================================= */}

            <div className="mt-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">

              <div className="flex gap-3">

                <span className="text-lg">
                  ⚙️
                </span>

                <div>

                  <p className="text-xs font-medium text-cyan-400">
                    TraceMail Intelligence Engine
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-600">
                    Explainable forensic rules analyze authentication,
                    content, URLs, domains and social-engineering signals.
                  </p>

                </div>

              </div>

            </div>

          </div>

        </div>

      </div>

    </div>
  )
}

export default AnalyzeEmail