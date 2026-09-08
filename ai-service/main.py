from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI(
    title="TraceMail AI Service",
    description="AI-powered email threat analysis and forensic intelligence service",
    version="2.0.0"
)


# =========================================
# REQUEST MODEL
# =========================================

class EmailRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    body: str = ""
    spf: str = "UNKNOWN"
    dkim: str = "UNKNOWN"
    dmarc: str = "UNKNOWN"
    sourceIp: str = ""
    domain: str = ""


# =========================================
# HEALTH CHECK
# =========================================

@app.get("/")
def root():
    return {
        "message": "TraceMail AI Service is running 🚀",
        "status": "success",
        "engine": "Explainable Threat Intelligence Engine",
        "version": "2.0.0"
    }


# =========================================
# HELPER FUNCTIONS
# =========================================

def contains_any(text, words):
    return any(word in text for word in words)


def extract_urls(text):
    return re.findall(
        r'https?://[^\s<>"\']+',
        text,
        re.IGNORECASE
    )


def detect_lookalike_domain(domain):
    """
    Detect common brand impersonation patterns such as:
    micros0ft
    paypa1
    g00gle
    """
    domain_lower = domain.lower()

    suspicious_patterns = {
        "micros0ft": "Microsoft lookalike domain detected",
        "microsft": "Microsoft lookalike domain detected",
        "paypa1": "PayPal lookalike domain detected",
        "g00gle": "Google lookalike domain detected",
        "app1e": "Apple lookalike domain detected",
        "amaz0n": "Amazon lookalike domain detected",
        "faceb00k": "Facebook lookalike domain detected",
    }

    for pattern, message in suspicious_patterns.items():
        if pattern in domain_lower:
            return message

    return None


# =========================================
# AI / THREAT ANALYSIS
# =========================================

@app.post("/analyze")
def analyze_email(email: EmailRequest):

    subject = email.subject.strip()
    sender = email.sender.strip()
    body = email.body.strip()
    domain = email.domain.strip()

    text = (
        subject + " " +
        sender + " " +
        body
    ).lower()

    score = 40

    indicators = []
    risk_factors = []
    recommended_actions = []

    # =========================================
    # PHISHING / CREDENTIAL INDICATORS
    # =========================================

    phishing_words = [
        "verify your account",
        "verify your identity",
        "account suspended",
        "password",
        "login",
        "urgent",
        "immediately",
        "click here",
        "security alert",
        "credential",
        "confirm your account"
    ]

    for word in phishing_words:
        if word in text:
            indicator = f"Suspicious phrase: {word}"

            if indicator not in indicators:
                indicators.append(indicator)

    # =========================================
    # FINANCIAL FRAUD / BEC INDICATORS
    # =========================================

    financial_words = [
        "urgent payment",
        "wire transfer",
        "bank account",
        "invoice",
        "payment",
        "transfer",
        "vendor account",
        "new vendor",
        "account number",
        "ifsc"
    ]

    for word in financial_words:
        if word in text:
            indicator = f"Financial risk phrase: {word}"

            if indicator not in indicators:
                indicators.append(indicator)

    # =========================================
    # AUTHENTICATION ANALYSIS
    # =========================================

    spf = email.spf.upper()
    dkim = email.dkim.upper()
    dmarc = email.dmarc.upper()

    if spf == "FAIL":
        score += 10
        indicators.append("SPF authentication failed")
        risk_factors.append(
            "The sending server failed SPF authentication."
        )

    elif spf == "PASS":
        risk_factors.append(
            "SPF authentication passed."
        )

    if dkim == "FAIL":
        score += 10
        indicators.append("DKIM authentication failed")
        risk_factors.append(
            "The email failed DKIM signature verification."
        )

    elif dkim == "PASS":
        risk_factors.append(
            "DKIM authentication passed."
        )

    if dmarc == "FAIL":
        score += 20
        indicators.append("DMARC authentication failed")
        risk_factors.append(
            "DMARC authentication failed, indicating an authentication or domain-alignment problem."
        )

    elif dmarc == "PASS":
        risk_factors.append(
            "DMARC authentication passed."
        )

    # =========================================
    # URL ANALYSIS
    # =========================================

    urls = extract_urls(body)

    if urls:
        indicators.append(
            f"Suspicious URL detected ({len(urls)} URL{'s' if len(urls) != 1 else ''})"
        )

        risk_factors.append(
            "The message contains one or more clickable URLs that require investigation."
        )

        recommended_actions.append(
            "Inspect and reputation-check all URLs before allowing user access."
        )

    # =========================================
    # LOOKALIKE DOMAIN DETECTION
    # =========================================

    lookalike_result = detect_lookalike_domain(domain)

    if lookalike_result:
        score += 10

        indicators.append(lookalike_result)

        risk_factors.append(
            "The sender domain appears to imitate a known organization."
        )

        recommended_actions.append(
            "Block or investigate the impersonating domain."
        )

    # =========================================
    # SOCIAL ENGINEERING DETECTION
    # =========================================

    urgency_patterns = [
        "urgent",
        "immediately",
        "within 24 hours",
        "24 hours",
        "do not delay",
        "time-sensitive",
        "act now"
    ]

    credential_patterns = [
        "password",
        "username",
        "login",
        "credential",
        "verify your identity",
        "verify your account"
    ]

    if contains_any(text, urgency_patterns):

        if "Urgency / social engineering language" not in indicators:
            indicators.append(
                "Urgency / social engineering language"
            )

        risk_factors.append(
            "The message uses urgency or pressure to encourage immediate action."
        )

        recommended_actions.append(
            "Verify the request through an independent trusted communication channel."
        )

    if contains_any(text, credential_patterns):

        if "Credential harvesting indicators detected" not in indicators:
            indicators.append(
                "Credential harvesting indicators detected"
            )

        risk_factors.append(
            "The message requests or references credentials, login activity, or identity verification."
        )

        recommended_actions.append(
            "Do not enter credentials through links contained in the message."
        )

    # =========================================
    # MULTIPLE INDICATORS
    # =========================================

    if len(indicators) >= 3:
        score += 10

        risk_factors.append(
            "Multiple independent indicators increase the overall threat level."
        )

    # =========================================
    # SCORE LIMIT
    # =========================================

    score = min(score, 100)

    # =========================================
    # CLASSIFICATION
    # =========================================

    if score >= 80:
        classification = "Malicious"
    elif score >= 50:
        classification = "Suspicious"
    else:
        classification = "Low Risk"

    # =========================================
    # PRIORITY
    # =========================================

    if score >= 85:
        priority = "Critical"
    elif score >= 70:
        priority = "High"
    elif score >= 50:
        priority = "Medium"
    else:
        priority = "Low"

    # =========================================
    # CONFIDENCE
    # =========================================

    confidence = min(
        95,
        70 + len(indicators) * 4
    )

    # =========================================
    # CATEGORY
    # =========================================

    credential_category = [
        "verify your account",
        "verify your identity",
        "password",
        "login",
        "credential",
        "account suspended"
    ]

    financial_category = [
        "payment",
        "invoice",
        "wire transfer",
        "vendor account",
        "bank account",
        "ifsc"
    ]

    malware_category = [
        "attachment",
        ".exe",
        ".zip",
        "malware",
        "trojan",
        "ransomware"
    ]

    if contains_any(text, credential_category):
        category = "Credential Theft"

    elif contains_any(text, financial_category):
        category = "BEC / Fraud"

    elif contains_any(text, malware_category):
        category = "Malware"

    elif contains_any(
        text,
        [
            "spam",
            "unsubscribe",
            "promotional"
        ]
    ):
        category = "Spam"

    else:
        category = "Suspicious"

    # =========================================
    # CATEGORY-SPECIFIC RECOMMENDATIONS
    # =========================================

    if category == "Credential Theft":

        recommended_actions.append(
            "Reset credentials if the recipient interacted with the message."
        )

        recommended_actions.append(
            "Review authentication logs for suspicious account activity."
        )

    elif category == "BEC / Fraud":

        recommended_actions.append(
            "Verify payment or banking changes directly with the requester."
        )

        recommended_actions.append(
            "Place suspicious financial transactions on hold until verified."
        )

    elif category == "Malware":

        recommended_actions.append(
            "Quarantine suspicious attachments and scan affected endpoints."
        )

    # =========================================
    # GENERAL RESPONSE
    # =========================================

    if not recommended_actions:

        recommended_actions.append(
            "Continue investigation using headers, domain reputation and infrastructure intelligence."
        )

    # Remove duplicate indicators while preserving order
    indicators = list(dict.fromkeys(indicators))

    # Remove duplicate risk factors
    risk_factors = list(dict.fromkeys(risk_factors))

    # Remove duplicate recommendations
    recommended_actions = list(
        dict.fromkeys(recommended_actions)
    )

    # =========================================
    # THREAT SEVERITY
    # =========================================

    if score >= 85:
        severity = "Critical"
    elif score >= 70:
        severity = "High"
    elif score >= 50:
        severity = "Medium"
    else:
        severity = "Low"

    # =========================================
    # EXPLAINABLE SUMMARY
    # =========================================

    if classification == "Malicious":

        explanation = (
            "High-confidence malicious activity detected based on "
            "authentication failures, suspicious content, social-engineering "
            "signals and multiple forensic indicators."
        )

    elif classification == "Suspicious":

        explanation = (
            "The email contains multiple suspicious characteristics "
            "that require further investigation before being considered safe."
        )

    else:

        explanation = (
            "No strong malicious indicators were identified by the current "
            "analysis engine."
        )

    # =========================================
    # FINAL RESPONSE
    # =========================================

    return {
        "success": True,

        "analysis": {

            "classification": classification,

            "threatScore": score,

            "confidence": confidence,

            "priority": priority,

            "severity": severity,

            "category": category,

            "indicators": indicators,

            "indicatorCount": len(indicators),

            "riskFactors": risk_factors,

            "explanation": explanation,

            "recommendedActions": recommended_actions,

            "authentication": {
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc
            },

            "sourceIp": email.sourceIp,

            "domain": email.domain,

            "urlsDetected": urls,

            "urlCount": len(urls),

            "engine": {
                "name": "TraceMail Explainable Threat Intelligence Engine",
                "version": "2.0.0",
                "type": "Rule-based forensic intelligence"
            }
        }
    }