from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI(
    title="TraceMail AI Service",
    description="AI-powered email threat analysis and forensic intelligence service",
    version="2.2.0"
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

    # Attachment metadata
    attachments: list[dict] = []


# =========================================
# HEALTH CHECK
# =========================================

@app.get("/")
def root():
    return {
        "message": "TraceMail AI Service is running 🚀",
        "status": "success",
        "engine": "Explainable Threat Intelligence Engine",
        "version": "2.2.0"
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
# IOC REPUTATION INTELLIGENCE
# =========================================

def analyze_ioc_reputation(urls, domain, source_ip, body):
    """
    Generate explainable reputation intelligence for
    URLs, domains and source IPs using deterministic
    forensic rules.
    """

    url_results = []
    domain_results = []
    ip_results = []

    body_lower = (body or "").lower()
    domain_lower = (domain or "").lower()

    # URL reputation
    for url in urls or []:
        url_lower = url.lower()
        reasons = []
        score = 0

        if any(
            pattern in url_lower
            for pattern in [
                "micros0ft", "microsft", "paypa1",
                "g00gle", "app1e", "amaz0n", "faceb00k"
            ]
        ):
            score += 40
            reasons.append(
                "Lookalike / impersonation domain detected"
            )

        credential_keywords = [
            "verify", "login", "signin", "account",
            "password", "credential", "security"
        ]

        matched_keywords = [
            keyword
            for keyword in credential_keywords
            if keyword in url_lower
        ]

        if matched_keywords:
            score += 20
            reasons.append(
                "Credential or account-related URL keyword detected"
            )

        if url_lower.startswith("http://"):
            score += 15
            reasons.append(
                "URL uses unencrypted HTTP"
            )

        if any(
            keyword in body_lower
            for keyword in [
                "urgent", "immediately", "act now", "within 24 hours"
            ]
        ):
            score += 10
            reasons.append(
                "URL appears in urgency / social-engineering context"
            )

        if score >= 50:
            reputation = "Malicious"
        elif score >= 25:
            reputation = "Suspicious"
        else:
            reputation = "Low Risk"

        url_results.append({
            "ioc": url,
            "type": "URL",
            "reputation": reputation,
            "score": min(score, 100),
            "reasons": reasons
        })

    # Domain reputation
    if domain:
        reasons = []
        score = 0

        lookalike_result = detect_lookalike_domain(domain)

        if lookalike_result:
            score += 50
            reasons.append(lookalike_result)

        if any(
            keyword in domain_lower
            for keyword in [
                "support", "security", "verify", "login", "account"
            ]
        ):
            score += 15
            reasons.append(
                "Domain contains security/account-themed keywords"
            )

        if any(char.isdigit() for char in domain_lower):
            score += 10
            reasons.append(
                "Domain contains numeric characters"
            )

        if score >= 50:
            reputation = "Malicious"
        elif score >= 25:
            reputation = "Suspicious"
        else:
            reputation = "Low Risk"

        domain_results.append({
            "ioc": domain,
            "type": "Domain",
            "reputation": reputation,
            "score": min(score, 100),
            "reasons": reasons
        })

    # Source IP reputation
    if source_ip:
        reasons = []
        score = 0

        if source_ip not in ["127.0.0.1", "localhost", "::1"]:
            score += 20
            reasons.append(
                "External source infrastructure observed"
            )

        if any(
            keyword in body_lower
            for keyword in ["urgent", "password", "login", "verify"]
        ):
            score += 10
            reasons.append(
                "IP is associated with suspicious email content"
            )

        if score >= 50:
            reputation = "Malicious"
        elif score >= 25:
            reputation = "Suspicious"
        else:
            reputation = "Low Risk"

        ip_results.append({
            "ioc": source_ip,
            "type": "IP",
            "reputation": reputation,
            "score": min(score, 100),
            "reasons": reasons
        })

    return {
        "urls": url_results,
        "domains": domain_results,
        "ips": ip_results,
        "totalIOCs": (
            len(url_results)
            + len(domain_results)
            + len(ip_results)
        )
    }


# =========================================
# ATTACHMENT FORENSICS
# =========================================

def analyze_attachments(attachments):

    findings = []
    risk_factors = []
    recommended_actions = []

    score_points = 0
    suspicious_count = 0

    # -----------------------------------------
    # HIGH-RISK EXECUTABLE FILE TYPES
    # -----------------------------------------

    high_risk_extensions = {
        ".exe",
        ".dll",
        ".scr",
        ".msi",
        ".bat",
        ".cmd",
        ".com",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".hta",
        ".reg"
    }

    # -----------------------------------------
    # MACRO-ENABLED OFFICE DOCUMENTS
    # -----------------------------------------

    macro_extensions = {
        ".docm",
        ".dotm",
        ".xlsm",
        ".xltm",
        ".pptm",
        ".ppsm"
    }

    # -----------------------------------------
    # ARCHIVE FILE TYPES
    # -----------------------------------------

    archive_extensions = {
        ".zip",
        ".rar",
        ".7z",
        ".iso",
        ".img"
    }

    for attachment in attachments or []:

        # =========================================
        # BASIC METADATA
        # =========================================

        name = str(
            attachment.get("name", "")
        ).strip()

        extension = str(
            attachment.get("extension") or ""
        ).lower().strip()

        file_type = str(
            attachment.get("type", "")
        ).strip()

        sha256 = str(
            attachment.get("sha256", "")
        ).strip()

        size = attachment.get("size")


        # =========================================
        # DETECT EXTENSION IF NOT PROVIDED
        # =========================================

        if not extension and "." in name:

            extension = (
                "."
                + name.rsplit(".", 1)[1].lower()
            )


        # =========================================
        # EXECUTABLE ATTACHMENT
        # =========================================

        if extension in high_risk_extensions:

            score_points += 25

            suspicious_count += 1

            findings.append(
                f"High-risk executable attachment: "
                f"{name or extension}"
            )

            risk_factors.append(
                f"The attachment {name or extension} "
                f"uses a file type commonly associated "
                f"with executable code."
            )

            recommended_actions.append(
                f"Quarantine and malware-scan the attachment "
                f"{name or extension} before opening it."
            )


        # =========================================
        # MACRO-ENABLED DOCUMENT
        # =========================================

        elif extension in macro_extensions:

            score_points += 20

            suspicious_count += 1

            findings.append(
                f"Macro-enabled document detected: "
                f"{name or extension}"
            )

            risk_factors.append(
                f"The attachment {name or extension} "
                f"can contain executable Office macros."
            )

            recommended_actions.append(
                f"Open {name or extension} only in a "
                f"controlled analysis environment and "
                f"inspect macros."
            )


        # =========================================
        # ARCHIVE ATTACHMENT
        # =========================================

        elif extension in archive_extensions:

            score_points += 10

            findings.append(
                f"Archive attachment detected: "
                f"{name or extension}"
            )

            risk_factors.append(
                f"The attachment {name or extension} "
                f"is an archive that may conceal "
                f"additional files."
            )

            recommended_actions.append(
                f"Extract and inspect {name or extension} "
                f"safely before allowing user access."
            )


        # =========================================
        # DOUBLE EXTENSION DETECTION
        #
        # Example:
        # invoice.pdf.exe
        # document.docx.exe
        # =========================================

        if name.count(".") >= 2:

            parts = name.lower().split(".")

            final_extension = (
                "."
                + parts[-1]
            )

            if final_extension in high_risk_extensions:

                score_points += 15

                suspicious_count += 1

                findings.append(
                    f"Suspicious double-extension "
                    f"attachment: {name}"
                )

                risk_factors.append(
                    f"The filename {name} uses a "
                    f"double-extension pattern that can "
                    f"disguise an executable file."
                )

                recommended_actions.append(
                    f"Treat {name} as suspicious and "
                    f"inspect it before opening."
                )


        # =========================================
        # ATTACHMENT HASH
        # =========================================

        if sha256:

            findings.append(
                f"SHA-256 evidence hash available for "
                f"{name or 'attachment'}"
            )


    # =========================================
    # ATTACHMENT RISK LEVEL
    # =========================================

    if score_points >= 40:

        risk_level = "Critical"

    elif score_points >= 25:

        risk_level = "High"

    elif score_points >= 10:

        risk_level = "Medium"

    else:

        risk_level = "Low"


    # =========================================
    # RETURN ATTACHMENT ANALYSIS
    # =========================================

    return {

        "attachmentCount":
            len(attachments or []),

        "suspiciousAttachmentCount":
            suspicious_count,

        "riskPoints":
            score_points,

        "riskLevel":
            risk_level,

        "findings":
            findings,

        "riskFactors":
            risk_factors,

        "recommendedActions":
            recommended_actions
    }


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


    # =========================================
    # ATTACHMENT FORENSIC ANALYSIS
    # =========================================

    attachment_analysis = analyze_attachments(
        email.attachments
    )


    # =========================================
    # EXPLAINABLE SCORE INITIALIZATION
    # =========================================

    score = 40


    score_breakdown = [

        {
            "factor": "Base risk score",

            "points": 40,

            "reason": (
                "Initial baseline assigned before "
                "forensic indicators are evaluated."
            )
        }

    ]


    indicators = []

    risk_factors = []

    recommended_actions = []


    # =========================================
    # ATTACHMENT FORENSICS
    # =========================================

    if attachment_analysis["riskPoints"] > 0:

        score += attachment_analysis[
            "riskPoints"
        ]


        for finding in attachment_analysis[
            "findings"
        ]:

            if finding not in indicators:

                indicators.append(
                    finding
                )


        risk_factors.extend(
            attachment_analysis[
                "riskFactors"
            ]
        )


        recommended_actions.extend(
            attachment_analysis[
                "recommendedActions"
            ]
        )


        score_breakdown.append({

            "factor":
                "Attachment forensic risk",

            "points":
                attachment_analysis[
                    "riskPoints"
                ],

            "reason": (
                "Risk points were added based on "
                "transparent attachment rules including "
                "executable, macro-enabled, archive, "
                "and suspicious filename patterns."
            )

        })


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

            indicator = (
                f"Suspicious phrase: {word}"
            )


            if indicator not in indicators:

                indicators.append(
                    indicator
                )


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

            indicator = (
                f"Financial risk phrase: {word}"
            )


            if indicator not in indicators:

                indicators.append(
                    indicator
                )


    # =========================================
    # AUTHENTICATION ANALYSIS
    # =========================================

    spf = email.spf.upper()

    dkim = email.dkim.upper()

    dmarc = email.dmarc.upper()


    # =========================================
    # SPF
    # =========================================

    if spf == "FAIL":

        score += 10


        score_breakdown.append({

            "factor":
                "SPF authentication failure",

            "points":
                10,

            "reason": (
                "The sending server failed SPF "
                "authentication, indicating the source "
                "server was not authorized for the "
                "sender domain."
            )

        })


        indicators.append(
            "SPF authentication failed"
        )


        risk_factors.append(
            "The sending server failed SPF authentication."
        )


    elif spf == "PASS":

        risk_factors.append(
            "SPF authentication passed."
        )


    # =========================================
    # DKIM
    # =========================================

    if dkim == "FAIL":

        score += 10


        score_breakdown.append({

            "factor":
                "DKIM authentication failure",

            "points":
                10,

            "reason": (
                "The email failed DKIM signature "
                "verification, meaning the expected "
                "cryptographic signature could not "
                "be validated."
            )

        })


        indicators.append(
            "DKIM authentication failed"
        )


        risk_factors.append(
            "The email failed DKIM signature verification."
        )


    elif dkim == "PASS":

        risk_factors.append(
            "DKIM authentication passed."
        )


    # =========================================
    # DMARC
    # =========================================

    if dmarc == "FAIL":

        score += 20


        score_breakdown.append({

            "factor":
                "DMARC authentication failure",

            "points":
                20,

            "reason": (
                "DMARC authentication or domain "
                "alignment failed, increasing the "
                "likelihood of sender impersonation."
            )

        })


        indicators.append(
            "DMARC authentication failed"
        )


        risk_factors.append(
            "DMARC authentication failed, indicating "
            "an authentication or domain-alignment problem."
        )


    elif dmarc == "PASS":

        risk_factors.append(
            "DMARC authentication passed."
        )


    # =========================================
    # URL ANALYSIS
    # =========================================

    urls = extract_urls(body)

    # =========================================
    # IOC REPUTATION INTELLIGENCE
    # =========================================

    ioc_reputation = analyze_ioc_reputation(
        urls,
        domain,
        email.sourceIp,
        body
    )

    if ioc_reputation["totalIOCs"] > 0:
        for result in (
            ioc_reputation["urls"]
            + ioc_reputation["domains"]
            + ioc_reputation["ips"]
        ):
            if result["reputation"] in ["Malicious", "Suspicious"]:
                indicator = (
                    f'{result["type"]} reputation: '
                    f'{result["reputation"]} - {result["ioc"]}'
                )
                if indicator not in indicators:
                    indicators.append(indicator)

    if urls:

        indicators.append(

            f"Suspicious URL detected "
            f"({len(urls)} URL"
            f"{'s' if len(urls) != 1 else ''})"

        )


        risk_factors.append(

            "The message contains one or more "
            "clickable URLs that require investigation."

        )


        recommended_actions.append(

            "Inspect and reputation-check all URLs "
            "before allowing user access."

        )


    # =========================================
    # LOOKALIKE DOMAIN DETECTION
    # =========================================

    lookalike_result = (
        detect_lookalike_domain(domain)
    )


    if lookalike_result:

        score += 10


        score_breakdown.append({

            "factor":
                "Lookalike / impersonation domain",

            "points":
                10,

            "reason": (
                "The sender domain contains a pattern "
                "associated with brand impersonation."
            )

        })


        indicators.append(
            lookalike_result
        )


        risk_factors.append(
            "The sender domain appears to imitate "
            "a known organization."
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


    if contains_any(
        text,
        urgency_patterns
    ):

        if (
            "Urgency / social engineering language"
            not in indicators
        ):

            indicators.append(
                "Urgency / social engineering language"
            )


        risk_factors.append(

            "The message uses urgency or pressure "
            "to encourage immediate action."

        )


        recommended_actions.append(

            "Verify the request through an independent "
            "trusted communication channel."

        )


    if contains_any(
        text,
        credential_patterns
    ):

        if (
            "Credential harvesting indicators detected"
            not in indicators
        ):

            indicators.append(
                "Credential harvesting indicators detected"
            )


        risk_factors.append(

            "The message requests or references "
            "credentials, login activity, or "
            "identity verification."

        )


        recommended_actions.append(

            "Do not enter credentials through links "
            "contained in the message."

        )


    # =========================================
    # MULTIPLE FORENSIC INDICATORS
    # =========================================

    if len(indicators) >= 3:

        score += 10


        score_breakdown.append({

            "factor":
                "Multiple forensic indicators",

            "points":
                10,

            "reason": (
                "Multiple independent indicators were "
                "detected, which increases the overall "
                "threat level."
            )

        })


        risk_factors.append(

            "Multiple independent indicators increase "
            "the overall threat level."

        )


    # =========================================
    # SCORE LIMIT
    # =========================================

    score = min(
        score,
        100
    )


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


    # Attachment with suspicious file
    # gets Malware classification.

    if (
        attachment_analysis[
            "suspiciousAttachmentCount"
        ] > 0
    ):

        category = "Malware"


    elif contains_any(
        text,
        credential_category
    ):

        category = "Credential Theft"


    elif contains_any(
        text,
        financial_category
    ):

        category = "BEC / Fraud"


    elif contains_any(
        text,
        malware_category
    ):

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

            "Reset credentials if the recipient "
            "interacted with the message."

        )


        recommended_actions.append(

            "Review authentication logs for suspicious "
            "account activity."

        )


    elif category == "BEC / Fraud":

        recommended_actions.append(

            "Verify payment or banking changes directly "
            "with the requester."

        )


        recommended_actions.append(

            "Place suspicious financial transactions "
            "on hold until verified."

        )


    elif category == "Malware":

        recommended_actions.append(

            "Quarantine suspicious attachments and "
            "scan affected endpoints."

        )


    # =========================================
    # GENERAL RESPONSE
    # =========================================

    if not recommended_actions:

        recommended_actions.append(

            "Continue investigation using headers, "
            "domain reputation and infrastructure "
            "intelligence."

        )


    # =========================================
    # REMOVE DUPLICATES
    # =========================================

    indicators = list(
        dict.fromkeys(
            indicators
        )
    )


    risk_factors = list(
        dict.fromkeys(
            risk_factors
        )
    )


    recommended_actions = list(
        dict.fromkeys(
            recommended_actions
        )
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

            "High-confidence malicious activity "
            "detected based on authentication failures, "
            "suspicious content, social-engineering "
            "signals, attachment analysis and multiple "
            "forensic indicators."

        )


    elif classification == "Suspicious":

        explanation = (

            "The email contains multiple suspicious "
            "characteristics including potentially "
            "risky content or attachments that require "
            "further investigation before being "
            "considered safe."

        )


    else:

        explanation = (

            "No strong malicious indicators were "
            "identified by the current analysis engine."

        )


    # =========================================
    # SCORE EXPLANATION
    # =========================================

    total_points_before_cap = sum(

        item["points"]

        for item in score_breakdown

    )


    score_explanation = {

        "baseScore":
            40,

        "pointsAdded":
            max(
                0,
                total_points_before_cap - 40
            ),

        "rawScore":
            total_points_before_cap,

        "finalScore":
            score,

        "cappedAt100":
            total_points_before_cap > 100,

        "method": (

            "Threat score is calculated from a "
            "transparent baseline plus weighted "
            "forensic indicators, including "
            "attachment analysis."

        )

    }


    # =========================================
    # FINAL RESPONSE
    # =========================================

    return {

        "success":
            True,


        "analysis": {

            "classification":
                classification,


            "threatScore":
                score,


            "confidence":
                confidence,


            "priority":
                priority,


            "severity":
                severity,


            "category":
                category,


            "indicators":
                indicators,


            "indicatorCount":
                len(indicators),


            "riskFactors":
                risk_factors,


            "explanation":
                explanation,


            # =================================
            # EXPLAINABLE THREAT SCORE
            # =================================

            "scoreBreakdown":
                score_breakdown,


            "scoreExplanation":
                score_explanation,


            "recommendedActions":
                recommended_actions,


            # =================================
            # AUTHENTICATION
            # =================================

            "authentication": {

                "spf":
                    spf,

                "dkim":
                    dkim,

                "dmarc":
                    dmarc

            },


            # =================================
            # INFRASTRUCTURE
            # =================================

            "sourceIp":
                email.sourceIp,


            "domain":
                email.domain,


            # =================================
            # URL INTELLIGENCE
            # =================================

            "urlsDetected":
                urls,


            "urlCount":
                len(urls),

            # =================================
            # IOC REPUTATION INTELLIGENCE
            # =================================

            "iocReputation":
                ioc_reputation,

            # =================================
            # ATTACHMENT FORENSICS
            # =================================

            "attachments":
                email.attachments,


            "attachmentForensics":
                attachment_analysis,


            # =================================
            # ENGINE INFORMATION
            # =================================

            "engine": {

                "name":
                    "TraceMail Explainable Threat Intelligence Engine",

                "version":
                    "2.2.0",

                "type":
                    "Rule-based forensic intelligence"

            }

        }

    }