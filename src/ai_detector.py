"""
ScamShield-X
Unified AI + local fallback scam detection engine.

The system first attempts AI analysis through OpenAI.
If the API is unavailable, has no credits, or returns an error,
ScamShield-X automatically uses a local evidence-based detector.
"""

import json
import os
import re
from typing import Any, Dict

from dotenv import load_dotenv
from openai import OpenAI

from src.ai_prompt import SYSTEM_PROMPT, build_analysis_prompt
from src.ai_schema import normalize_ai_result


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# OPENAI CLIENT
# ============================================================

def get_client() -> OpenAI:
    """Create the OpenAI client using the API key in .env."""

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY was not found. "
            "Please add your API key to the .env file."
        )

    return OpenAI(api_key=api_key)


# ============================================================
# LOCAL FALLBACK ENGINE
# ============================================================

def _contains_any(text: str, patterns: list[str]) -> bool:
    """Return True when any pattern is found in the text."""

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


def _local_analysis(
    content: str,
    channel: str,
    language: str = "unknown",
    metadata: dict | None = None,
) -> Dict[str, Any]:
    """
    Transparent evidence-based local scam detector.

    Every score contribution is tied to an observable
    signal in the supplied content.
    """

    text = content.strip()
    lower = text.lower()

    score = 0

    evidence = []
    red_flags = []
    scam_types = []


    # ========================================================
    # 1. FINANCIAL / PAYMENT REQUEST
    # ========================================================

    financial_patterns = [
        r"\bpay\b",
        r"\bpayment\b",
        r"\btransfer\b",
        r"\bsend\s+(?:money|cash|funds)\b",
        r"\bupi\b",
        r"\bpaytm\b",
        r"\bphonepe\b",
        r"\bgpay\b",
        r"\bbank\s+account\b",
        r"\baccount\s+number\b",
        r"\bcard\s+number\b",
        r"\bcredit\s+card\b",
        r"\bdebit\s+card\b",
        r"\brefund\b",
        r"\bfee\b",
        r"\bdeposit\b",
    ]

    has_financial_request = _contains_any(
        lower,
        financial_patterns,
    )

    if has_financial_request:

        score += 25

        evidence.append(
            "The message contains a financial or payment-related request."
        )

        red_flags.append(
            "Financial/payment request"
        )

        scam_types.append(
            "financial_scam"
        )


    # ========================================================
    # 2. CREDENTIAL / OTP REQUEST
    # ========================================================

    credential_patterns = [
        r"\botp\b",
        r"\bone[-\s]?time\s+password\b",
        r"\bpassword\b",
        r"\bpin\b",
        r"\bcvv\b",
        r"\bverification\s+code\b",
        r"\bsecurity\s+code\b",
        r"\blogin\b",
        r"\bsign\s*in\b",
        r"\bverify\s+(?:your\s+)?account\b",
        r"\busername\b",
        r"\bverification\s+process\b",
        r"\bsecurity\s+verification\b",
    ]

    has_credential_request = _contains_any(
        lower,
        credential_patterns,
    )

    if has_credential_request:

        score += 35

        evidence.append(
            "The message requests or pressures the recipient "
            "regarding credentials, OTPs, PINs, or account verification."
        )

        red_flags.append(
            "Credential or verification request"
        )

        scam_types.append(
            "credential_theft"
        )


    # ========================================================
    # 3. URGENCY / PRESSURE
    # ========================================================

    urgency_patterns = [
        r"\bimmediately\b",
        r"\bnow\b",
        r"\burgent(?:ly)?\b",
        r"\bact\s+now\b",
        r"\blast\s+chance\b",
        r"\bexpires?\b",
        r"\bexpire[sd]?\b",
        r"\bwithin\s+\d+\s*(?:minutes?|hours?|days?)\b",
        r"\btoday\s+only\b",
        r"\bdo\s+not\s+delay\b",
        r"\bfinal\s+notice\b",
        r"\baccount\s+will\s+be\s+(?:blocked|closed|suspended)\b",
    ]

    has_urgency = _contains_any(
        lower,
        urgency_patterns,
    )

    if has_urgency:

        score += 20

        evidence.append(
            "The message uses urgency or pressure "
            "to encourage immediate action."
        )

        red_flags.append(
            "Urgency or pressure"
        )

        scam_types.append(
            "social_engineering"
        )


    # ========================================================
    # 4. PRIZE / REWARD SCAM
    # ========================================================

    prize_patterns = [
        r"\bcongratulations\b",
        r"\byou\s+(?:have\s+)?won\b",
        r"\byou\s+are\s+a\s+winner\b",
        r"\bprize\b",
        r"\breward\b",
        r"\blottery\b",
        r"\bjackpot\b",
        r"\bcash\s+prize\b",
        r"\bclaim\s+(?:your\s+)?(?:prize|reward|money)\b",
    ]

    money_patterns = [
        r"(?:₹|rs\.?|inr)\s*\d[\d,]*(?:\.\d+)?",
        r"\$\s*\d[\d,]*(?:\.\d+)?",
        r"\b\d[\d,]*\s*(?:rupees|dollars)\b",
    ]

    has_prize = _contains_any(
        lower,
        prize_patterns,
    )

    has_money = _contains_any(
        lower,
        money_patterns,
    )

    if has_prize:

        score += 30

        evidence.append(
            "The message contains an unsolicited prize, reward, "
            "lottery, or winning claim."
        )

        red_flags.append(
            "Unexpected prize/reward claim"
        )

        scam_types.append(
            "prize_scam"
        )

    if has_prize and has_money:

        score += 15

        evidence.append(
            "The prize/reward claim is associated "
            "with a specific monetary amount."
        )


    # ========================================================
    # 5. SUSPICIOUS LINK
    # ========================================================

    url_pattern = (
        r"(?:https?://|www\.)\S+"
        r"|(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl)/\S+"
    )

    has_external_link = (
        re.search(
            url_pattern,
            lower,
        )
        is not None
    )

    if has_external_link:

        score += 20

        evidence.append(
            "The message contains a web link."
        )

        red_flags.append(
            "External link"
        )

        scam_types.append(
            "link_based_scam"
        )


    # ========================================================
    # 6. SHORTENED URL
    # ========================================================

    shortened_url_patterns = [
        r"\bbit\.ly/",
        r"\btinyurl\.com/",
        r"\bt\.co/",
        r"\bgoo\.gl/",
        r"\bcutt\.ly/",
        r"\bshorturl\.",
    ]

    has_shortened_url = _contains_any(
        lower,
        shortened_url_patterns,
    )

    if has_shortened_url:

        score += 15

        evidence.append(
            "The message contains a shortened URL "
            "that obscures its destination."
        )

        red_flags.append(
            "Shortened URL"
        )


    # ========================================================
    # 7. JOB SCAM
    # ========================================================

    job_patterns = [
        r"\bwork\s+from\s+home\b",
        r"\bwork\s+online\b",
        r"\bjob\s+offer\b",
        r"\bjob\s+opportunity\b",
        r"\bpart[-\s]?time\s+job\b",
        r"\bearn\s+(?:₹|rs\.?|inr|\$)?\s*\d+",
        r"\bsalary\b",
        r"\brecruitment\b",
        r"\bselected\s+for\s+(?:the\s+)?job\b",
        r"\bregistration\s+fee\b",
        r"\bprocessing\s+fee\b",
    ]

    has_job_signal = _contains_any(
        lower,
        job_patterns,
    )

    if has_job_signal:

        score += 25

        evidence.append(
            "The message contains job/recruitment language "
            "commonly associated with employment scams."
        )

        red_flags.append(
            "Suspicious job/recruitment offer"
        )

        scam_types.append(
            "job_scam"
        )


    # ========================================================
    # 8. INVESTMENT / CRYPTO SCAM
    # ========================================================

    investment_patterns = [
        r"\binvest\b",
        r"\binvestment\b",
        r"\bguaranteed\s+(?:return|profit)\b",
        r"\bguaranteed\s+profit\b",
        r"\bdouble\s+your\s+money\b",
        r"\bhigh\s+returns?\b",
        r"\bcrypto(?:currency)?\b",
        r"\btrading\s+profit\b",
        r"\bpassive\s+income\b",
        r"\bquick\s+profit\b",
    ]

    has_investment_signal = _contains_any(
        lower,
        investment_patterns,
    )

    if has_investment_signal:

        score += 30

        evidence.append(
            "The message promotes an investment "
            "or unusually attractive financial return."
        )

        red_flags.append(
            "Suspicious investment/return claim"
        )

        scam_types.append(
            "investment_scam"
        )


    # ========================================================
    # 9. IMPERSONATION
    # ========================================================

    impersonation_patterns = [
        r"\bbank\b",
        r"\bpaypal\b",
        r"\bamazon\b",
        r"\bflipkart\b",
        r"\bgoogle\b",
        r"\bmicrosoft\b",
        r"\bgovernment\b",
        r"\bpolice\b",
        r"\bcourt\b",
        r"\btax\s+(?:department|office)\b",
        r"\bcustoms\b",
        r"\bcustomer\s+care\b",
        r"\bsupport\s+team\b",
    ]

    has_impersonation = _contains_any(
        lower,
        impersonation_patterns,
    )

    if has_impersonation:

        score += 10

        evidence.append(
            "The message claims an association with "
            "an organization or authority."
        )

        red_flags.append(
            "Possible impersonation"
        )

        scam_types.append(
            "impersonation"
        )


    # ========================================================
    # 10. THREAT / ACCOUNT SUSPENSION
    # ========================================================

    threat_patterns = [
        r"\baccount\s+(?:blocked|closed|suspended|deactivated)\b",
        r"\baccess\s+(?:will\s+be\s+)?(?:restricted|suspended|blocked)\b",
        r"\blegal\s+action\b",
        r"\barrest\b",
        r"\bpolice\s+case\b",
        r"\bcourt\s+case\b",
        r"\bfine\b",
        r"\bpenalty\b",
        r"\bblacklist\b",
        r"\btemporarily\s+restricted\b",
    ]

    has_threat = _contains_any(
        lower,
        threat_patterns,
    )

    if has_threat:

        score += 25

        evidence.append(
            "The message uses threats, penalties, "
            "or account consequences to pressure the recipient."
        )

        red_flags.append(
            "Threat or consequence"
        )

        scam_types.append(
            "social_engineering"
        )


    # ========================================================
    # 11. STRONG PHISHING COMBINATION
    # ========================================================

    phishing_restriction_patterns = [
        r"\baccess\b.*\brestricted\b",
        r"\baccess\b.*\bsuspend",
        r"\baccount\b.*\brestricted\b",
        r"\baccount\b.*\bsuspend",
        r"\baccount\b.*\bblocked\b",
        r"\bsecurity\s+update\b",
        r"\bsecurity\s+check\b",
        r"\broutine\s+security\b",
        r"\bsecurity\s+verification\b",
        r"\bverification\s+process\b",
        r"\bverify\s+(?:your\s+)?account\b",
    ]

    has_phishing_restriction = _contains_any(
        lower,
        phishing_restriction_patterns,
    )

    if (
        has_phishing_restriction
        and has_credential_request
        and has_external_link
    ):

        score += 25

        evidence.append(
            "The combination of account/security verification, "
            "possible access restriction, and an external link "
            "is a strong phishing indicator."
        )

        red_flags.append(
            "Phishing-style account verification"
        )

        scam_types.append(
            "phishing"
        )


    # ========================================================
    # 12. PRIZE + MONEY + LINK
    # ========================================================

    if (
        has_prize
        and has_money
        and has_external_link
    ):

        score += 25

        evidence.append(
            "The combination of an unsolicited monetary prize "
            "and an external link is a strong scam indicator."
        )


    # ========================================================
    # 13. PRIZE + MONEY + URGENCY
    # ========================================================

    if (
        has_prize
        and has_money
        and has_urgency
    ):

        score += 20

        evidence.append(
            "The combination of an unsolicited monetary reward "
            "and urgency strongly increases scam likelihood."
        )


    # ========================================================
    # 14. CREDENTIAL + URGENCY
    # ========================================================

    if (
        has_credential_request
        and has_urgency
    ):

        score += 20

        evidence.append(
            "Credential-related requests combined with urgency "
            "are a strong social-engineering indicator."
        )


    # ========================================================
    # 15. FINANCIAL + URGENCY
    # ========================================================

    if (
        has_financial_request
        and has_urgency
    ):

        score += 20

        evidence.append(
            "A financial request combined with urgency "
            "is a strong scam indicator."
        )


    # ========================================================
    # 16. PHISHING + IMPERSONATION + LINK
    # ========================================================

    if (
        has_impersonation
        and has_credential_request
        and has_external_link
    ):

        score += 20

        evidence.append(
            "An organization or authority claim combined with "
            "account verification and an external link "
            "is a strong phishing indicator."
        )

        red_flags.append(
            "Impersonation-based phishing"
        )

        scam_types.append(
            "phishing"
        )


    # ========================================================
    # 17. THREAT + CREDENTIAL + LINK
    # ========================================================

    if (
        has_threat
        and has_credential_request
        and has_external_link
    ):

        score += 20

        evidence.append(
            "A threat or account restriction combined with "
            "credential verification and a link strongly "
            "indicates phishing or social engineering."
        )

        scam_types.append(
            "phishing"
        )


    # ========================================================
    # 18. NORMALIZE SCORE
    # ========================================================

    score = min(score, 100)


    # ========================================================
    # 19. CONTEXT-AWARE CLASSIFICATION
    # ========================================================

    if score >= 85:

        prediction = "SCAM"
        risk_level = "CRITICAL"
        confidence = 0.97

    elif score >= 70:

        prediction = "SCAM"
        risk_level = "HIGH"
        confidence = 0.93

    elif score >= 50:

        prediction = "SUSPICIOUS"
        risk_level = "MEDIUM"
        confidence = 0.82

    elif score >= 25:

        prediction = "SUSPICIOUS"
        risk_level = "LOW"
        confidence = 0.68

    else:

        prediction = "LEGITIMATE"
        risk_level = "MINIMAL"
        confidence = 0.72


    # ========================================================
    # 20. REMOVE DUPLICATES
    # ========================================================

    scam_types = list(
        dict.fromkeys(scam_types)
    )

    red_flags = list(
        dict.fromkeys(red_flags)
    )

    evidence = list(
        dict.fromkeys(evidence)
    )


    # ========================================================
    # 21. DEFAULT SCAM TYPE
    # ========================================================

    if (
        not scam_types
        and prediction != "LEGITIMATE"
    ):

        scam_types = [
            "social_engineering"
        ]


    # ========================================================
    # 22. RECOMMENDATION
    # ========================================================

    if prediction == "SCAM":

        recommendation = (
            "Do not click links, send money, or share "
            "passwords, OTPs, PINs, or other sensitive "
            "information. Verify the sender through an "
            "independent official channel."
        )

    elif prediction == "SUSPICIOUS":

        recommendation = (
            "Treat this message cautiously. Do not provide "
            "sensitive information or make payments until "
            "the sender and request are independently verified."
        )

    else:

        recommendation = (
            "No strong scam indicators were detected. "
            "Continue to use normal security precautions "
            "and verify unexpected requests."
        )


    # ========================================================
    # 23. DEFAULT EVIDENCE
    # ========================================================

    if not evidence:

        evidence.append(
            "No strong scam indicators were detected "
            "in the supplied content."
        )


    # ========================================================
    # 24. RESULT
    # ========================================================

    result = {

        "prediction": prediction,

        "risk_score": score,

        "risk_level": risk_level,

        "confidence": confidence,

        "scam_type": scam_types,

        "reasons": evidence[:8],

        "evidence": evidence[:10],

        "red_flags": red_flags[:10],

        "recommendation": recommendation,
    }


    return normalize_ai_result(result)


# ============================================================
# UNIFIED ANALYSIS FUNCTION
# ============================================================

def analyze_with_ai(
    content: str,
    channel: str,
    language: str = "unknown",
    metadata: dict | None = None,
) -> Dict[str, Any]:

    """
    Analyze content using the unified ScamShield-X engine.

    Primary:
        OpenAI

    Fallback:
        Transparent local evidence-based detector
    """

    if not content or not content.strip():

        raise ValueError(
            "No content was provided for analysis."
        )


    # ========================================================
    # TRY OPENAI FIRST
    # ========================================================

    try:

        client = get_client()

        user_prompt = build_analysis_prompt(
            content=content,
            channel=channel,
            language=language,
            metadata=metadata,
        )

        model = os.getenv(
            "OPENAI_MODEL",
            "gpt-4o-mini",
        )

        response = client.chat.completions.create(

            model=model,

            temperature=0,

            response_format={
                "type": "json_object"
            },

            messages=[

                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },

                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
        )


        raw_content = (
            response.choices[0]
            .message
            .content
        )


        if not raw_content:

            raise RuntimeError(
                "The AI returned an empty response."
            )


        try:

            result = json.loads(
                raw_content
            )

        except json.JSONDecodeError as exc:

            raise RuntimeError(
                "The AI returned invalid JSON."
            ) from exc


        normalized = normalize_ai_result(
            result
        )

        normalized["_engine"] = "openai"

        return normalized


    # ========================================================
    # AUTOMATIC LOCAL FALLBACK
    # ========================================================

    except Exception as exc:

        print(
            f"\n[ScamShield-X] OpenAI unavailable: "
            f"{type(exc).__name__}: {exc}"
        )

        print(
            "[ScamShield-X] "
            "Using local evidence-based fallback.\n"
        )


        result = _local_analysis(

            content=content,

            channel=channel,

            language=language,

            metadata=metadata,
        )


        result["_engine"] = (
            "local_fallback"
        )


        return result


# ============================================================
# COMMAND-LINE TEST
# ============================================================

if __name__ == "__main__":

    test_message = (
        "Congratulations! You won ₹50,000. "
        "Click here immediately to claim your prize."
    )

    print(
        "\nRunning ScamShield-X AI test...\n"
    )


    result = analyze_with_ai(

        content=test_message,

        channel="sms",

        language="English",
    )


    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )