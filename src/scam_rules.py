import re


# ============================================================
# ScamShield-X Rule Engine
# ============================================================

SCAM_RULES = {

    "payment_request": {
        "patterns": [
            r"\bpay\b",
            r"\bpayment\b",
            r"\bfee\b",
            r"\bdeposit\b",
            r"\bprocessing fee\b",
            r"\bregistration fee\b",
            r"\bjoining fee\b",
            r"\btransfer money\b",
            r"\bsend money\b",

            # Money/payment formats
            r"\bpay\s+(?:₹|rs\.?|inr|\$|usd)?\s*[\d,]+",
            r"\b(?:pay|send|transfer)\s+(?:₹|rs\.?|inr|\$|usd)?\s*[\d,]+",
        ],
        "weight": 18,
        "reason": "Requests money, payment, deposit, or a fee"
    },


    "credential_request": {
        "patterns": [
            r"\botp\b",
            r"\bpassword\b",
            r"\bpin\b",
            r"\bcvv\b",
            r"\bcard number\b",
            r"\bbank details\b",
            r"\blogin details\b",
            r"\bverify your account\b",
            r"\bverify account\b",
        ],
        "weight": 25,
        "reason": "Requests sensitive credentials or financial information"
    },


    "urgency": {
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bact now\b",
            r"\blast chance\b",
            r"\bwithin \d+ minutes\b",
            r"\bwithin \d+ hours\b",
            r"\baccount will be blocked\b",
            r"\baccount will be suspended\b",
            r"\btoday only\b",
            r"\bexpires today\b",
            r"\bdo not delay\b",
        ],
        "weight": 15,
        "reason": "Uses urgency or pressure to make the user act quickly"
    },


    # ========================================================
    # PRIZE / WINNER SCAMS
    # ========================================================
    "prize": {
        "patterns": [

            # Winner language
            r"\byou won\b",
            r"\byou have won\b",
            r"\byou've won\b",
            r"\byou are a winner\b",
            r"\byou are the winner\b",
            r"\byou are a lucky winner\b",
            r"\blucky winner\b",
            r"\bcongratulations\b",
            r"\bcongrats\b",
            r"\bwinner\b",
            r"\bwinning\b",

            # Prize/reward language
            r"\bprize\b",
            r"\breward\b",
            r"\bgiveaway\b",
            r"\blottery\b",
            r"\bjackpot\b",
            r"\bcash prize\b",
            r"\bmoney prize\b",
            r"\bselected as a winner\b",
            r"\bselected for a prize\b",

            # Money after winning language
            r"\bwon\s+(?:₹|rs\.?|inr|\$|usd)?\s*[\d,]+",
            r"\bwon\s+(?:₹|rs\.?|inr|\$|usd)?\s*[\d,]+\s*(?:rupees?|dollars?)?\b",

            # Monetary amount
            r"(?:₹|rs\.?|inr)\s*[\d,]+",
            r"(?:\$|usd)\s*[\d,]+",
        ],
        "weight": 30,
        "reason": "Claims an unexpected prize, reward, giveaway, lottery win, or monetary reward"
    },


    "investment": {
        "patterns": [
            r"\bguaranteed profit\b",
            r"\bguaranteed returns\b",
            r"\bdouble your money\b",
            r"\bquick profit\b",
            r"\bhigh returns\b",
            r"\bcrypto investment\b",
            r"\binvest now\b",
            r"\bguaranteed income\b",
            r"\bno risk investment\b",
        ],
        "weight": 20,
        "reason": "Contains suspicious investment or guaranteed-return claims"
    },


    "link_redirect": {
        "patterns": [
            r"\bclick here\b",
            r"\bclick the link\b",
            r"\blink in bio\b",
            r"\bvisit this link\b",
            r"\bopen this link\b",
            r"\btap the link\b",
            r"\bclick below\b",
        ],
        "weight": 15,
        "reason": "Attempts to redirect the user to a link"
    },


    "job_scam": {
        "patterns": [
            r"\bwork from home\b",
            r"\bear[n]?\s+(?:₹|rs\.?|inr|\$|usd)?\s*[\d,]+",
            r"\bno experience required\b",
            r"\bregistration fee\b",
            r"\bjoining fee\b",
            r"\bjob offer\b",
            r"\bguaranteed income\b",
            r"\bearn money\b",
            r"\beasy money\b",
        ],
        "weight": 18,
        "reason": "Contains suspicious job-offer or unrealistic-income indicators"
    },


    "impersonation": {
        "patterns": [
            r"\bwe are from your bank\b",
            r"\bbank official\b",
            r"\bpolice department\b",
            r"\bincome tax department\b",
            r"\bcustomer support\b",
            r"\baccount verification team\b",
            r"\bbank security team\b",
        ],
        "weight": 20,
        "reason": "May be impersonating an organization or authority"
    }
}


# ============================================================
# Additional combination rules
# ============================================================

def detect_combination_evidence(text, categories):
    """
    Detect combinations that are significantly more suspicious
    than individual keywords.
    """

    extra_score = 0
    extra_findings = []

    # --------------------------------------------------------
    # Winner + money
    # --------------------------------------------------------
    winner_pattern = re.search(
        r"\b(?:you\s+)?(?:won|have won|you've won|winner)\b",
        text,
        re.IGNORECASE
    )

    money_pattern = re.search(
        r"(?:₹|rs\.?|inr|\$|usd)?\s*[\d,]+\s*(?:rupees?|dollars?)?\b",
        text,
        re.IGNORECASE
    )

    if winner_pattern and money_pattern:
        extra_score += 35
        extra_findings.append({
            "category": "prize_money_combination",
            "matched": (
                f"{winner_pattern.group(0)} + "
                f"{money_pattern.group(0).strip()}"
            ),
            "reason": "Winner language combined with a monetary amount",
            "weight": 35
        })

    # --------------------------------------------------------
    # Congratulations + winner/prize
    # --------------------------------------------------------
    congrats = re.search(
        r"\b(?:congratulations|congrats)\b",
        text,
        re.IGNORECASE
    )

    prize_words = re.search(
        r"\b(?:won|winner|prize|reward|lottery|giveaway|jackpot)\b",
        text,
        re.IGNORECASE
    )

    if congrats and prize_words:
        extra_score += 20
        extra_findings.append({
            "category": "congratulations_prize_combination",
            "matched": f"{congrats.group(0)} + {prize_words.group(0)}",
            "reason": "Congratulations language combined with prize or winner language",
            "weight": 20
        })

    # --------------------------------------------------------
    # Prize + payment
    # --------------------------------------------------------
    if "prize" in categories and "payment_request" in categories:
        extra_score += 30
        extra_findings.append({
            "category": "prize_payment_combination",
            "matched": "prize + payment request",
            "reason": "Prize claim combined with a request for money",
            "weight": 30
        })

    # --------------------------------------------------------
    # Prize + link
    # --------------------------------------------------------
    if "prize" in categories and "link_redirect" in categories:
        extra_score += 20
        extra_findings.append({
            "category": "prize_link_combination",
            "matched": "prize + link",
            "reason": "Prize claim combined with a link or redirection request",
            "weight": 20
        })

    # --------------------------------------------------------
    # Credential + urgency
    # --------------------------------------------------------
    if "credential_request" in categories and "urgency" in categories:
        extra_score += 25
        extra_findings.append({
            "category": "credential_urgency_combination",
            "matched": "credential request + urgency",
            "reason": "Sensitive information request combined with pressure to act quickly",
            "weight": 25
        })

    # --------------------------------------------------------
    # Job + payment
    # --------------------------------------------------------
    if "job_scam" in categories and "payment_request" in categories:
        extra_score += 25
        extra_findings.append({
            "category": "job_payment_combination",
            "matched": "job offer + payment request",
            "reason": "Job opportunity combined with a registration, joining, or other payment request",
            "weight": 25
        })

    return extra_score, extra_findings


# ============================================================
# Main rule detector
# ============================================================

def detect_scam_indicators(text):

    text = str(text).lower().strip()

    findings = []
    total_score = 0
    categories = set()

    # --------------------------------------------------------
    # Individual rules
    # --------------------------------------------------------

    for category, rule in SCAM_RULES.items():

        for pattern in rule["patterns"]:

            match = re.search(
                pattern,
                text,
                re.IGNORECASE
            )

            if match:

                findings.append({
                    "category": category,
                    "matched": match.group(0),
                    "reason": rule["reason"],
                    "weight": rule["weight"]
                })

                total_score += rule["weight"]
                categories.add(category)

                # One match per category is enough
                break

    # --------------------------------------------------------
    # Combination evidence
    # --------------------------------------------------------

    combination_score, combination_findings = detect_combination_evidence(
        text,
        categories
    )

    total_score += combination_score
    findings.extend(combination_findings)

    # --------------------------------------------------------
    # Special strong-scam escalation
    # --------------------------------------------------------

    # Winner/prize + money should always be treated as
    # strong scam evidence unless there is clear context
    # proving it is legitimate.

    has_winner = bool(re.search(
        r"\b(?:won|winner|winning|prize|reward|lottery|giveaway|jackpot)\b",
        text,
        re.IGNORECASE
    ))

    has_money = bool(re.search(
        r"(?:₹|rs\.?|inr|\$|usd)\s*[\d,]+|"
        r"\b\d[\d,]{2,}\b",
        text,
        re.IGNORECASE
    ))

    if has_winner and has_money:

        # Ensure the rule engine gives this enough weight.
        total_score = max(total_score, 85)

        findings.append({
            "category": "strong_prize_evidence",
            "matched": "winner/prize + monetary amount",
            "reason": "Strong combination of winning/prize language and money",
            "weight": 0
        })

    # --------------------------------------------------------
    # Multiple independent scam categories
    # --------------------------------------------------------

    if len(categories) >= 3:
        total_score = max(total_score, 80)

    # --------------------------------------------------------
    # Limit score
    # --------------------------------------------------------

    total_score = min(total_score, 100)

    return {
        "score": total_score,
        "findings": findings,
        "categories": sorted(list(categories))
    }