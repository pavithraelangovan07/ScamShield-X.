
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update",
    "secure", "claim", "reward", "prize",
    "free", "gift", "bonus", "bank",
    "payment", "wallet"
]

HIGH_RISK_WORDS = [
    "login", "verify", "account", "secure",
    "bank", "wallet", "payment"
]


def normalize_url(url):
    value = str(url).strip()

    if not value:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value

    return value


def extract_url_features(url):
    value = normalize_url(url)
    parsed = urlparse(value)

    host = parsed.hostname or ""
    lower = value.lower()

    matched_words = [
        word for word in SUSPICIOUS_WORDS
        if re.search(r"\b" + re.escape(word) + r"\b", lower)
        or word in host.lower()
    ]

    return {
        "url_length": len(value),
        "https": int(parsed.scheme.lower() == "https"),
        "has_ip": int(bool(
            re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", host)
        )),
        "dots": host.count("."),
        "hyphens": host.count("-"),
        "digits": sum(c.isdigit() for c in value),
        "special_chars": len(
            re.findall(r"[^a-zA-Z0-9]", value)
        ),
        "suspicious_words": len(set(matched_words)),
        "matched_words": sorted(set(matched_words)),
        "subdomain_depth": host.count(".")
    }


def analyze_url(url):
    value = normalize_url(url)
    parsed = urlparse(value)

    host = (parsed.hostname or "").lower()
    full_url = value.lower()

    features = extract_url_features(value)

    score = 0
    reasons = []

    if not value:
        return {
            "score": 0,
            "reasons": ["No URL was supplied."],
            "features": features
        }

    if parsed.scheme.lower() != "https":
        score += 8
        reasons.append("URL does not use HTTPS.")

    if features["has_ip"]:
        score += 35
        reasons.append(
            "URL uses an IP address instead of a normal domain."
        )

    if "@" in parsed.netloc:
        score += 30
        reasons.append(
            "URL contains an @ symbol in its address."
        )

    high_risk_matches = [
        word for word in HIGH_RISK_WORDS
        if word in host
    ]

    other_matches = [
        word for word in SUSPICIOUS_WORDS
        if word in full_url and word not in high_risk_matches
    ]

    for word in high_risk_matches:
        score += 13
        reasons.append(
            f"High-risk URL keyword found in domain: {word}."
        )

    for word in other_matches:
        score += 7
        reasons.append(
            f"Suspicious URL keyword found: {word}."
        )

    if features["hyphens"] >= 3:
        score += 10
        reasons.append(
            "Domain contains several hyphens."
        )

    if features["subdomain_depth"] >= 3:
        score += 10
        reasons.append(
            "URL contains multiple subdomain levels."
        )

    if features["url_length"] > 100:
        score += 5
        reasons.append(
            "URL is unusually long."
        )

    score = min(score, 100)

    if not reasons:
        reasons.append(
            "No obvious URL-level warning signs were detected."
        )

    return {
        "score": score,
        "reasons": reasons,
        "features": features
    }


def explain_url(url, features=None):
    analysis = analyze_url(url)
    return analysis["reasons"]
