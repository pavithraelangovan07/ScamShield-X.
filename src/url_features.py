import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "account", "update", "secure", "claim", "reward", "prize", "free", "gift", "bonus", "bank", "payment", "wallet"]


def extract_url_features(url):
    url = str(url).strip()
    parsed = urlparse(url)
    host = parsed.netloc
    return {
        "url_length": len(url),
        "https": int(url.lower().startswith("https://")),
        "has_ip": int(bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", url))),
        "dots": url.count("."),
        "hyphens": url.count("-"),
        "digits": sum(c.isdigit() for c in url),
        "special_chars": len(re.findall(r"[^a-zA-Z0-9]", url)),
        "suspicious_words": sum(w in url.lower() for w in SUSPICIOUS_WORDS),
        "subdomain_depth": host.count("."),
    }


def explain_url(url):
    value = str(url).strip().lower()
    reasons = []
    if not value.startswith("https://"):
        reasons.append("URL does not use HTTPS.")
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", value):
        reasons.append("URL contains an IP address instead of a normal domain.")
    matches = [w for w in SUSPICIOUS_WORDS if w in value]
    for word in matches[:5]:
        reasons.append(f"Suspicious URL keyword: '{word}'.")
    if value.count("-") >= 3:
        reasons.append("URL contains many hyphens.")
    if len(value) > 100:
        reasons.append("URL is unusually long.")
    if not reasons:
        reasons.append("No obvious URL-level warning signs were detected.")
    return reasons
