try:
    from langdetect import detect, LangDetectException
except ImportError:
    detect = None
    class LangDetectException(Exception):
        pass

LANGUAGE_NAMES = {
    "en": "English", "ta": "Tamil", "hi": "Hindi", "te": "Telugu",
    "ml": "Malayalam", "kn": "Kannada", "unknown": "Unknown"
}

SCAM_KEYWORDS = {
    "en": ["urgent", "verify", "account blocked", "otp", "password", "bank", "kyc", "prize", "winner", "lottery", "refund", "send money", "pay now", "investment", "guaranteed profit", "limited time", "act now"],
    "ta": ["அவசரம்", "சரிபார்க்க", "கணக்கு முடக்கப்படும்", "வங்கி", "கடவுச்சொல்", "ரகசிய குறியீடு", "பரிசு", "லாட்டரி", "பணம்", "முதலீடு", "உடனடியாக", "கிளிக்", "வெற்றி"],
    "hi": ["जरूरी", "तुरंत", "सत्यापित", "खाता बंद", "बैंक", "पासवर्ड", "ओटीपी", "इनाम", "लॉटरी", "पैसे", "निवेश", "क्लिक करें"],
}


def detect_language(text):
    if not text or not str(text).strip() or detect is None:
        return {"code": "unknown", "name": "Unknown"}
    try:
        code = detect(str(text))
        return {"code": code, "name": LANGUAGE_NAMES.get(code, code.upper())}
    except LangDetectException:
        return {"code": "unknown", "name": "Unknown"}


def find_multilingual_keywords(text):
    if not text:
        return []
    found = []
    lower = str(text).lower()
    for language, keywords in SCAM_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in lower:
                found.append({"keyword": keyword, "language": LANGUAGE_NAMES.get(language, language)})
    return found
