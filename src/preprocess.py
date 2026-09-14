import re
import unicodedata


def clean_text(text):
    """Normalize text while preserving Unicode characters for multilingual input."""
    if text is None:
        return ""
    text = unicodedata.normalize("NFKC", str(text)).lower()
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", " EMAIL ", text, flags=re.IGNORECASE)
    text = re.sub(r"https?://\S+|www\.\S+", " URL ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def prepare_for_model(text, channel):
    channel = str(channel or "unknown").lower().strip()
    return f"channel_{channel} {clean_text(text)}"
