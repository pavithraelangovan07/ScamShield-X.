"""
ScamShield-X
AI response schema and validation.
"""

from typing import Any, Dict


ALLOWED_PREDICTIONS = {
    "SCAM",
    "SUSPICIOUS",
    "LEGITIMATE",
}

ALLOWED_RISK_LEVELS = {
    "MINIMAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def _clean_string(value: Any, default: str = "") -> str:
    """Convert a value into a clean string."""
    if value is None:
        return default

    return str(value).strip()


def _clean_list(value: Any) -> list[str]:
    """Convert an AI response field into a list of strings."""
    if value is None:
        return []

    if isinstance(value, str):
        return [value.strip()] if value.strip() else []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return []


def normalize_ai_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize and validate the structured response returned by the AI.
    """

    if not isinstance(result, dict):
        raise ValueError("AI response must be a JSON object.")

    prediction = _clean_string(
        result.get("prediction"),
        "SUSPICIOUS",
    ).upper()

    if prediction not in ALLOWED_PREDICTIONS:
        prediction = "SUSPICIOUS"

    risk_level = _clean_string(
        result.get("risk_level"),
        "MEDIUM",
    ).upper()

    if risk_level not in ALLOWED_RISK_LEVELS:
        risk_level = "MEDIUM"

    try:
        risk_score = float(result.get("risk_score", 50))
    except (TypeError, ValueError):
        risk_score = 50.0

    risk_score = max(0.0, min(100.0, risk_score))

    try:
        confidence = float(result.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    confidence = max(0.0, min(1.0, confidence))

    scam_type = _clean_list(result.get("scam_type"))
    reasons = _clean_list(result.get("reasons"))
    evidence = _clean_list(result.get("evidence"))
    red_flags = _clean_list(result.get("red_flags"))

    recommendation = _clean_string(
        result.get("recommendation"),
        "Verify the sender independently before taking any action.",
    )

    return {
        "prediction": prediction,
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "confidence": round(confidence, 3),
        "scam_type": scam_type,
        "reasons": reasons,
        "evidence": evidence,
        "red_flags": red_flags,
        "recommendation": recommendation,
    }