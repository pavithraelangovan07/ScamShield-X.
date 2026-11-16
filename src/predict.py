
from pathlib import Path
import joblib

from src.preprocess import prepare_for_model
from src.scam_rules import detect_scam_indicators

try:
    from src.url_features import (
        extract_url_features,
        explain_url,
        analyze_url
    )
except ImportError:
    extract_url_features = None
    explain_url = None
    analyze_url = None


MODEL_PATH = Path("models/unified_model.joblib")

_model = None


def load_model():
    global _model

    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                "Model not found. Run: python src\\unified_train.py"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


def calculate_risk(ml_probability, rule_score, categories):
    ml_score = ml_probability * 100
    score = (ml_score * 0.70) + (rule_score * 0.30)

    if len(categories) >= 3:
        score += 12

    if "payment_request" in categories and "prize" in categories:
        score += 10

    if "credential_request" in categories and "urgency" in categories:
        score += 10

    if "job_scam" in categories and "payment_request" in categories:
        score += 10

    if "investment" in categories and "payment_request" in categories:
        score += 8

    score = min(round(score, 2), 100)

    if rule_score >= 60:
        score = max(score, 85)

    if rule_score >= 75:
        score = max(score, 92)

    if len(categories) >= 3:
        score = max(score, 90)

    if score >= 90:
        level = "CRITICAL"
        prediction = "SCAM"
    elif score >= 75:
        level = "HIGH"
        prediction = "SCAM"
    elif score >= 50:
        level = "MEDIUM"
        prediction = "REVIEW REQUIRED"
    elif score >= 25:
        level = "LOW"
        prediction = "LIKELY LEGITIMATE"
    else:
        level = "MINIMAL"
        prediction = "LIKELY LEGITIMATE"

    return {
        "score": score,
        "level": level,
        "prediction": prediction
    }


def predict_text(text, channel="sms"):
    model = load_model()

    channel = str(channel or "sms").lower().strip()

    prepared = prepare_for_model(text, channel)

    probabilities = model.predict_proba([prepared])[0]
    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "The trained model does not contain the scam class (1)."
        )

    scam_index = classes.index(1)
    ml_probability = float(probabilities[scam_index])

    rule_result = detect_scam_indicators(text)

    risk = calculate_risk(
        ml_probability,
        rule_result["score"],
        rule_result["categories"]
    )

    result = {
        "prediction": risk["prediction"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "ml_probability": round(ml_probability * 100, 2),
        "rule_score": rule_result["score"],
        "rule_evidence": rule_result["findings"],
        "categories": rule_result["categories"],
        "channel": channel,
        "text": text
    }

    # Additional URL-specific risk analysis
    if channel == "url" and analyze_url:

        url_result = analyze_url(text)

        url_score = url_result["score"]

        # Combine the existing model/rule score with URL analysis.
        # URL analysis can increase risk but cannot lower it.
        final_score = max(
            result["risk_score"],
            url_score
        )

        if final_score >= 90:
            final_level = "CRITICAL"
            final_prediction = "SCAM"
        elif final_score >= 75:
            final_level = "HIGH"
            final_prediction = "SCAM"
        elif final_score >= 50:
            final_level = "MEDIUM"
            final_prediction = "REVIEW REQUIRED"
        elif final_score >= 25:
            final_level = "LOW"
            final_prediction = "LIKELY LEGITIMATE"
        else:
            final_level = "MINIMAL"
            final_prediction = "LIKELY LEGITIMATE"

        result["risk_score"] = final_score
        result["risk_level"] = final_level
        result["prediction"] = final_prediction

        result["url_score"] = url_score
        result["url_reasons"] = url_result["reasons"]
        result["url_features"] = url_result["features"]

        if url_score >= 50:
            if "suspicious_url" not in result["categories"]:
                result["categories"].append("suspicious_url")

    return result


if __name__ == "__main__":

    test_url = (
        "http://secure-bank-login-verify.example.com/account/update"
    )

    print("Testing URL detection...")

    result = predict_text(test_url, "url")

    print("\nPrediction:", result["prediction"])
    print("Risk level:", result["risk_level"])
    print("Risk score:", result["risk_score"])
    print("ML probability:", result["ml_probability"])
    print("URL score:", result.get("url_score"))
    print("\nURL reasons:")

    for reason in result.get("url_reasons", []):
        print("-", reason)
