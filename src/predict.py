from pathlib import Path
import joblib

from src.preprocess import prepare_for_model
from src.scam_rules import detect_scam_indicators

try:
    from src.url_features import extract_url_features, explain_url
except ImportError:
    extract_url_features = None
    explain_url = None


MODEL_PATH = Path("models/unified_model.joblib")

_model = None


def load_model():
    global _model

    if _model is None:

        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                "Model not found.\n"
                "Run this command first:\n"
                "python src\\unified_train.py"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


def calculate_risk(ml_probability, rule_score, categories):
    """
    Combines ML probability with transparent scam evidence.
    """

    ml_score = ml_probability * 100

    # ML has the main contribution.
    score = (ml_score * 0.70) + (rule_score * 0.30)

    # Multiple independent scam indicators
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

    # Strong rule evidence prevents an obvious scam
    # from being incorrectly shown as only MEDIUM.
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

        "ml_probability": round(
            ml_probability * 100,
            2
        ),

        "rule_score": rule_result["score"],

        "rule_evidence": rule_result["findings"],

        "categories": rule_result["categories"],

        "channel": channel,

        "text": text
    }

    # URL-specific analysis
    if channel == "url" and extract_url_features:

        try:
            features = extract_url_features(text)

            result["url_features"] = features

            if explain_url:
                result["url_reasons"] = explain_url(
                    text,
                    features
                )

        except Exception as exc:
            result["url_error"] = str(exc)

    return result


if __name__ == "__main__":

    print("=" * 70)
    print("ScamShield-X Detection Test")
    print("=" * 70)

    test_cases = [

        (
            "Congratulations! You won ₹50000. "
            "Pay ₹99 immediately to claim your prize. "
            "Click the link in bio.",
            "instagram"
        ),

        (
            "URGENT! Your bank account will be blocked. "
            "Send your OTP immediately to verify your account.",
            "sms"
        ),

        (
            "You have been selected for a work from home job. "
            "Earn ₹50000 per month. Pay ₹500 registration fee.",
            "job"
        ),

        (
            "Your order has been shipped and will arrive tomorrow.",
            "sms"
        )
    ]

    for text, channel in test_cases:

        try:

            result = predict_text(
                text,
                channel
            )

            print("\n" + "-" * 70)

            print("INPUT:")
            print(text)

            print("\nCHANNEL:")
            print(channel)

            print("\nPREDICTION:")
            print(result["prediction"])

            print("\nRISK LEVEL:")
            print(result["risk_level"])

            print("\nRISK SCORE:")
            print(result["risk_score"])

            print("\nML PROBABILITY:")
            print(
                str(result["ml_probability"]) + "%"
            )

            print("\nRULE SCORE:")
            print(result["rule_score"])

            print("\nDETECTED EVIDENCE:")

            if result["rule_evidence"]:

                for evidence in result["rule_evidence"]:

                    print(
                        "  ✓ "
                        + evidence["reason"]
                        + " | matched: "
                        + evidence["matched"]
                    )

            else:
                print("  No strong rule-based indicators.")

        except Exception as exc:

            print("\nERROR:")
            print(exc)