import os
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from src.ai_detector import analyze_with_ai
from src.multilingual import detect_language, find_multilingual_keywords
from src.ocr import extract_multilingual_text
from src.qr_scanner import scan_qr_code
from src.reel_analyzer import analyze_reel


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parent

UPLOAD_FOLDER = ROOT / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024


# ============================================================
# ALLOWED FILES / CHANNELS
# ============================================================

ALLOWED_IMAGES = {
    "png",
    "jpg",
    "jpeg",
    "webp",
}

ALLOWED_VIDEOS = {
    "mp4",
    "mov",
    "avi",
    "mkv",
}

ALLOWED_CHANNELS = {
    "sms",
    "email",
    "job",
    "url",
    "instagram",
}


# ============================================================
# OPTIONAL ML EXPLANATION
# ============================================================

def get_ml_explanation(text, channel):
    """
    Try to obtain feature-level explanation from the trained
    unified ML model.

    If the model has not been trained yet, return an empty list
    so the application can use the AI/local evidence explanation.
    """

    try:

        from src.explain import explain_prediction

        explanation = explain_prediction(
            text,
            channel,
            top_n=8,
        )

        return explanation or []

    except Exception as exc:

        print(
            "[ScamShield-X] ML explanation unavailable: "
            f"{type(exc).__name__}: {exc}"
        )

        return []


# ============================================================
# FALLBACK XAI EXPLANATION
# ============================================================

def build_fallback_xai(result, text):
    """
    Build an explainable evidence list when the trained
    unified ML model is unavailable.

    This prevents the ML explanation panel from being empty
    when the OpenAI API is unavailable.
    """

    xai = []

    red_flags = result.get(
        "red_flags",
        [],
    )

    scam_types = result.get(
        "scam_type",
        [],
    )

    evidence = result.get(
        "evidence",
        [],
    )

    reasons = result.get(
        "reasons",
        [],
    )


    # --------------------------------------------------------
    # Red flags
    # --------------------------------------------------------

    for flag in red_flags[:5]:

        xai.append(
            {
                "feature": flag,
                "direction": "SCAM",
                "contribution": "evidence signal",
            }
        )


    # --------------------------------------------------------
    # Scam categories
    # --------------------------------------------------------

    for scam_type in scam_types[:4]:

        readable = str(
            scam_type
        ).replace(
            "_",
            " ",
        )

        xai.append(
            {
                "feature": readable.title(),
                "direction": "SCAM",
                "contribution": "detected scam category",
            }
        )


    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    existing_features = {
        str(item.get("feature", "")).lower()
        for item in xai
        if isinstance(item, dict)
    }

    for item in (evidence or reasons)[:5]:

        short_item = str(item)

        if short_item.lower() in existing_features:
            continue

        xai.append(
            {
                "feature": short_item,
                "direction": (
                    "SCAM"
                    if result.get("prediction") == "SCAM"
                    else "SIGNAL"
                ),
                "contribution": "rule/evidence signal",
            }
        )


    # --------------------------------------------------------
    # Legitimate case
    # --------------------------------------------------------

    if not xai:

        if result.get("prediction") == "LEGITIMATE":

            xai.append(
                {
                    "feature": "No strong scam-associated features",
                    "direction": "LEGITIMATE",
                    "contribution": "no detected risk signal",
                }
            )

        else:

            xai.append(
                {
                    "feature": "Risk indicators detected",
                    "direction": "SUSPICIOUS",
                    "contribution": "combined evidence",
                }
            )


    return xai[:10]


# ============================================================
# RECOMMENDATION
# ============================================================

def make_recommendation(risk_score, prediction):

    risk_score = float(
        risk_score or 0
    )

    if prediction == "SCAM" or risk_score >= 70:

        return (
            "High risk. Do not click links, send money, "
            "share OTPs/passwords, or provide bank details. "
            "Verify the sender through an independent official source."
        )

    if prediction == "SUSPICIOUS" or risk_score >= 40:

        return (
            "Suspicious content detected. Do not act on the "
            "message yet. Verify the sender, domain, offer, "
            "and payment request independently."
        )

    return (
        "No strong scam indicators were detected. This is "
        "not proof of safety. Continue using normal security "
        "precautions and verify unexpected requests."
    )


# ============================================================
# ENRICH RESULT
# ============================================================

def enrich_result(
    result,
    original_text,
    channel,
):

    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    result["channel"] = channel


    # --------------------------------------------------------
    # Language
    # --------------------------------------------------------

    try:

        language = detect_language(
            original_text
        )

        result["language"] = language.get(
            "name",
            "Unknown",
        )

        result["language_code"] = language.get(
            "code",
            "unknown",
        )

    except Exception:

        result["language"] = "Unknown"
        result["language_code"] = "unknown"


    # --------------------------------------------------------
    # Multilingual keywords
    # --------------------------------------------------------

    try:

        result["multilingual_keywords"] = (
            find_multilingual_keywords(
                original_text
            )
        )

    except Exception:

        result["multilingual_keywords"] = []


    # --------------------------------------------------------
    # ML / XAI explanation
    # --------------------------------------------------------

    ml_xai = get_ml_explanation(
        original_text,
        channel,
    )


    if ml_xai:

        result["xai"] = ml_xai

        result["xai_source"] = (
            "trained_unified_ml_model"
        )

    else:

        result["xai"] = build_fallback_xai(
            result,
            original_text,
        )

        result["xai_source"] = (
            "evidence_based_explanation"
        )


    # --------------------------------------------------------
    # Safety recommendation
    # --------------------------------------------------------

    result["recommendation"] = (
        make_recommendation(
            result.get("risk_score", 0),
            result.get("prediction", ""),
        )
    )


    # --------------------------------------------------------
    # Ensure confidence exists
    # --------------------------------------------------------

    if "confidence" not in result:

        result["confidence"] = 0.0


    # --------------------------------------------------------
    # Ensure scam type exists
    # --------------------------------------------------------

    if "scam_type" not in result:

        result["scam_type"] = []


    # --------------------------------------------------------
    # Ensure reasons exist
    # --------------------------------------------------------

    if not result.get("reasons"):

        result["reasons"] = [
            "No strong scam indicators were detected "
            "in the supplied content."
        ]


    return result


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify(
        {
            "status": "ok",
            "ai_engine": "OpenAI + local fallback",
            "xai": "ML feature explanation + evidence fallback",
        }
    )


# ============================================================
# TEXT ANALYSIS
# ============================================================

@app.route(
    "/analyze",
    methods=["POST"],
)
@app.route(
    "/api/analyze",
    methods=["POST"],
)
def analyze_text():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    text = str(
        data.get(
            "text",
            "",
        )
    ).strip()

    channel = str(
        data.get(
            "channel",
            "sms",
        )
    ).lower().strip()


    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not text:

        return jsonify(
            {
                "error": (
                    "Please enter text to analyze."
                )
            }
        ), 400


    if channel not in ALLOWED_CHANNELS:

        return jsonify(
            {
                "error": (
                    f"Unsupported channel: {channel}"
                )
            }
        ), 400


    # --------------------------------------------------------
    # AI ANALYSIS
    # --------------------------------------------------------

    try:

        result = analyze_with_ai(
            content=text,
            channel=channel,
        )

        result = enrich_result(
            result,
            text,
            channel,
        )

        return jsonify(
            result
        )


    except Exception as exc:

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500


# ============================================================
# IMAGE + OCR + QR ANALYSIS
# ============================================================

@app.route(
    "/analyze-image",
    methods=["POST"],
)
def analyze_image():

    image = request.files.get(
        "image"
    )


    if image is None or image.filename == "":

        return jsonify(
            {
                "error": (
                    "Please select an image."
                )
            }
        ), 400


    filename_lower = (
        image.filename.lower()
    )

    if not allowed_file(
        filename_lower,
        ALLOWED_IMAGES,
    ):

        return jsonify(
            {
                "error": (
                    "Allowed image types: "
                    "PNG, JPG, JPEG, WEBP."
                )
            }
        ), 400


    suffix = Path(
        secure_filename(
            image.filename
        )
    ).suffix.lower()


    filename = (
        f"{uuid.uuid4().hex}{suffix}"
    )

    image_path = (
        UPLOAD_FOLDER / filename
    )


    try:

        image.save(
            image_path
        )


        # ----------------------------------------------------
        # OCR
        # ----------------------------------------------------

        ocr = extract_multilingual_text(
            image_path
        )


        # ----------------------------------------------------
        # QR
        # ----------------------------------------------------

        qr = scan_qr_code(
            image_path
        )


        evidence_parts = []


        if ocr.get("text"):

            evidence_parts.append(
                "Image OCR: "
                + ocr["text"]
            )


        for value in qr.get(
            "data",
            [],
        ):

            evidence_parts.append(
                "QR content: "
                + value
            )


        combined = "\n".join(
            evidence_parts
        )


        if not combined.strip():

            return jsonify(
                {
                    "error": (
                        "No readable text or QR "
                        "content was detected in "
                        "the image."
                    )
                }
            ), 400


        # ----------------------------------------------------
        # Analyze extracted content
        # ----------------------------------------------------

        analysis_channel = (
            "url"
            if qr.get("data")
            else "sms"
        )


        result = analyze_with_ai(
            content=combined,
            channel=analysis_channel,
        )


        result = enrich_result(
            result,
            combined,
            "image",
        )


        result.update(
            {
                "channel": "image",
                "ocr_text": ocr.get(
                    "text",
                    "",
                ),
                "ocr_language": ocr.get(
                    "ocr_language",
                    "unknown",
                ),
                "qr_data": qr.get(
                    "data",
                    [],
                ),
                "combined_text": combined,
            }
        )


        return jsonify(
            result
        )


    except Exception as exc:

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500


    finally:

        if image_path.exists():

            image_path.unlink()


# ============================================================
# INSTAGRAM REEL ANALYSIS
# ============================================================

@app.route(
    "/analyze-reel",
    methods=["POST"],
)
def analyze_instagram_reel():

    video = request.files.get(
        "video"
    )

    caption = str(
        request.form.get(
            "caption",
            "",
        )
    ).strip()


    if video is None or video.filename == "":

        return jsonify(
            {
                "error": (
                    "Please upload an Instagram "
                    "Reel video."
                )
            }
        ), 400


    filename_lower = (
        video.filename.lower()
    )

    if not allowed_file(
        filename_lower,
        ALLOWED_VIDEOS,
    ):

        return jsonify(
            {
                "error": (
                    "Allowed video types: "
                    "MP4, MOV, AVI, MKV."
                )
            }
        ), 400


    suffix = Path(
        secure_filename(
            video.filename
        )
    ).suffix.lower()


    filename = (
        f"{uuid.uuid4().hex}{suffix}"
    )

    video_path = (
        UPLOAD_FOLDER / filename
    )


    try:

        video.save(
            video_path
        )


        # ----------------------------------------------------
        # Reel extraction
        # ----------------------------------------------------

        reel = analyze_reel(
            video_path,
            caption,
        )


        combined = reel.get(
            "combined_text",
            "",
        )


        if not combined.strip():

            return jsonify(
                {
                    "error": (
                        "No caption, speech, or "
                        "visible text could be "
                        "extracted from this Reel."
                    )
                }
            ), 400


        # ----------------------------------------------------
        # AI analysis
        # ----------------------------------------------------

        result = analyze_with_ai(
            content=combined,
            channel="instagram",
        )


        result = enrich_result(
            result,
            combined,
            "instagram",
        )


        result.update(
            {
                "channel": "instagram",

                "caption": reel.get(
                    "caption",
                    caption,
                ),

                "transcript": reel.get(
                    "transcript",
                    "",
                ),

                "ocr_text": reel.get(
                    "ocr_text",
                    "",
                ),

                "combined_text": combined,
            }
        )


        return jsonify(
            result
        )


    except Exception as exc:

        return jsonify(
            {
                "error": str(exc)
            }
        ), 500


    finally:

        if video_path.exists():

            video_path.unlink()


# ============================================================
# FILE VALIDATION
# ============================================================

def allowed_file(
    filename,
    allowed_extensions,
):

    return (
        "."
        in filename
        and filename.rsplit(
            ".",
            1,
        )[1].lower()
        in allowed_extensions
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
    