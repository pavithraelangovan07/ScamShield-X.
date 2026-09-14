from pathlib import Path
import sys
import re
import numpy as np


# ============================================================
# PROJECT PATH
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.predict import load_model
from src.preprocess import prepare_for_model


# ============================================================
# UNINFORMATIVE FEATURES
# ============================================================

# Common English words that usually do not provide useful
# scam-specific explanatory value.
#
# These are filtered ONLY from the explanation display.
# They do NOT modify the trained model or its prediction.

STOP_FEATURES = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "been",
    "being",
    "but",
    "by",
    "can",
    "could",
    "did",
    "do",
    "does",
    "for",
    "from",
    "had",
    "has",
    "have",
    "he",
    "her",
    "here",
    "hers",
    "him",
    "his",
    "how",
    "i",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "me",
    "my",
    "no",
    "not",
    "of",
    "on",
    "or",
    "our",
    "ours",
    "she",
    "so",
    "than",
    "that",
    "the",
    "their",
    "theirs",
    "them",
    "then",
    "there",
    "these",
    "they",
    "this",
    "those",
    "to",
    "too",
    "us",
    "was",
    "we",
    "were",
    "what",
    "when",
    "where",
    "which",
    "who",
    "why",
    "will",
    "with",
    "would",
    "you",
    "your",
    "yours",
}


# ============================================================
# LOW-INFORMATION FEATURE PATTERNS
# ============================================================

LOW_INFORMATION_PATTERNS = [
    r"^\d+$",
    r"^[^\w]+$",
]


# ============================================================
# FEATURE NAME CLEANING
# ============================================================

def clean_feature_name(feature_name):
    """
    Convert technical scikit-learn feature names into
    human-readable feature names.

    Examples:

        word__prize
            -> prize

        word__claim_your
            -> claim your

        char__urgent
            -> urgent

        channel__sms
            -> channel: sms
    """

    name = str(feature_name)

    # Remove TF-IDF prefixes.
    if name.startswith("word__"):
        name = name[len("word__"):]

    elif name.startswith("char__"):
        name = name[len("char__"):]

    elif name.startswith("channel__"):
        name = "channel: " + name[len("channel__"):]

    elif name.startswith("text__"):
        name = name[len("text__"):]

    # scikit-learn feature names can use underscores
    # to represent word boundaries.
    name = name.replace("_", " ")

    # Normalize whitespace.
    name = " ".join(name.split())

    return name.strip()


# ============================================================
# FEATURE FILTER
# ============================================================

def is_useful_feature(feature_name):
    """
    Determine whether a feature is useful enough to display
    in the Explainable AI section.

    This affects presentation only.
    It does NOT change model prediction.
    """

    feature = clean_feature_name(
        feature_name
    )

    if not feature:
        return False

    normalized = feature.lower().strip()

    # --------------------------------------------------------
    # Remove common stop words when the entire feature
    # consists only of one stop word.
    # --------------------------------------------------------

    if normalized in STOP_FEATURES:
        return False

    # --------------------------------------------------------
    # Remove very short alphabetic tokens.
    # --------------------------------------------------------

    if (
        len(normalized) <= 2
        and normalized.isalpha()
    ):
        return False

    # --------------------------------------------------------
    # Remove purely numeric or punctuation features.
    # --------------------------------------------------------

    for pattern in LOW_INFORMATION_PATTERNS:

        if re.fullmatch(
            pattern,
            normalized
        ):
            return False

    # --------------------------------------------------------
    # For multi-word features, remove them if every word
    # is an uninformative stop word.
    # --------------------------------------------------------

    words = normalized.split()

    if words and all(
        word in STOP_FEATURES
        for word in words
    ):
        return False

    return True


# ============================================================
# CONTRIBUTION STRENGTH
# ============================================================

def contribution_strength(value):
    """
    Convert numerical model contribution into a
    human-readable explanation.
    """

    magnitude = abs(
        float(value)
    )

    if magnitude >= 0.10:
        return "Very strong signal"

    if magnitude >= 0.05:
        return "Strong signal"

    if magnitude >= 0.02:
        return "Moderate signal"

    if magnitude >= 0.01:
        return "Weak signal"

    return "Very weak signal"


# ============================================================
# EXPLAIN PREDICTION
# ============================================================

def explain_prediction(
    text,
    channel,
    top_n=10,
):
    """
    Explain the trained unified ML model prediction.

    The function calculates the contribution of each
    TF-IDF feature using:

        TF-IDF value × Logistic Regression coefficient

    Only useful explanatory features are returned.

    Returns:

        feature
        direction
        contribution
        strength
    """

    # --------------------------------------------------------
    # Load trained unified model
    # --------------------------------------------------------

    model = load_model()

    features = model.named_steps[
        "features"
    ]

    classifier = model.named_steps[
        "classifier"
    ]


    # --------------------------------------------------------
    # Prepare input exactly as the model expects
    # --------------------------------------------------------

    model_text = prepare_for_model(
        text,
        channel
    )


    # --------------------------------------------------------
    # Convert text into TF-IDF features
    # --------------------------------------------------------

    vector = features.transform(
        [model_text]
    )

    names = features.get_feature_names_out()

    values = vector.toarray()[0]


    # --------------------------------------------------------
    # Calculate feature contributions
    # --------------------------------------------------------

    coefficients = classifier.coef_[0]

    contributions = (
        values * coefficients
    )


    # --------------------------------------------------------
    # Find features actually present in the message
    # --------------------------------------------------------

    indices = np.flatnonzero(
        values
    )


    # --------------------------------------------------------
    # Rank features by absolute contribution
    # --------------------------------------------------------

    ranked = sorted(
        indices,
        key=lambda i: abs(
            contributions[i]
        ),
        reverse=True,
    )


    # --------------------------------------------------------
    # Build final explanation
    # --------------------------------------------------------

    output = []


    for i in ranked:

        # Stop after enough useful explanations
        # have been collected.
        if len(output) >= top_n:
            break


        original_name = str(
            names[i]
        )


        # ----------------------------------------------------
        # Filter unhelpful features
        # ----------------------------------------------------

        if not is_useful_feature(
            original_name
        ):
            continue


        contribution = float(
            contributions[i]
        )


        feature = clean_feature_name(
            original_name
        )


        # ----------------------------------------------------
        # Determine model direction
        # ----------------------------------------------------

        if contribution > 0:
            direction = "SCAM"

        else:
            direction = "LEGITIMATE"


        # ----------------------------------------------------
        # Build explanation object
        # ----------------------------------------------------

        output.append(
            {
                "feature": feature,

                "direction": direction,

                "contribution": round(
                    contribution,
                    5
                ),

                "strength": (
                    contribution_strength(
                        contribution
                    )
                ),
            }
        )


    return output