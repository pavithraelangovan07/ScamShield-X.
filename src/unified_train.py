import json
import os
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.preprocess import prepare_for_model

DATASETS = {
    "sms": ROOT / "data" / "sms.csv",
    "email": ROOT / "data" / "email.csv",
    "job": ROOT / "data" / "jobs.csv",
    "url": ROOT / "data" / "urls.csv",
    "instagram": ROOT / "data" / "instagram.csv",
}


def load_data():
    frames = []
    for channel, path in DATASETS.items():
        if not path.exists():
            print(f"WARNING: missing {path}")
            continue
        df = pd.read_csv(path)
        required = {"text", "label"}
        if not required.issubset(df.columns):
            raise ValueError(f"{path} must contain columns: text,label")
        df = df[["text", "label"]].copy()
        df["text"] = df["text"].fillna("").astype(str)
        df["label"] = df["label"].astype(str).str.strip().str.lower().map({"legit": 0, "legitimate": 0, "scam": 1})
        df = df.dropna(subset=["label"])
        df["channel"] = channel
        df["model_text"] = [prepare_for_model(t, channel) for t in df["text"]]
        frames.append(df)
    if not frames:
        raise RuntimeError("No datasets found.")
    result = pd.concat(frames, ignore_index=True)
    if result["label"].nunique() < 2:
        raise RuntimeError("Training data must contain both scam and legitimate labels.")
    return result


def build_model():
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, max_features=30000)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, sublinear_tf=True, max_features=30000)),
    ])
    classifier = LogisticRegression(class_weight="balanced", max_iter=3000, random_state=42)
    return Pipeline([("features", features), ("classifier", classifier)])


def main():
    data = load_data()
    print(f"Total samples: {len(data)}")
    print("Labels:\n", data["label"].value_counts().sort_index())
    print("Channels:\n", data["channel"].value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        data["model_text"], data["label"], test_size=0.25, random_state=42, stratify=data["label"]
    )

    model = build_model()
    print("\nTraining unified TF-IDF (word + character) + Logistic Regression model...")
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]
    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "test_size": int(len(y_test)),
    }

    print("\n=== OVERALL TEST RESULTS ===")
    for k in ["accuracy", "precision", "recall", "f1"]:
        print(f"{k.capitalize()}: {metrics[k]:.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, pred, target_names=["Legitimate", "Scam"], zero_division=0))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, pred))

    # Channel-wise evaluation is diagnostic only; with tiny demo data it is not statistically meaningful.
    print("\n=== CHANNEL-WISE TEST RESULTS ===")
    channel_results = {}
    test_df = data.loc[X_test.index].copy()
    test_df["prediction"] = pred
    for channel, group in test_df.groupby("channel"):
        if len(group) == 0:
            continue
        channel_results[channel] = {
            "samples": int(len(group)),
            "accuracy": accuracy_score(group["label"], group["prediction"]),
            "f1": f1_score(group["label"], group["prediction"], zero_division=0),
        }
        print(f"{channel}: n={len(group)}, accuracy={channel_results[channel]['accuracy']:.4f}, f1={channel_results[channel]['f1']:.4f}")

    models_dir = ROOT / "models"
    models_dir.mkdir(exist_ok=True)
    joblib.dump(model, models_dir / "unified_model.joblib")
    metrics["channel_results"] = channel_results
    with open(models_dir / "training_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved: {models_dir / 'unified_model.joblib'}")
    print(f"Saved: {models_dir / 'training_metrics.json'}")


if __name__ == "__main__":
    main()
