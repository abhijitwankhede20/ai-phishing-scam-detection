
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"


def get_hostname(url):
    """Extract hostname so URLs from the same host stay in one split."""
    url = str(url).strip()

    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        return (parts.hostname or "").lower()
    except ValueError:
        return ""


# 1. Load data
print("Loading dataset...")
df = pd.read_csv(DATA_PATH, usecols=["URL", "label"]).dropna()
df["URL"] = df["URL"].astype(str).str.strip()
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)

df = df[
    df["URL"].ne("")
    & df["label"].isin([0, 1])
].copy()

df["hostname"] = df["URL"].apply(get_hostname)
df = df[df["hostname"] != ""].reset_index(drop=True)

print("Rows:", len(df))
print("Unique hostnames:", df["hostname"].nunique())
print("Labels:", df["label"].value_counts().sort_index().to_dict())

# 2. Split by hostname, not individual URL
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(df["URL"], df["label"], groups=df["hostname"])
)

train_df = df.iloc[train_idx]
test_df = df.iloc[test_idx]

train_hosts = set(train_df["hostname"])
test_hosts = set(test_df["hostname"])

print("\nTraining rows:", len(train_df))
print("Testing rows:", len(test_df))
print("Training hostnames:", len(train_hosts))
print("Testing hostnames:", len(test_hosts))
print("Hostnames shared between splits:", len(train_hosts & test_hosts))

# 3. Train a fresh baseline model
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=200000,
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            random_state=42,
        ),
    ),
])

print("\nTraining on training hostnames...")
model.fit(train_df["URL"], train_df["label"])

# 4. Evaluate only on held-out hostnames
predictions = model.predict(test_df["URL"])

print("\nDOMAIN-SEPARATED EVALUATION")
print("Accuracy:", f"{accuracy_score(test_df['label'], predictions) * 100:.2f}%")

print("\nClassification report:")
print(classification_report(
    test_df["label"],
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))

print("Confusion matrix (actual rows, predicted columns; labels 0, 1):")
print(confusion_matrix(
    test_df["label"],
    predictions,
    labels=[0, 1],
))

print("\nEvaluation complete. No production model was changed.")



# Save this experimental model separately
MODEL_PATH = ROOT / "results" / "domain_test_model.pkl"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

import joblib
joblib.dump(model, MODEL_PATH)
print("\nExperimental model saved to:", MODEL_PATH)

# Test known legitimate URLs
legitimate_urls = [
    "https://google.com/",
    "https://wikipedia.org/",
    "https://chatgpt.com/",
    "https://github.com/",
]

print("\nKnown-legitimate URL diagnostic:")
probabilities = model.predict_proba(legitimate_urls)
phishing_index = list(model.classes_).index(0)

for url, probs in zip(legitimate_urls, probabilities):
    print(
        f"{url} | "
        f"Phishing probability: {probs[phishing_index] * 100:.2f}%"
    )
