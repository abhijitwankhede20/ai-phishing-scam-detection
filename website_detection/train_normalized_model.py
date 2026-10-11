
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report


ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "results" / "normalized_url_model.pkl"


def normalize_for_training(url):
    url = str(url).strip()

    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        hostname = (parts.hostname or "").lower()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        path = parts.path or "/"
        query = parts.query

        # Remove protocol and common www prefix from model input.
        return urlunsplit(("", hostname, path, query, ""))
    except ValueError:
        return url.lower()


print("Loading dataset...")
df = pd.read_csv(DATA_PATH, usecols=["URL", "label"]).dropna()
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)
df = df[df["label"].isin([0, 1])].copy()

df["normalized_url"] = df["URL"].apply(normalize_for_training)
df = df[df["normalized_url"] != ""]

X = df["normalized_url"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

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
    ("classifier", LogisticRegression(max_iter=1000, random_state=42)),
])

print("Training normalized URL model...")
model.fit(X_train, y_train)
predictions = model.predict(X_test)

print("\nRandom-split accuracy:",
      f"{accuracy_score(y_test, predictions) * 100:.2f}%")
print(classification_report(
    y_test, predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))

test_urls = [
    "https://google.com/",
    "https://wikipedia.org/",
    "https://chatgpt.com/",
    "https://github.com/",
]

print("\nKnown-legitimate URL diagnostic:")
for url in test_urls:
    normalized = normalize_for_training(url)
    probabilities = model.predict_proba([normalized])[0]
    phishing_index = list(model.classes_).index(0)
    print(f"{url}: {probabilities[phishing_index] * 100:.2f}% phishing probability")

MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(model, MODEL_PATH)
print("\nExperimental model saved to:", MODEL_PATH)
