
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"


def split_url(url):
    url = str(url).strip()
    parts = urlsplit(url if "://" in url else "//" + url)
    hostname = (parts.hostname or "").lower()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    normalized = urlunsplit(
        ("", hostname, parts.path or "/", parts.query, "")
    )
    return hostname, normalized


print("Loading dataset...")
df = pd.read_csv(DATA_PATH, usecols=["URL", "label"]).dropna()
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)
df = df[df["label"].isin([0, 1])].copy()

parts = df["URL"].apply(split_url)
df["hostname"] = parts.apply(lambda x: x[0])
df["normalized_url"] = parts.apply(lambda x: x[1])
df = df[df["hostname"] != ""].reset_index(drop=True)

X = df["normalized_url"]
y = df["label"]
groups = df["hostname"]

splitter = GroupShuffleSplit(
    n_splits=1, test_size=0.20, random_state=42
)
train_idx, test_idx = next(splitter.split(X, y, groups=groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

print("Shared hostnames:", len(
    set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])
))

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        max_features=200000,
    )),
    ("classifier", LogisticRegression(max_iter=1000, random_state=42)),
])

print("Training normalized model on training hostnames...")
model.fit(X_train, y_train)
predictions = model.predict(X_test)

print("\nUnseen-hostname accuracy:",
      f"{accuracy_score(y_test, predictions) * 100:.2f}%")
print("\nClassification report:")
print(classification_report(
    y_test, predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))
print("Confusion matrix (actual rows, predicted columns):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print("\nKnown-legitimate URL diagnostic:")
for url in [
    "https://google.com/",
    "https://wikipedia.org/",
    "https://chatgpt.com/",
    "https://github.com/",
]:
    _, normalized = split_url(url)
    probabilities = model.predict_proba([normalized])[0]
    index = list(model.classes_).index(0)
    print(f"{url}: {probabilities[index] * 100:.2f}% phishing")

print("\nNo production model was changed.")
