
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "results" / "improved_url_model.pkl"


def extract_parts(url):
    url = str(url).strip()
    candidate = url if "://" in url else "http://" + url

    try:
        parts = urlsplit(candidate)
        hostname = (parts.hostname or "").lower()
        path_query = (parts.path or "/") + (
            "?" + parts.query if parts.query else ""
        )
        return pd.Series({
            "hostname": hostname,
            "path_query": path_query,
        })
    except ValueError:
        return pd.Series({"hostname": "", "path_query": url})


print("Loading dataset...")
df = pd.read_csv(DATA_PATH, usecols=["URL", "label"]).dropna()
df["URL"] = df["URL"].astype(str).str.strip()
df = df[df["URL"] != ""].copy()

df["label"] = pd.to_numeric(df["label"], errors="raise").astype(int)
df = df[df["label"].isin([0, 1])]

# Separate URL components to help the model learn their roles.
parts = df["URL"].apply(extract_parts)
df = pd.concat([df.reset_index(drop=True), parts], axis=1)

X = df[["hostname", "path_query"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

features = ColumnTransformer(
    transformers=[
        (
            "hostname",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=100000,
            ),
            "hostname",
        ),
        (
            "path_query",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=150000,
            ),
            "path_query",
        ),
    ],
)

model = Pipeline([
    ("features", features),
    ("classifier", LogisticRegression(max_iter=1000, random_state=42)),
])

print("Training improved model...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nRandom-split accuracy:", f"{accuracy_score(y_test, predictions) * 100:.2f}%")
print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))
print("\nConfusion matrix (actual rows, predicted columns; labels 0, 1):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

# Evaluate known legitimate websites separately.
legitimate_urls = [
    "https://google.com/",
    "https://wikipedia.org/",
    "https://chatgpt.com/",
    "https://github.com/",
]

test_parts = pd.DataFrame(
    [extract_parts(url).to_dict() for url in legitimate_urls]
)

print("\nKnown-legitimate-domain diagnostic (not a complete security test):")
probabilities = model.predict_proba(test_parts)
for url, probs in zip(legitimate_urls, probabilities):
    phishing_index = list(model.classes_).index(0)
    print(f"{url}: phishing probability = {probs[phishing_index] * 100:.2f}%")

ROOT.joinpath("results").mkdir(parents=True, exist_ok=True)
joblib.dump(model, MODEL_PATH)
print("\nExperimental model saved to:", MODEL_PATH)
print("The existing production model has not been replaced.")
