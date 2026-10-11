from pathlib import Path
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "email_dataset.csv"
MODEL_PATH = ROOT / "models" / "email_text_model.joblib"

print("Loading email dataset...")
df = pd.read_csv(DATA_PATH, usecols=["body", "label"])

df = df.dropna(subset=["body", "label"]).copy()
df["body"] = df["body"].astype(str).str.strip()
df = df[df["body"] != ""]

df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"])
df = df[df["label"].isin([0, 1])]
df["label"] = df["label"].astype(int)

# Remove exact duplicate email bodies before splitting.
df = df.drop_duplicates(subset=["body"], keep="first")

X = df["body"]
y = df["label"]

print("\nDataset after cleaning:")
print("Total unique emails:", len(df))
print(y.value_counts().sort_index())

if y.nunique() != 2:
    raise ValueError("Expected exactly two classes: 0 and 1.")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=(1, 2),
        min_df=2,
        max_features=150000,
        sublinear_tf=True,
        dtype=float,
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )),
])

print("\nTraining TF-IDF + Logistic Regression...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n--- Test results ---")
print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Safe (0)", "Phishing/Scam (1)"],
    digits=4,
    zero_division=0,
))

print("Confusion matrix (rows=actual, columns=predicted):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(model, MODEL_PATH)

print("\nModel saved to:", MODEL_PATH)
print("Label mapping: 0 = Safe; 1 = Phishing/Scam")
