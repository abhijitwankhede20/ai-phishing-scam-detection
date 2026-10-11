
from pathlib import Path

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# ==========================================
# 1. Set Project Paths
# ==========================================

ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
RESULTS_DIR = ROOT / "results"
MODEL_PATH = RESULTS_DIR / "raw_url_phishing_model.pkl"

print("Dataset path:", DATA_PATH)

if not DATA_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATA_PATH}"
    )

# ==========================================
# 2. Load Dataset
# ==========================================

df = pd.read_csv(DATA_PATH)

print("\nDataset loaded successfully.")
print("Dataset shape:", df.shape)

# Check required columns
required_columns = {"URL", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        f"Dataset must contain columns: {required_columns}"
    )

# Keep only the columns used by this model
df = df[["URL", "label"]].dropna().copy()

df["URL"] = df["URL"].astype(str).str.strip()
df = df[df["URL"] != ""]
df["label"] = pd.to_numeric(
    df["label"], errors="raise"
).astype(int)

if set(df["label"].unique()) != {0, 1}:
    raise ValueError(
        f"Expected labels 0 and 1; found "
        f"{sorted(df['label'].unique())}"
    )

X = df["URL"]
y = df["label"]

print("\nLabel meaning:")
print("0 = Phishing")
print("1 = Legitimate")
print("\nLabel counts:")
print(y.value_counts().sort_index())

# ==========================================
# 3. Split Dataset
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# ==========================================
# 4. Create Model Pipeline
# ==========================================

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

# ==========================================
# 5. Train Model
# ==========================================

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training completed.")

# ==========================================
# 6. Make Predictions
# ==========================================

y_pred = model.predict(X_test)

# ==========================================
# 7. Evaluate Model
# ==========================================

accuracy = accuracy_score(y_test, y_pred)

print("\n===================================")
print("        MODEL EVALUATION")
print("===================================")

print("\nAccuracy:", f"{accuracy * 100:.2f}%")

print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))

print("\nConfusion Matrix")
print("(Rows = actual, columns = predicted; labels 0, 1):")
print(confusion_matrix(
    y_test,
    y_pred,
    labels=[0, 1],
))

# ==========================================
# 8. Save Model to Main Results Folder
# ==========================================

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully:")
print(MODEL_PATH)
print("\nModel classes:", model.classes_)
