
from pathlib import Path

import pandas as pd
import joblib

# Locate project files
ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "results" / "raw_url_phishing_model.pkl"

print("=" * 60)
print("PHISHING DATASET INSPECTION")
print("=" * 60)

# Load dataset and model
df = pd.read_csv(DATA_PATH, usecols=["URL", "label"])
model = joblib.load(MODEL_PATH)

df = df.dropna(subset=["URL", "label"]).copy()
df["URL"] = df["URL"].astype(str)

# 1. Check labels
print("\n1. LABEL COUNTS")
print(df["label"].value_counts().sort_index())

print("\nExpected mapping: 0 = phishing, 1 = legitimate")

# 2. Inspect examples from each class
for label in [0, 1]:
    print(f"\n2. SAMPLE URLS FOR LABEL {label}")
    samples = df.loc[df["label"] == label, "URL"].head(10)

    for url in samples:
        print("-", url)

# 3. Search for well-known domains in the dataset
for domain in ["google.com", "chatgpt.com", "github.com", "wikipedia.org"]:
    matches = df[
        df["URL"].str.contains(domain, case=False, regex=False)
    ]

    print(f"\n3. DATASET MATCHES: {domain}")
    print("Number of rows:", len(matches))

    if not matches.empty:
        print(matches[["URL", "label"]].head(10).to_string(index=False))
        print("Label distribution:")
        print(matches["label"].value_counts().sort_index())

# 4. Check predictions on actual dataset examples
print("\n4. MODEL CHECK ON DATASET EXAMPLES")

for label in [0, 1]:
    sample_urls = df.loc[df["label"] == label, "URL"].head(5).tolist()

    if not sample_urls:
        continue

    probabilities = model.predict_proba(sample_urls)

    for url, probs in zip(sample_urls, probabilities):
        print(
            f"Actual label={label} | "
            f"Predicted={model.predict([url])[0]} | "
            f"P(phishing)={probs[list(model.classes_).index(0)] * 100:.2f}% | "
            f"URL={url}"
        )

print("\nInspection complete.")
