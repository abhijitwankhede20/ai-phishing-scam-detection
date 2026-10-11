from pathlib import Path
import pandas as pd

path = Path("email_detection/data/email_dataset.csv")

print("Loading dataset metadata and labels...")
df = pd.read_csv(path, usecols=["body", "label"])

print("\n--- Dataset shape ---")
print("Rows:", len(df))
print("Columns:", df.columns.tolist())

print("\n--- Label distribution ---")
print(df["label"].value_counts(dropna=False).sort_index())

print("\n--- Label percentages ---")
print((df["label"].value_counts(normalize=True, dropna=False) * 100).round(2))

print("\n--- Missing values ---")
print(df.isna().sum())

print("\n--- Duplicate rows ---")
print("Exact duplicate rows:", df.duplicated().sum())

print("\n--- Unique labels ---")
print(sorted(df["label"].dropna().unique().tolist()))

print("\n--- Sample text for each label ---")
for label in sorted(df["label"].dropna().unique()):
    sample = df.loc[df["label"] == label, "body"].dropna()
    if not sample.empty:
        print(f"\nLabel {label}:")
        print(str(sample.iloc[0])[:700].replace("\n", " "))

print("\nAnalysis complete.")
