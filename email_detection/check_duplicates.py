import pandas as pd

path = "email_detection/data/email_dataset.csv"
df = pd.read_csv(path, usecols=["body", "label"])

df = df.dropna(subset=["body"]).copy()
df["body"] = df["body"].astype(str).str.strip()
df = df[df["body"] != ""]

print("Rows with usable email text:", len(df))

# Count texts that appear under more than one label
label_counts = df.groupby("body")["label"].nunique()
conflicting = label_counts[label_counts > 1]

print("Unique email texts:", df["body"].nunique())
print("Texts with conflicting labels:", len(conflicting))

# Count duplicate texts regardless of label
print("Repeated email-text rows:", df.duplicated(subset=["body"], keep="first").sum())

print("\nLabel distribution after removing empty text:")
print(df["label"].value_counts().sort_index())
