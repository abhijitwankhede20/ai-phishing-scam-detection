import pandas as pd

# Load PhiUSIIL dataset
file_path = "data/PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(file_path)

print("===================================")
print("       PhiUSIIL Dataset Info")
print("===================================")

print("\nDataset shape:")
print(df.shape)

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nData types:")
print(df.dtypes)

print("\nMissing values:")
print(df.isnull().sum())

print("\nDuplicate rows:")
print(df.duplicated().sum())

print("\nLabel distribution:")
print(df["label"].value_counts())
