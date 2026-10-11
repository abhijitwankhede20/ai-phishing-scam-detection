from pathlib import Path
import pandas as pd

csv_path = Path("email_detection/data/email_dataset.csv")

print("File exists:", csv_path.exists())
print("File size (MB):", round(csv_path.stat().st_size / (1024 * 1024), 2))

df = pd.read_csv(csv_path, nrows=5, low_memory=False)

print("\nColumns:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.to_string(max_colwidth=100))

print("\nColumn data types:")
print(df.dtypes)

print("\nSample loaded successfully.")
