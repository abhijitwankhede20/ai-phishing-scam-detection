import joblib
import pandas as pd
from scipy.io import arff

# Load saved model
model = joblib.load("results/random_forest_phishing_model.pkl")

# Load feature names
feature_names = joblib.load("results/website_feature_names.pkl")

# Load dataset
file_path = "data/Training Dataset.arff"
data, metadata = arff.loadarff(file_path)
df = pd.DataFrame(data)

# Convert byte values into strings
for column in df.columns:
    df[column] = df[column].str.decode("utf-8")

# Convert columns to integers
df = df.astype(int)

# Remove exact duplicate rows
df_unique = df.drop_duplicates()

# Remove conflicting feature patterns
feature_columns = df_unique.columns[:-1]

conflicting_patterns = (
    df_unique.groupby(list(feature_columns))["Result"]
    .nunique()
)

conflicting_patterns = conflicting_patterns[
    conflicting_patterns > 1
]

conflicting_rows = (
    df_unique.groupby(list(feature_columns))
    ["Result"]
    .transform("nunique") > 1
)

df_clean = df_unique[~conflicting_rows].copy()

# Select features
X = df_clean[feature_names]
y = df_clean["Result"]

# Take one real sample
sample = X.iloc[[0]]

# Predict
prediction = model.predict(sample)
probability = model.predict_proba(sample)

print("Model loaded successfully.")
print("\nPrediction:")

if prediction[0] == -1:
    print("Result: PHISHING")
else:
    print("Result: LEGITIMATE")

print("\nPrediction probabilities:")
print("Phishing:", probability[0][0])
print("Legitimate:", probability[0][1])