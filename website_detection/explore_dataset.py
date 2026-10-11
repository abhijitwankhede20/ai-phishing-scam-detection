import pandas as pd
from scipy.io import arff

# Path to our dataset
file_path = "data/Training Dataset.arff"

# Load the ARFF file
data, metadata = arff.loadarff(file_path)

# Convert the data into a Pandas DataFrame
df = pd.DataFrame(data)

# Convert byte values into strings
for column in df.columns:
    df[column] = df[column].str.decode("utf-8")

# Convert all columns to numeric values
df = df.astype(int)

# Display basic information
print("Number of rows:", df.shape[0])
print("Number of columns:", df.shape[1])

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nDataset information:")
print(df.info())

print("\nMissing values:")
print(df.isnull().sum())

print("\nDuplicate rows:", df.duplicated().sum())

print("\nResult values:")
print(df["Result"].value_counts())


# Check duplicate rows with their labels
duplicates = df[df.duplicated(keep=False)]

print("\nTotal rows involved in duplicates:", len(duplicates))

print("\nResult distribution among duplicate rows:")
print(duplicates["Result"].value_counts())

print("\nDuplicate rows with conflicting results:")
conflicting = (
    duplicates.groupby(list(df.columns[:-1]))["Result"]
    .nunique()
)

print("Number of feature patterns with different labels:", 
      (conflicting > 1).sum())

# Check conflicting feature patterns
feature_columns = df.columns[:-1]

conflicting_patterns = (
    df.groupby(list(feature_columns))["Result"]
    .nunique()
)

conflicting_patterns = conflicting_patterns[
    conflicting_patterns > 1
]

print("\nNumber of conflicting feature patterns:",
      len(conflicting_patterns))

print("\nRows belonging to conflicting patterns:")

conflicting_rows = (
    df.groupby(list(feature_columns))["Result"]
    .transform("nunique") > 1
)

print(conflicting_rows.sum())

# Remove exact duplicate rows temporarily for analysis
df_unique = df.drop_duplicates()

print("\nRows after removing exact duplicates:", len(df_unique))

print("\nDuplicates removed:", len(df) - len(df_unique))

print("\nClass distribution after removing duplicates:")
print(df_unique["Result"].value_counts())

# Check conflicting labels after removing exact duplicates

conflicts_after_dedup = (
    df_unique.groupby(list(feature_columns))["Result"]
    .nunique()
)

conflicts_after_dedup = conflicts_after_dedup[
    conflicts_after_dedup > 1
]

print("\nConflicting feature patterns after deduplication:",
      len(conflicts_after_dedup))

conflicting_rows_after_dedup = (
    df_unique.groupby(list(feature_columns))["Result"]
    .transform("nunique") > 1
)

print("Rows belonging to conflicting patterns after deduplication:",
      conflicting_rows_after_dedup.sum())

# Remove rows with conflicting feature patterns

df_clean = df_unique[~conflicting_rows_after_dedup].copy()

print("\nFinal cleaned dataset shape:", df_clean.shape)

print("\nFinal class distribution:")
print(df_clean["Result"].value_counts())

print("\nRemaining duplicates:", df_clean.duplicated().sum())

# Separate features and target

X = df_clean.drop("Result", axis=1)
y = df_clean["Result"]

print("\nFeature matrix shape:", X.shape)
print("Target shape:", y.shape)

print("\nFeature columns:")
print(X.columns.tolist())

print("\nTarget values:")
print(y.value_counts())


from sklearn.model_selection import train_test_split

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining data shape:", X_train.shape)
print("Testing data shape:", X_test.shape)

print("\nTraining target distribution:")
print(y_train.value_counts())

print("\nTesting target distribution:")
print(y_test.value_counts())

from sklearn.linear_model import LogisticRegression

# Create the model
model = LogisticRegression(max_iter=1000)

# Train the model
model.fit(X_train, y_train)

# Make predictions on the test data
y_pred = model.predict(X_test)

print("\nFirst 10 predictions:")
print(y_pred[:10])

print("\nFirst 10 actual values:")
print(y_test.iloc[:10].values)

print("\nLogistic Regression model trained successfully.")


from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

# Detailed evaluation
print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Phishing", "Legitimate"]
))

# Confusion matrix
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


from sklearn.ensemble import RandomForestClassifier

# Create Random Forest model
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Train the model
rf_model.fit(X_train, y_train)

print("\nRandom Forest model trained successfully.")

rf_pred = rf_model.predict(X_test)

print("\nFirst 10 Random Forest predictions:")
print(rf_pred[:10])

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

rf_accuracy = accuracy_score(y_test, rf_pred)

print("\nRandom Forest Accuracy:", rf_accuracy)

print("\nRandom Forest Classification Report:")
print(classification_report(
    y_test,
    rf_pred,
    target_names=["Phishing", "Legitimate"]
))

print("\nRandom Forest Confusion Matrix:")
print(confusion_matrix(y_test, rf_pred))

# Get feature importance from Random Forest
feature_importance = pd.Series(
    rf_model.feature_importances_,
    index=X.columns
)

# Sort features from most important to least important
feature_importance = feature_importance.sort_values(ascending=False)

print("\nRandom Forest Feature Importance:")
print(feature_importance)


import matplotlib.pyplot as plt

# Select top 10 features
top_features = feature_importance.head(10)

# Create bar chart
plt.figure(figsize=(10, 6))
top_features.sort_values().plot(kind="barh")

plt.title("Top 10 Random Forest Feature Importances")
plt.xlabel("Importance")
plt.ylabel("Feature")

plt.tight_layout()
plt.show()

from xgboost import XGBClassifier

# Convert labels for XGBoost
# Original: -1 = Phishing, 1 = Legitimate
# XGBoost:  0 = Phishing, 1 = Legitimate

y_train_xgb = y_train.map({-1: 0, 1: 1})
y_test_xgb = y_test.map({-1: 0, 1: 1})


# Create XGBoost model
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    random_state=42,
    eval_metric="logloss"
)

# Train the model
xgb_model.fit(X_train, y_train_xgb)

print("\nXGBoost model trained successfully.")

# Make predictions
xgb_pred = xgb_model.predict(X_test)

# Convert XGBoost labels back to original dataset labels
# 0 = Phishing → -1
# 1 = Legitimate → 1

xgb_pred = pd.Series(xgb_pred).map({0: -1, 1: 1}).values

print("\nFirst 10 XGBoost predictions:")
print(xgb_pred[:10])

print("\nFirst 10 actual values:")
print(y_test.iloc[:10].values)

xgb_accuracy = accuracy_score(y_test, xgb_pred)

print("\nXGBoost Accuracy:", xgb_accuracy)

print("\nXGBoost Classification Report:")
print(classification_report(
    y_test,
    xgb_pred,
    target_names=["Phishing", "Legitimate"]
))

print("\nXGBoost Confusion Matrix:")
print(confusion_matrix(y_test, xgb_pred))



from sklearn.metrics import roc_auc_score, roc_curve

# Get probability of Phishing
# Random Forest classes: [-1, 1]
# Column 0 = Phishing (-1)

rf_phishing_probability = rf_model.predict_proba(X_test)[:, 0]

# Convert actual labels:
# Phishing (-1) -> 1
# Legitimate (1) -> 0

y_test_phishing = y_test.map({-1: 1, 1: 0})

# Calculate ROC-AUC for Phishing detection
rf_auc = roc_auc_score(
    y_test_phishing,
    rf_phishing_probability
)

print("\nRandom Forest Phishing ROC-AUC:", rf_auc)


# Calculate ROC curve
fpr, tpr, thresholds = roc_curve(
    y_test_phishing,
    rf_phishing_probability
)

# Plot ROC curve
plt.figure(figsize=(8, 6))

plt.plot(
    fpr,
    tpr,
    label=f"Random Forest (AUC = {rf_auc:.4f})"
)

# Random guessing line
plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    label="Random Guessing"
)

plt.title("Random Forest ROC Curve")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.legend()
plt.grid()

plt.tight_layout()
plt.show()


from sklearn.model_selection import cross_val_score

# 5-fold cross-validation
cv_scores = cross_val_score(
    rf_model,
    X,
    y,
    cv=5,
    scoring="accuracy"
)

print("\nRandom Forest 5-Fold Cross-Validation:")
print("Fold accuracies:", cv_scores)
print("Mean accuracy:", cv_scores.mean())
print("Standard deviation:", cv_scores.std())


# --------------------------------------------------
# 5-Fold Cross-Validation for All Models
# --------------------------------------------------

# Logistic Regression
lr_cv_scores = cross_val_score(
    model,
    X,
    y,
    cv=5,
    scoring="accuracy"
)

# Random Forest
rf_cv_scores = cross_val_score(
    rf_model,
    X,
    y,
    cv=5,
    scoring="accuracy"
)

# XGBoost
xgb_cv_scores = cross_val_score(
    xgb_model,
    X,
    y.map({-1: 0, 1: 1}),
    cv=5,
    scoring="accuracy"
)

print("\n========== 5-Fold Cross-Validation Comparison ==========")

print("\nLogistic Regression:")
print("Fold accuracies:", lr_cv_scores)
print("Mean accuracy:", lr_cv_scores.mean())
print("Standard deviation:", lr_cv_scores.std())

print("\nRandom Forest:")
print("Fold accuracies:", rf_cv_scores)
print("Mean accuracy:", rf_cv_scores.mean())
print("Standard deviation:", rf_cv_scores.std())

print("\nXGBoost:")
print("Fold accuracies:", xgb_cv_scores)
print("Mean accuracy:", xgb_cv_scores.mean())
print("Standard deviation:", xgb_cv_scores.std())



import joblib
import os

# Create results directory if it doesn't exist
os.makedirs("results", exist_ok=True)

# Save the trained Random Forest model
joblib.dump(rf_model, "results/random_forest_phishing_model.pkl")

# Save the feature names and their order
joblib.dump(X.columns.tolist(), "results/website_feature_names.pkl")

print("\nRandom Forest model saved successfully.")
print("Feature names saved successfully.")
