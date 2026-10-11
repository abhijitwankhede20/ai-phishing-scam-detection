import joblib
import pandas as pd

from url_features import extract_features


# ============================================================
# LOAD SAVED MODEL
# ============================================================

model = joblib.load(
    "results/random_forest_phishing_model.pkl"
)

feature_names = joblib.load(
    "results/website_feature_names.pkl"
)


# ============================================================
# GET URL FROM USER
# ============================================================

url = input("Enter URL: ")


# ============================================================
# EXTRACT 30 FEATURES
# ============================================================

features = extract_features(url)


# ============================================================
# CREATE DATAFRAME
# ============================================================

X_new = pd.DataFrame(
    [features],
    columns=feature_names
)


# ============================================================
# PREDICTION
# ============================================================

prediction = model.predict(X_new)[0]

probabilities = model.predict_proba(X_new)[0]


# Random Forest classes are:
# [-1, 1]
#
# -1 = Phishing
#  1 = Legitimate

phishing_probability = probabilities[0]
legitimate_probability = probabilities[1]


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n===================================")
print("       PHISHING WEBSITE CHECK")
print("===================================")

if prediction == -1:

    print("🚨 RESULT: PHISHING")

else:

    print("✅ RESULT: LEGITIMATE")


print("\nPhishing probability:",
      f"{phishing_probability * 100:.2f}%")

print("Legitimate probability:",
      f"{legitimate_probability * 100:.2f}%")

print("===================================")