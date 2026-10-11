import joblib


# ==========================================
# 1. Load Saved Model
# ==========================================

model = joblib.load(
    "results/raw_url_phishing_model.pkl"
)

print("Model loaded successfully.")


# ==========================================
# 2. Take URL from User
# ==========================================

url = input("\nEnter URL: ").strip()


# ==========================================
# 3. Predict
# ==========================================

prediction = model.predict([url])[0]

probabilities = model.predict_proba([url])[0]

# Model classes are [0, 1]
# 0 = Phishing
# 1 = Legitimate

phishing_probability = probabilities[0]
legitimate_probability = probabilities[1]


# ==========================================
# 4. Display Result
# ==========================================

print("\n===================================")
print("       PHISHING URL CHECK")
print("===================================")

if prediction == 0:
    print("🚨 RESULT: PHISHING")
else:
    print("✅ RESULT: LEGITIMATE")

print(
    "\nPhishing probability:",
    f"{phishing_probability * 100:.2f}%"
)

print(
    "Legitimate probability:",
    f"{legitimate_probability * 100:.2f}%"
)

print("===================================")