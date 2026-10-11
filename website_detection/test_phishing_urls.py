
import joblib
from risk_engine import analyze_url

model = joblib.load("results/raw_url_phishing_model.pkl")

phishing_urls = [
    "http://secure-login-verification-account.com/login",
    "http://paypal-login-verification.com/account",
    "http://google-security-alert.com/verify",
    "http://microsoft-account-security.com/login",
    "http://apple-id-verification.com/login",
    "http://amazon-account-verify.com/login",
    "http://bank-account-verification.com/login",
    "http://192.168.1.10/login/verify",
    "http://secure-payment-update-account.com/verify",
    "http://account-security-confirmation.com/login"
]

print("\n========== PHISHING URL TEST ==========\n")

detected = 0

for url in phishing_urls:
    probability = model.predict_proba([url])[0][0]
    structural = analyze_url(url)

    if probability >= 0.60 or structural["risk_points"] >= 40:
        result = "DETECTED"
        detected += 1
    else:
        result = "MISSED"

    print(f"{result:10} {probability * 100:6.2f}%  {url}")

total = len(phishing_urls)

print("\n========== RESULTS ==========")
print("Total test URLs:", total)
print("Detected:", detected)
print("Missed:", total - detected)
print(f"Detection rate: {detected / total * 100:.2f}%")
print("Note: These are synthetic test URLs.")

