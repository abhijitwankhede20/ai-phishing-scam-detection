from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "email_text_model.joblib"

model = joblib.load(MODEL_PATH)

def predict_email(text):
    prediction = int(model.predict([text])[0])
    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    phishing_index = classes.index(1)
    phishing_score = float(probabilities[phishing_index]) * 100

    label = "PHISHING / SCAM" if prediction == 1 else "SAFE"

    return {
        "prediction": label,
        "predicted_label": prediction,
        "phishing_model_score_percent": round(phishing_score, 2),
    }

if __name__ == "__main__":
    samples = [
        "Hi, our meeting is scheduled for tomorrow at 10 AM. Please bring your assignment.",
        "URGENT! Verify your account password immediately to prevent suspension. Claim your reward now.",
    ]

    for i, email in enumerate(samples, start=1):
        print(f"\nTest email {i}: {email}")
        print(predict_email(email))
