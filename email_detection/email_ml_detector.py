from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "email_text_model.joblib"

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Trained email model not found: {MODEL_PATH}"
    )

# Load the trained model once when this module is imported.
model = joblib.load(MODEL_PATH)


def analyze_email_ml(sender_email="", subject="", body=""):
    """Predict email text using the trained ML model."""

    subject = (subject or "").strip()
    body = (body or "").strip()

    if not subject and not body:
        raise ValueError("Enter an email subject or body.")

    # The model was trained on email bodies. Include the subject
    # because it can contain useful information for classification.
    email_text = f"{subject}\n{body}".strip()

    prediction = int(model.predict([email_text])[0])
    probabilities = model.predict_proba([email_text])[0]
    classes = list(model.classes_)

    phishing_index = classes.index(1)
    safe_index = classes.index(0)

    phishing_score = float(probabilities[phishing_index]) * 100
    safe_score = float(probabilities[safe_index]) * 100

    if prediction == 1:
        result = "PHISHING / SCAM"
    else:
        result = "SAFE"

    return {
        "prediction": result,
        "predicted_label": prediction,
        "phishing_model_score": round(phishing_score, 2),
        "safe_model_score": round(safe_score, 2),
        "method": "TF-IDF + Logistic Regression",
    }
