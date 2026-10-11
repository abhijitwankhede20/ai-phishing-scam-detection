from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import sys
from pathlib import Path
from email_detection.email_ml_detector import analyze_email_ml
from email_detection.email_ml_detector import analyze_email_ml

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "website_detection"))

from final_detector import analyze_website

from email_detection.email_detector import analyze_email


app = FastAPI(
    title="AI Phishing and Scam Detection",
    description="Website phishing detection API",
    version="1.0"
)

FRONTEND_DIR = ROOT / "frontend"

app.mount(
    "/static",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="static"
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.post("/check-url")
def check_url(request: URLRequest):

    try:
        result = analyze_website(request.url)

        return {
            "url": request.url,
            "hostname": result["hostname"],
            "normalized_url": result["normalized_url"],
            "prediction": result["result"],
            "phishing_probability": round(
                result["phishing_probability"] * 100, 2
            ),
            "legitimate_probability": round(
                result["legitimate_probability"] * 100, 2
            ),
            "structural_risk_points": result["risk_points"],
            "reasons": result["reasons"]
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )




class EmailRequest(BaseModel):
    sender_email: str = ""
    subject: str = ""
    body: str = ""


@app.post("/check-email-ml")
def check_email_ml(request: EmailRequest):
    try:
        return analyze_email_ml(
            sender_email=request.sender_email,
            subject=request.subject,
            body=request.body,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@app.post("/check-email-combined")
def check_email_combined(request: EmailRequest):
    try:
        rule_result = analyze_email(
            sender_email=request.sender_email,
            subject=request.subject,
            body=request.body,
        )

        ml_result = analyze_email_ml(
            sender_email=request.sender_email,
            subject=request.subject,
            body=request.body,
        )

        rule_prediction = rule_result["prediction"]
        ml_prediction = ml_result["prediction"]

        return {
            "rule_based": rule_result,
            "machine_learning": ml_result,
            "predictions_agree": (
                (rule_prediction == "LOWER RISK" and ml_prediction == "SAFE")
                or (
                    rule_prediction == "PHISHING / HIGH RISK"
                    and ml_prediction == "PHISHING / SCAM"
                )
                or (
                    rule_prediction == "SUSPICIOUS"
                    and ml_prediction == "PHISHING / SCAM"
                )
            ),
            "note": (
                "Both detectors provide signals; neither result "
                "guarantees that an email is safe or malicious."
            ),
        }

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))