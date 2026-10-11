
import ipaddress
import re
from urllib.parse import urlsplit


URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
    re.IGNORECASE
)

URGENT_PHRASES = [
    "act immediately",
    "urgent action",
    "account will be suspended",
    "account will be blocked",
    "within 24 hours",
    "immediately",
    "final warning",
    "limited time",
]

CREDENTIAL_PHRASES = [
    "enter your password",
    "confirm your password",
    "verify your account",
    "verify your identity",
    "share your otp",
    "send your otp",
    "one-time password",
    "bank details",
    "credit card details",
    "login credentials",
    "confirm your otp",
]

MONEY_PHRASES = [
    "gift card",
    "claim your prize",
    "you have won",
    "processing fee",
    "send money",
    "wire transfer",
    "payment required",
    "refund is waiting",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "rb.gy"
}


def extract_urls(text):
    """Extract links appearing in the email text."""
    urls = URL_PATTERN.findall(text or "")

    cleaned = []
    for url in urls:
        url = url.rstrip(".,!?;:)]}")
        if url.lower().startswith("www."):
            url = "https://" + url
        cleaned.append(url)

    return list(dict.fromkeys(cleaned))


def inspect_url(url):
    """Check basic URL warning signs without opening the URL."""
    points = 0
    reasons = []

    try:
        parts = urlsplit(url)
        hostname = parts.hostname

        if not hostname:
            return 15, ["A link has an invalid or unclear hostname."]

        hostname = hostname.lower().rstrip(".")

        try:
            ipaddress.ip_address(hostname)
            points += 25
            reasons.append("A link uses an IP address as its hostname.")
        except ValueError:
            pass

        if parts.scheme.lower() != "https":
            points += 10
            reasons.append("A link does not use HTTPS.")

        if "@" in parts.netloc:
            points += 20
            reasons.append("A link contains an @ symbol in its authority.")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            points += 15
            reasons.append("A link contains an internationalized hostname.")

        if hostname in SHORTENERS:
            points += 15
            reasons.append("A link uses a URL-shortening service.")

    except ValueError:
        points += 15
        reasons.append("A link could not be parsed reliably.")

    return points, reasons


def analyze_email(sender_email="", subject="", body=""):
    """
    Analyze email text using transparent heuristic rules.
    This is a baseline, not a trained ML classifier.
    """

    sender_email = (sender_email or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()

    full_text = f"{subject}\n{body}".lower()
    score = 0
    reasons = []

    if not subject and not body:
        raise ValueError("Enter an email subject or body.")

    # Urgency and pressure tactics
    urgency_count = sum(
        phrase in full_text for phrase in URGENT_PHRASES
    )
    if urgency_count:
        points = min(urgency_count * 10, 20)
        score += points
        reasons.append(
            "The message uses urgent or threatening language."
        )

    # Requests for sensitive information
    credential_count = sum(
        phrase in full_text for phrase in CREDENTIAL_PHRASES
    )
    if credential_count:
        score += min(credential_count * 20, 40)
        reasons.append(
            "The message mentions passwords, OTPs, identity "
            "verification, or sensitive financial information."
        )

    # Money, prizes, and payment pressure
    money_count = sum(
        phrase in full_text for phrase in MONEY_PHRASES
    )
    if money_count:
        score += min(money_count * 15, 30)
        reasons.append(
            "The message contains payment, prize, or money-related "
            "phrases often used in scams."
        )

    # Sender address format
    if sender_email:
        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            sender_email
        ):
            score += 10
            reasons.append(
                "The sender address has an unusual format."
            )

    # Inspect links without visiting them
    urls = extract_urls(body)
    suspicious_url_count = 0

    for url in urls:
        url_points, url_reasons = inspect_url(url)

        if url_points:
            suspicious_url_count += 1
            score += min(url_points, 25)
            reasons.extend(url_reasons)

    if suspicious_url_count:
        reasons.append(
            f"{suspicious_url_count} link(s) contain URL warning signs."
        )

    score = min(score, 100)

    # Conservative labels: warning signs are not proof.
    if score >= 50:
        result = "PHISHING / HIGH RISK"
    elif score >= 20:
        result = "SUSPICIOUS"
    else:
        result = "LOWER RISK"

    if not reasons:
        reasons.append(
            "No warning signs covered by the current rules were found."
        )

    return {
        "prediction": result,
        "risk_score": score,
        "sender_email": sender_email,
        "subject": subject,
        "urls_found": urls,
        "reasons": list(dict.fromkeys(reasons)),
        "method": "Rule-based baseline; not a trained ML model"
    }
