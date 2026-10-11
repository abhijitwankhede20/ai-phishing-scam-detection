
import ipaddress
import joblib
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from risk_engine import analyze_url


ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "results" / "raw_url_phishing_model.pkl"

model = joblib.load(MODEL_PATH)


# Common advertising and analytics parameters
TRACKING_KEYS = {
    "gclid", "fbclid", "msclkid", "gad_source",
    "gad_campaignid", "tag", "ref", "mcid",
    "adgrpid", "hydadcr", "sourceid",
    "hvpone", "hvptwo", "hvadid", "hvpos",
    "hvnetw", "hvrand", "hvqmt", "hvdev",
    "hvdvcmdl", "hvlocint", "hvlocphy",
    "hvtargid", "hvocijid", "hvexpln"
}


def normalize_url(url):
    """Validate a URL and remove common tracking parameters."""

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if any(ch.isspace() for ch in url):
        raise ValueError("URL cannot contain spaces.")

    if "://" not in url:
        url = "https://" + url

    parts = urlsplit(url)

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are supported.")

    hostname = parts.hostname

    if not hostname:
        raise ValueError("Invalid hostname.")

    try:
        port = parts.port
    except ValueError:
        raise ValueError("Invalid port.")

    hostname = hostname.lower().rstrip(".")

    # Validate domain or IP address.
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip:
        if "." not in hostname:
            raise ValueError("Enter a valid domain name.")

        if not re.fullmatch(r"[a-z0-9.-]+", hostname):
            raise ValueError("Invalid domain characters.")

        if (
            hostname.startswith(".")
            or hostname.endswith(".")
            or ".." in hostname
            or any(not label for label in hostname.split("."))
        ):
            raise ValueError("Invalid hostname.")

    original_url = url

    # Remove common tracking parameters for model input.
    query_items = parse_qsl(
        parts.query,
        keep_blank_values=True
    )

    clean_query = [
        (key, value)
        for key, value in query_items
        if key.lower() not in TRACKING_KEYS
        and not key.lower().startswith("utm_")
        and not key.lower().startswith("gad_")
        and not key.lower().startswith("hv")
    ]

    cleaned_query = urlencode(clean_query)

    # Normalize the authority and default ports.
    host = hostname

    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    if port is not None:
        if not (
            (parts.scheme.lower() == "http" and port == 80)
            or (parts.scheme.lower() == "https" and port == 443)
        ):
            host = f"{host}:{port}"

    ml_url = urlunsplit((
        parts.scheme.lower(),
        host,
        parts.path or "/",
        cleaned_query,
        ""
    ))

    return original_url, ml_url, hostname


def get_model_url(normalized_url):
    """
    Remove a leading www. for model input so the model receives
    a consistent hostname representation.

    This is a normalization experiment, not a safety guarantee.
    """
    parts = urlsplit(normalized_url)
    hostname = (parts.hostname or "").lower()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    # Preserve a non-default port if present.
    try:
        port = parts.port
    except ValueError:
        port = None

    netloc = hostname

    if port is not None:
        netloc = f"{hostname}:{port}"

    return urlunsplit((
        parts.scheme.lower(),
        netloc,
        parts.path or "/",
        parts.query,
        ""
    ))


def analyze_website(url):
    original_url, ml_url, hostname = normalize_url(url)

    # Use consistent hostname representation for ML prediction.
    model_url = ml_url

    probabilities = model.predict_proba([model_url])[0]
    classes = list(model.classes_)

    phishing_probability = float(
        probabilities[classes.index(0)]
    )

    legitimate_probability = float(
        probabilities[classes.index(1)]
    )

    # Structural checks use the original URL.
    structural = analyze_url(original_url)

    risk_points = structural["risk_points"]
    reasons = list(structural["reasons"])

    # Existing classification thresholds.
    if phishing_probability >= 0.90 and risk_points >= 30:
        result = "PHISHING"

    elif phishing_probability >= 0.60 or risk_points >= 20:
        result = "SUSPICIOUS"

    else:
        result = "LEGITIMATE"

    if phishing_probability >= 0.60:
        reasons.append(
            "Machine learning detected suspicious URL patterns."
        )

    if result == "LEGITIMATE" and not reasons:
        reasons.append(
            "No major risk indicators were detected."
        )

    return {
        "result": result,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "risk_points": risk_points,
        "hostname": hostname,
        "normalized_url": model_url,
        "reasons": reasons
    }


if __name__ == "__main__":
    url = input("Enter URL or domain: ")

    try:
        result = analyze_website(url)

        print("\n========== WEBSITE SECURITY CHECK ==========")
        print("Hostname:", result["hostname"])
        print("Normalized URL:", result["normalized_url"])
        print("Prediction:", result["result"])

        print(
            "Phishing probability:",
            f"{result['phishing_probability'] * 100:.2f}%"
        )

        print(
            "Legitimate probability:",
            f"{result['legitimate_probability'] * 100:.2f}%"
        )

        print("Structural risk:", result["risk_points"])

        print("\nReasons:")
        for reason in result["reasons"]:
            print("-", reason)

    except ValueError as error:
        print("Error:", error)
