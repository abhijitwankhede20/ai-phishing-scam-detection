
import os
import requests


SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def check_known_threat(url):
    """
    Check whether Google Safe Browsing reports this URL
    as a known threat.

    status:
      MALICIOUS  - a threat match was returned
      NOT_LISTED - request succeeded, no match found
      UNAVAILABLE - API key, network, or API error
    """

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "UNAVAILABLE",
            "details": "Google Safe Browsing API key is not configured."
        }

    payload = {
        "client": {
            "clientId": "ai-phishing-detection-project",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=5
        )

        if response.status_code != 200:
            return {
                "status": "UNAVAILABLE",
                "details": f"Threat service returned HTTP {response.status_code}."
            }

        data = response.json()

        if data.get("matches"):
            return {
                "status": "MALICIOUS",
                "details": "Google Safe Browsing reported a known threat."
            }

        return {
            "status": "NOT_LISTED",
            "details": "No matching threat was found in this lookup."
        }

    except (requests.RequestException, ValueError):
        return {
            "status": "UNAVAILABLE",
            "details": "Threat service could not be reached."
        }
