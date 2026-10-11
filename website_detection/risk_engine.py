import re
from urllib.parse import urlparse


# ==========================================
# URL STRUCTURAL ANALYSIS
# ==========================================

def analyze_url(url):

    url = url.strip()

    # Add scheme if user doesn't provide one
    if not url.startswith(("http://", "https://")):
        url_for_parse = "https://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    full_url = url_for_parse.lower()

    reasons = []
    risk_points = 0

    # --------------------------------------
    # 1. IP address instead of domain
    # --------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        risk_points += 30
        reasons.append("URL uses an IP address instead of a domain")


    # --------------------------------------
    # 2. HTTPS
    # --------------------------------------

    if parsed.scheme != "https":
        risk_points += 10
        reasons.append("Website does not use HTTPS")


    # --------------------------------------
    # 3. @ symbol
    # --------------------------------------

    if "@" in full_url:
        risk_points += 25
        reasons.append("URL contains '@' symbol")


    # --------------------------------------
    # 4. Excessive subdomains
    # --------------------------------------

    subdomain_count = max(0, len(hostname.split(".")) - 2)

    if subdomain_count >= 3:
        risk_points += 15
        reasons.append("URL contains many subdomains")


    # --------------------------------------
    # 5. Very long URL
    # --------------------------------------

    if len(full_url) > 150:
        risk_points += 10
        reasons.append("URL is unusually long")


    # --------------------------------------
    # 6. Suspicious words
    # --------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "bank",
        "wallet",
        "recover",
        "suspend",
        "unlock",
        "payment"
    ]

    found_words = [
        word for word in suspicious_words
        if word in full_url
    ]

    # Don't heavily penalize a URL just because
    # it contains one common word like "login".

    if len(found_words) >= 3:
        risk_points += 20
        reasons.append(
            "URL contains multiple security/account-related keywords"
        )


    # --------------------------------------
    # 7. URL obfuscation
    # --------------------------------------

    if "%" in full_url:
        risk_points += 10
        reasons.append("URL contains encoded characters")


    # --------------------------------------
    # 8. Excessive hyphens
    # --------------------------------------

    if hostname.count("-") >= 3:
        risk_points += 10
        reasons.append("Domain contains many hyphens")


    # --------------------------------------
    # 9. Suspicious double slash
    # --------------------------------------

    if "//" in path:
        risk_points += 10
        reasons.append("URL path contains suspicious redirection pattern")


    # --------------------------------------
    # 10. Suspicious port
    # --------------------------------------

    try:
        port = parsed.port

        if port is not None and port not in [80, 443]:
            risk_points += 10
            reasons.append("URL uses a non-standard port")

    except ValueError:
        risk_points += 20
        reasons.append("URL contains an invalid port")


    return {
        "risk_points": risk_points,
        "reasons": reasons,
        "hostname": hostname,
        "length": len(full_url)
    }


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    test_url = input("Enter URL: ")

    result = analyze_url(test_url)

    print("\n===================================")
    print("       URL STRUCTURAL ANALYSIS")
    print("===================================")

    print("Hostname:", result["hostname"])
    print("URL Length:", result["length"])
    print("Risk Points:", result["risk_points"])

    print("\nReasons:")

    if result["reasons"]:

        for reason in result["reasons"]:
            print("-", reason)

    else:
        print("No major structural risk indicators found.")

    print("===================================")