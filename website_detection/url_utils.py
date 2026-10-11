
from urllib.parse import urlsplit, urlunsplit
import tldextract


def analyze_url_parts(url):
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")

    # Extract registered domain using the Public Suffix List
    parts = tldextract.extract(parsed.hostname)

    registered_domain = parts.top_domain_under_public_suffix

    # Keep the complete URL for the ML model.
    # Remove only the fragment, which is not sent to the server.
    normalized_url = urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path,
        parsed.query,
        ""
    ))

    return {
        "normalized_url": normalized_url,
        "hostname": parsed.hostname.lower(),
        "registered_domain": registered_domain
    }


if __name__ == "__main__":
    url = input("Enter URL: ")
    try:
        print(analyze_url_parts(url))
    except ValueError as error:
        print("Invalid URL:", error)
