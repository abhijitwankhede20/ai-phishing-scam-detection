import joblib
from risk_engine import analyze_url


# Load model
model = joblib.load(
    "results/raw_url_phishing_model.pkl"
)


# Legitimate websites for testing
legitimate_urls = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.in",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.youtube.com",
    "https://www.linkedin.com",
    "https://stackoverflow.com",
    "https://www.python.org",
    "https://www.mozilla.org",
    "https://www.cloudflare.com",
    "https://www.ubuntu.com",
    "https://www.ibm.com",
    "https://www.oracle.com",
    "https://www.nasa.gov",
    "https://www.bbc.com",
    "https://www.reddit.com",
    "https://www.openai.com",
    "https://example.com"
]


print("\n==============================================")
print("       LEGITIMATE URL FALSE-POSITIVE TEST")
print("==============================================\n")


false_positives = 0

for url in legitimate_urls:

    probabilities = model.predict_proba([url])[0]

    phishing_probability = probabilities[0]

    structural = analyze_url(url)

    # Conservative decision for legitimate-site test
    if (
        phishing_probability >= 0.90
        or structural["risk_points"] >= 40
    ):
        result = "⚠️ FLAGGED"
        false_positives += 1
    else:
        result = "✅ ACCEPTED"

    print(
        f"{result:12} "
        f"{phishing_probability * 100:6.2f}%  "
        f"{url}"
    )


print("\n==============================================")
print("RESULT")
print("==============================================")

print("Total websites:", len(legitimate_urls))
print("False positives:", false_positives)

accuracy = (
    (len(legitimate_urls) - false_positives)
    / len(legitimate_urls)
) * 100

print(
    "Legitimate acceptance rate:",
    f"{accuracy:.2f}%"
)

print("==============================================")