import re
import socket
import requests

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


# ============================================================
# 1. having_IP_Address
# ============================================================

def having_ip_address(url):
    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if re.match(pattern, hostname):
            return 1

        return -1

    except:
        return -1


# ============================================================
# 2. URL_Length
# ============================================================

def url_length(url):
    length = len(url)

    if length < 54:
        return -1
    elif length <= 75:
        return 0
    else:
        return 1


# ============================================================
# 3. Shortining_Service
# ============================================================

def shortining_service(url):

    services = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "cli.gs",
        "ow.ly",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "tiny.cc"
    ]

    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        hostname = hostname.lower()

        for service in services:
            if hostname == service or hostname.endswith("." + service):
                return 1

        return -1

    except:
        return -1


# ============================================================
# 4. having_At_Symbol
# ============================================================

def having_at_symbol(url):

    if "@" in url:
        return 1

    return -1


# ============================================================
# 5. double_slash_redirecting
# ============================================================

def double_slash_redirecting(url):

    try:
        position = url.find("//", 8)

        if position != -1:
            return 1

        return -1

    except:
        return -1


# ============================================================
# 6. Prefix_Suffix
# ============================================================

def prefix_suffix(url):

    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        if "-" in hostname:
            return 1

        return -1

    except:
        return -1


# ============================================================
# 7. having_Sub_Domain
# ============================================================

def having_sub_domain(url):

    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        # Remove www
        if hostname.startswith("www."):
            hostname = hostname[4:]

        dots = hostname.count(".")

        if dots == 1:
            return -1

        elif dots == 2:
            return 0

        else:
            return 1

    except:
        return -1


# ============================================================
# 8. SSLfinal_State
# ============================================================

def sslfinal_state(url):

    try:
        parsed = urlparse(url)

        if parsed.scheme == "https":
            return 1

        return -1

    except:
        return -1


# ============================================================
# 9. Domain_registeration_length
# ============================================================

def domain_registration_length(url):

    # Requires WHOIS/domain-registration information.
    # Temporary fallback.

    return -1


# ============================================================
# 10. Favicon
# ============================================================

def favicon(url, soup):

    if soup is None:
        return -1

    try:

        base_domain = urlparse(url).hostname

        links = soup.find_all("link", href=True)

        for link in links:

            rel = link.get("rel", [])

            if isinstance(rel, list):
                rel = " ".join(rel)

            if "icon" in rel.lower():

                icon_url = urljoin(
                    url,
                    link.get("href")
                )

                icon_domain = urlparse(icon_url).hostname

                if icon_domain and icon_domain != base_domain:
                    return 1

                return -1

        return -1

    except:
        return -1


# ============================================================
# 11. port
# ============================================================

def port(url):

    try:

        parsed = urlparse(url)

        if parsed.port is None:
            return -1

        if parsed.port in [80, 443]:
            return -1

        return 1

    except:
        return -1


# ============================================================
# 12. HTTPS_token
# ============================================================

def https_token(url):

    try:

        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        if "https" in hostname.lower():
            return 1

        return -1

    except:
        return -1


# ============================================================
# 13. Request_URL
# ============================================================

def request_url(url, soup):

    if soup is None:
        return -1

    try:

        base_domain = urlparse(url).hostname

        total = 0
        external = 0

        for tag in soup.find_all(["img", "script", "link"]):

            source = tag.get("src") or tag.get("href")

            if not source:
                continue

            total += 1

            full_url = urljoin(url, source)

            domain = urlparse(full_url).hostname

            if domain and domain != base_domain:
                external += 1

        if total == 0:
            return -1

        ratio = external / total

        if ratio < 0.20:
            return -1

        elif ratio <= 0.50:
            return 0

        else:
            return 1

    except:
        return -1


# ============================================================
# 14. URL_of_Anchor
# ============================================================

def url_of_anchor(url, soup):

    if soup is None:
        return -1

    try:

        base_domain = urlparse(url).hostname

        anchors = soup.find_all("a", href=True)

        if len(anchors) == 0:
            return -1

        suspicious = 0

        for anchor in anchors:

            href = anchor.get("href", "").strip()

            if (
                href == ""
                or href == "#"
                or href.startswith("javascript")
            ):
                suspicious += 1
                continue

            full_url = urljoin(url, href)

            domain = urlparse(full_url).hostname

            if domain and domain != base_domain:
                suspicious += 1

        ratio = suspicious / len(anchors)

        if ratio < 0.31:
            return -1

        elif ratio <= 0.67:
            return 0

        else:
            return 1

    except:
        return -1


# ============================================================
# 15. Links_in_tags
# ============================================================

def links_in_tags(url, soup):

    if soup is None:
        return -1

    try:

        base_domain = urlparse(url).hostname

        tags = soup.find_all(["meta", "script", "link"])

        if len(tags) == 0:
            return -1

        external = 0
        total = 0

        for tag in tags:

            link = tag.get("href") or tag.get("src")

            if not link:
                continue

            total += 1

            full_url = urljoin(url, link)

            domain = urlparse(full_url).hostname

            if domain and domain != base_domain:
                external += 1

        if total == 0:
            return -1

        ratio = external / total

        if ratio < 0.17:
            return -1

        elif ratio <= 0.81:
            return 0

        else:
            return 1

    except:
        return -1


# ============================================================
# 16. SFH
# ============================================================

def sfh(url, soup):

    if soup is None:
        return -1

    try:

        base_domain = urlparse(url).hostname

        forms = soup.find_all("form")

        if len(forms) == 0:
            return -1

        for form in forms:

            action = form.get("action", "").strip()

            if action == "" or action.lower() == "about:blank":
                return 0

            full_action = urljoin(url, action)

            domain = urlparse(full_action).hostname

            if domain and domain != base_domain:
                return 1

        return -1

    except:
        return -1


# ============================================================
# 17. Submitting_to_email
# ============================================================

def submitting_to_email(url, soup):

    if soup is None:
        return -1

    try:

        forms = soup.find_all("form")

        for form in forms:

            action = form.get("action", "").lower()

            if "mailto:" in action:
                return 1

        return -1

    except:
        return -1


# ============================================================
# 18. Abnormal_URL
# ============================================================

def abnormal_url(url):

    try:

        parsed = urlparse(url)

        if parsed.netloc == "":
            return 1

        return -1

    except:
        return 1


# ============================================================
# 19. Redirect
# ============================================================

def redirect(url):

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if 300 <= response.status_code < 400:
            return 1

        return 0

    except:
        return 0


# ============================================================
# 20. on_mouseover
# ============================================================

def on_mouseover(soup):

    if soup is None:
        return -1

    try:

        elements = soup.find_all(
            attrs={"onmouseover": True}
        )

        if elements:
            return 1

        return -1

    except:
        return -1


# ============================================================
# 21. RightClick
# ============================================================

def rightclick(soup):

    if soup is None:
        return -1

    try:

        html = str(soup).lower()

        if "contextmenu" in html:
            return 1

        if "event.button==2" in html:
            return 1

        if "event.button == 2" in html:
            return 1

        return -1

    except:
        return -1


# ============================================================
# 22. popUpWidnow
# ============================================================

def popupwindow(soup):

    if soup is None:
        return -1

    try:

        html = str(soup).lower()

        if "window.open" in html:
            return 1

        return -1

    except:
        return -1


# ============================================================
# 23. Iframe
# ============================================================

def iframe(soup):

    if soup is None:
        return -1

    try:

        if soup.find("iframe"):
            return 1

        return -1

    except:
        return -1


# ============================================================
# 24. age_of_domain
# ============================================================

def age_of_domain(url):

    # Requires WHOIS/domain registration data.
    # Temporary fallback.

    return -1


# ============================================================
# 25. DNSRecord
# ============================================================

def dns_record(url):

    try:

        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        socket.gethostbyname(hostname)

        return 1

    except:
        return 0


# ============================================================
# 26. web_traffic
# ============================================================

def web_traffic(url):

    # Requires external traffic/ranking service.
    # Temporary fallback.

    return -1


# ============================================================
# 27. Page_Rank
# ============================================================

def page_rank(url):

    # Requires external PageRank information.
    # Temporary fallback.

    return -1


# ============================================================
# 28. Google_Index
# ============================================================

def google_index(url):

    # Requires search engine information.
    # Temporary fallback.

    return -1


# ============================================================
# 29. Links_pointing_to_page
# ============================================================

def links_pointing_to_page(url):

    # Requires external backlink information.
    # Temporary fallback.

    return -1


# ============================================================
# 30. Statistical_report
# ============================================================

def statistical_report(url):

    # Requires external reputation databases.
    # Temporary fallback.

    return -1


# ============================================================
# DOWNLOAD WEBPAGE
# ============================================================

def get_webpage(url):

    try:

        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        return BeautifulSoup(
            response.text,
            "html.parser"
        )

    except:

        return None


# ============================================================
# EXTRACT ALL 30 FEATURES
# ============================================================

def extract_features(url):

    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    soup = get_webpage(url)

    features = [

        having_ip_address(url),          # 1
        url_length(url),                 # 2
        shortining_service(url),         # 3
        having_at_symbol(url),           # 4
        double_slash_redirecting(url),   # 5
        prefix_suffix(url),              # 6
        having_sub_domain(url),          # 7
        sslfinal_state(url),             # 8
        domain_registration_length(url),# 9
        favicon(url, soup),              # 10
        port(url),                       # 11
        https_token(url),                # 12
        request_url(url, soup),          # 13
        url_of_anchor(url, soup),        # 14
        links_in_tags(url, soup),        # 15
        sfh(url, soup),                  # 16
        submitting_to_email(url, soup),  # 17
        abnormal_url(url),               # 18
        redirect(url),                   # 19
        on_mouseover(soup),              # 20
        rightclick(soup),                # 21
        popupwindow(soup),               # 22
        iframe(soup),                    # 23
        age_of_domain(url),              # 24
        dns_record(url),                 # 25
        web_traffic(url),                # 26
        page_rank(url),                  # 27
        google_index(url),               # 28
        links_pointing_to_page(url),     # 29
        statistical_report(url)          # 30
    ]

    return features


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    url = input("Enter URL: ")

    features = extract_features(url)

    print("\nExtracted Features:")
    print("-------------------")

    for i, value in enumerate(features, start=1):
        print(f"Feature {i}: {value}")

    print("\nTotal features:", len(features))