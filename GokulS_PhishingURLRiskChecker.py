"""
Project: Phishing URL Risk Checker
Author: Gokul S

A beginner-friendly, rule-based demo that checks a URL for common suspicious
patterns. It does not visit websites and is not a replacement for professional
security tools.
"""

from urllib.parse import urlparse
import ipaddress


SUSPICIOUS_KEYWORDS = (
    "login", "verify", "update", "secure", "account", "password",
    "banking", "wallet", "confirm", "signin"
)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"
}


def check_url(url):
    """Return a simple risk score, risk label, and reasons for a URL."""
    url = url.strip()
    reasons = []
    score = 0

    if not url:
        return {"url": url, "score": 0, "risk": "Invalid", "reasons": ["No URL entered"]}

    candidate = url if "://" in url else "http://" + url
    parsed = urlparse(candidate)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return {"url": url, "score": 0, "risk": "Invalid", "reasons": ["Could not identify a hostname"]}

    if parsed.scheme.lower() != "https":
        score += 1
        reasons.append("URL does not use HTTPS")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("Contains '@' in the network location")

    if len(url) > 75:
        score += 1
        reasons.append("Unusually long URL")

    if hostname.count(".") >= 3:
        score += 1
        reasons.append("Many subdomains")

    try:
        ipaddress.ip_address(hostname)
        score += 2
        reasons.append("Uses an IP address instead of a domain name")
    except ValueError:
        pass

    if hostname in SHORTENER_DOMAINS:
        score += 2
        reasons.append("Uses a known URL-shortening domain")

    lower_url = url.lower()
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]
    if found_keywords:
        score += 1
        reasons.append("Contains account-related keywords: " + ", ".join(found_keywords))

    if "-" in hostname:
        score += 1
        reasons.append("Domain contains a hyphen")

    if score >= 4:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No common warning signs found by these simple rules")

    return {"url": url, "score": score, "risk": risk, "reasons": reasons}


def main():
    print("=" * 48)
    print("        PHISHING URL RISK CHECKER")
    print("        Project by Gokul S")
    print("=" * 48)
    print("Educational demo only: do not rely on this alone.")
    url = input("\nEnter a URL to check: ")
    result = check_url(url)

    print("\nURL:", result["url"])
    print("Risk level:", result["risk"])
    print("Risk score:", result["score"])
    print("Reasons:")
    for reason in result["reasons"]:
        print(" -", reason)


if __name__ == "__main__":
    main()
