import re
from urllib.parse import urlparse


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at"
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "security",
    "update",
    "confirm",
    "credential",
    "wallet",
    "payment",
    "invoice",
    "reset",
    "unlock"
}


def extract_url_domain(url: str):

    try:

        parsed = urlparse(url)

        return parsed.hostname.lower() if parsed.hostname else None

    except Exception:

        return None


def is_ip_address(hostname: str):

    if not hostname:
        return False

    return bool(
        re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            hostname
        )
    )


def analyze_url(url: str):

    if not url:

        return {
            "url": url,
            "status": "suspicious",
            "reasons": [
                "empty_url"
            ]
        }

    try:

        parsed = urlparse(url)

    except Exception:

        return {
            "url": url,
            "status": "suspicious",
            "reasons": [
                "invalid_url"
            ]
        }

    hostname = parsed.hostname

    if hostname:
        hostname = hostname.lower()

    reasons = []

    # --------------------------------
    # SCHEME
    # --------------------------------

    if parsed.scheme.lower() == "http":

        reasons.append(
            "unencrypted_http"
        )

    # --------------------------------
    # IP ADDRESS
    # --------------------------------

    if is_ip_address(hostname):

        reasons.append(
            "ip_address_url"
        )

    # --------------------------------
    # @ SYMBOL
    # --------------------------------

    if "@" in url:

        reasons.append(
            "at_symbol_in_url"
        )

    # --------------------------------
    # URL LENGTH
    # --------------------------------

    if len(url) > 150:

        reasons.append(
            "very_long_url"
        )

    # --------------------------------
    # SUBDOMAIN COUNT
    # --------------------------------

    if hostname:

        parts = hostname.split(".")

        if len(parts) >= 5:

            reasons.append(
                "excessive_subdomains"
            )

    # --------------------------------
    # URL SHORTENER
    # --------------------------------

    if hostname in URL_SHORTENERS:

        reasons.append(
            "url_shortener"
        )

    # --------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------

    url_lower = url.lower()

    matched_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            matched_keywords.append(
                keyword
            )

    if matched_keywords:

        reasons.append(
            "suspicious_keywords"
        )

    # --------------------------------
    # FINAL STATUS
    # --------------------------------

    if reasons:

        status = "suspicious"

    else:

        status = "normal"

    return {
        "url": url,
        "domain": hostname,
        "scheme": parsed.scheme,
        "status": status,
        "reasons": reasons,
        "matched_keywords": matched_keywords
    }


def analyze_urls(urls: list):

    results = []

    for url in urls:

        results.append(
            analyze_url(url)
        )

    suspicious_count = sum(
        1
        for result in results
        if result["status"] == "suspicious"
    )

    return {
        "total_urls": len(urls),
        "suspicious_urls": suspicious_count,
        "urls": results
    }
