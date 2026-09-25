import re

import dns.resolver
import dkim


def analyze_dkim_header(dkim_header: str):

    if not dkim_header:
        return {
            "present": False,
            "selector": None,
            "domain": None,
            "algorithm": None,
            "canonicalization": None,
            "signed_headers": [],
            "signature": None
        }

    selector_match = re.search(
        r'(?:^|;)\s*s=([^;]+)',
        dkim_header,
        re.IGNORECASE
    )

    domain_match = re.search(
        r'(?:^|;)\s*d=([^;]+)',
        dkim_header,
        re.IGNORECASE
    )

    algorithm_match = re.search(
        r'(?:^|;)\s*a=([^;]+)',
        dkim_header,
        re.IGNORECASE
    )

    canonicalization_match = re.search(
        r'(?:^|;)\s*c=([^;]+)',
        dkim_header,
        re.IGNORECASE
    )

    headers_match = re.search(
        r'(?:^|;)\s*h=([^;]+)',
        dkim_header,
        re.IGNORECASE
    )

    signature_match = re.search(
        r'(?:^|;)\s*b=([^;]+)',
        dkim_header,
        re.IGNORECASE
    )

    signed_headers = []

    if headers_match:

        signed_headers = [
            header.strip()
            for header in headers_match.group(1).split(":")
        ]

    return {
        "present": True,
        "selector": (
            selector_match.group(1).strip()
            if selector_match
            else None
        ),
        "domain": (
            domain_match.group(1).strip()
            if domain_match
            else None
        ),
        "algorithm": (
            algorithm_match.group(1).strip()
            if algorithm_match
            else None
        ),
        "canonicalization": (
            canonicalization_match.group(1).strip()
            if canonicalization_match
            else None
        ),
        "signed_headers": signed_headers,
        "signature": (
            signature_match.group(1).strip()
            if signature_match
            else None
        )
    }


def get_dkim_public_key(
    domain: str,
    selector: str
):

    if not domain or not selector:

        return {
            "status": "missing_parameters",
            "domain": domain,
            "selector": selector,
            "record": None
        }

    dkim_domain = (
        f"{selector}._domainkey.{domain}"
    )

    try:

        answers = dns.resolver.resolve(
            dkim_domain,
            "TXT"
        )

        records = []

        for answer in answers:

            record = "".join(
                part.decode("utf-8")
                if isinstance(part, bytes)
                else str(part)
                for part in answer.strings
            )

            records.append(record)

        if not records:

            return {
                "status": "not_found",
                "domain": domain,
                "selector": selector,
                "record": None
            }

        return {
            "status": "found",
            "domain": domain,
            "selector": selector,
            "record": records[0]
        }

    except dns.resolver.NXDOMAIN:

        return {
            "status": "not_found",
            "domain": domain,
            "selector": selector,
            "record": None
        }

    except dns.resolver.NoAnswer:

        return {
            "status": "no_txt_record",
            "domain": domain,
            "selector": selector,
            "record": None
        }

    except dns.resolver.Timeout:

        return {
            "status": "dns_timeout",
            "domain": domain,
            "selector": selector,
            "record": None
        }

    except Exception as e:

        return {
            "status": "error",
            "domain": domain,
            "selector": selector,
            "record": None,
            "error": str(e)
        }


def verify_dkim(email_content: bytes):

    try:

        result = dkim.verify(
            email_content
        )

        if result:

            return {
                "status": "pass",
                "verified": True
            }

        return {
            "status": "fail",
            "verified": False
        }

    except Exception as e:

        return {
            "status": "error",
            "verified": False,
            "error": str(e)
        }