import re

import dns.resolver


def get_dmarc_record(domain: str):

    if not domain:
        return {
            "status": "missing_domain",
            "domain": domain,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "aggregate_reports": [],
            "forensic_reports": [],
            "dkim_alignment": None,
            "spf_alignment": None
        }

    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(
            dmarc_domain,
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

            if record.lower().startswith("v=dmarc1"):
                records.append(record)

        if not records:
            return {
                "status": "not_found",
                "domain": domain,
                "record": None,
                "policy": None,
                "subdomain_policy": None,
                "percentage": None,
                "aggregate_reports": [],
                "forensic_reports": [],
                "dkim_alignment": None,
                "spf_alignment": None
            }

        record = records[0]

        tags = {}

        for part in record.split(";"):

            part = part.strip()

            if "=" not in part:
                continue

            key, value = part.split(
                "=",
                1
            )

            tags[key.strip().lower()] = value.strip()

        aggregate_reports = []

        if tags.get("rua"):

            aggregate_reports = [
                value.strip()
                for value in tags["rua"].split(",")
            ]

        forensic_reports = []

        if tags.get("ruf"):

            forensic_reports = [
                value.strip()
                for value in tags["ruf"].split(",")
            ]

        return {
            "status": "found",
            "domain": domain,
            "record": record,
            "policy": tags.get("p"),
            "subdomain_policy": tags.get("sp"),
            "percentage": tags.get("pct"),
            "aggregate_reports": aggregate_reports,
            "forensic_reports": forensic_reports,
            "dkim_alignment": tags.get("adkim"),
            "spf_alignment": tags.get("aspf")
        }

    except dns.resolver.NXDOMAIN:

        return {
            "status": "not_found",
            "domain": domain,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "aggregate_reports": [],
            "forensic_reports": [],
            "dkim_alignment": None,
            "spf_alignment": None
        }

    except dns.resolver.NoAnswer:

        return {
            "status": "no_txt_record",
            "domain": domain,
            "record": None,
            "policy": None,
            "percentage": None,
            "aggregate_reports": [],
            "forensic_reports": [],
            "dkim_alignment": None,
            "spf_alignment": None
        }

    except dns.resolver.Timeout:

        return {
            "status": "dns_timeout",
            "domain": domain,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "aggregate_reports": [],
            "forensic_reports": [],
            "dkim_alignment": None,
            "spf_alignment": None
        }

    except Exception as e:

        return {
            "status": "error",
            "domain": domain,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "aggregate_reports": [],
            "forensic_reports": [],
            "dkim_alignment": None,
            "spf_alignment": None,
            "error": str(e)
        }


# -------------------------------------------------
# DOMAIN HELPERS
# -------------------------------------------------

def normalize_domain(domain: str):

    if not domain:
        return None

    domain = domain.strip().lower()

    domain = domain.strip("<>")

    if "@" in domain:
        domain = domain.split("@")[-1]

    domain = domain.rstrip(".")

    return domain


def extract_email_domain(email_address: str):

    if not email_address:
        return None

    match = re.search(
        r'@([A-Za-z0-9.-]+)',
        email_address
    )

    if not match:
        return None

    return normalize_domain(
        match.group(1)
    )


# -------------------------------------------------
# DOMAIN ALIGNMENT
# -------------------------------------------------

def domains_aligned(
    from_domain: str,
    authenticated_domain: str,
    mode: str = "r"
):

    from_domain = normalize_domain(
        from_domain
    )

    authenticated_domain = normalize_domain(
        authenticated_domain
    )

    if not from_domain or not authenticated_domain:
        return False

    # Strict alignment
    if mode == "s":
        return (
            from_domain
            == authenticated_domain
        )

    # Relaxed alignment
    if mode == "r":

        return (
            from_domain == authenticated_domain
            or
            from_domain.endswith(
                "." + authenticated_domain
            )
            or
            authenticated_domain.endswith(
                "." + from_domain
            )
        )

    return False


# -------------------------------------------------
# DMARC ALIGNMENT EVALUATION
# -------------------------------------------------

def evaluate_dmarc_alignment(
    from_domain: str,
    spf_domain: str,
    dkim_domain: str,
    spf_result: str,
    dkim_result: str,
    dmarc_record: dict
):

    from_domain = normalize_domain(
        from_domain
    )

    spf_domain = normalize_domain(
        spf_domain
    )

    dkim_domain = normalize_domain(
        dkim_domain
    )

    if not from_domain:

        return {
            "status": "unknown",
            "from_domain": None,
            "spf": {
                "domain": spf_domain,
                "result": spf_result,
                "aligned": False
            },
            "dkim": {
                "domain": dkim_domain,
                "result": dkim_result,
                "aligned": False
            },
            "dmarc_result": "unknown"
        }

    # DMARC alignment modes
    spf_mode = "r"
    dkim_mode = "r"

    if dmarc_record:

        spf_mode = (
            dmarc_record.get(
                "spf_alignment"
            ) or "r"
        ).lower()

        dkim_mode = (
            dmarc_record.get(
                "dkim_alignment"
            ) or "r"
        ).lower()

    # SPF alignment
    spf_aligned = False

    if (
        spf_result == "pass"
        and spf_domain
    ):

        spf_aligned = domains_aligned(
            from_domain,
            spf_domain,
            spf_mode
        )

    # DKIM alignment
    dkim_aligned = False

    if (
        dkim_result == "pass"
        and dkim_domain
    ):

        dkim_aligned = domains_aligned(
            from_domain,
            dkim_domain,
            dkim_mode
        )

    # DMARC passes if either
    # aligned SPF OR aligned DKIM passes
    if spf_aligned or dkim_aligned:

        dmarc_result = "pass"

    else:

        dmarc_result = "fail"

    return {
        "status": "evaluated",
        "from_domain": from_domain,
        "spf": {
            "domain": spf_domain,
            "result": spf_result,
            "alignment_mode": spf_mode,
            "aligned": spf_aligned
        },
        "dkim": {
            "domain": dkim_domain,
            "result": dkim_result,
            "alignment_mode": dkim_mode,
            "aligned": dkim_aligned
        },
        "dmarc_result": dmarc_result
    }
