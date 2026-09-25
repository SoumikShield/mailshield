import re


def extract_domain(email_address: str):

    if not email_address:
        return None

    match = re.search(
        r'@([A-Za-z0-9.-]+)',
        email_address
    )

    if not match:
        return None

    return match.group(1).lower().rstrip(".")


def extract_display_name(email_address: str):

    if not email_address:
        return None

    match = re.match(
        r'\s*(.*?)\s*<[^>]+>\s*$',
        email_address
    )

    if match:

        display_name = match.group(1).strip()

        if display_name:
            return display_name.strip('"')

    return None


def normalize_lookalike_domain(domain: str):

    if not domain:
        return None

    domain = domain.lower()

    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t"
    }

    normalized = ""

    for character in domain:

        normalized += replacements.get(
            character,
            character
        )

    return normalized


def levenshtein_distance(
    first: str,
    second: str
):

    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous_row = list(
        range(len(second) + 1)
    )

    for i, first_character in enumerate(
        first,
        start=1
    ):

        current_row = [i]

        for j, second_character in enumerate(
            second,
            start=1
        ):

            insertions = (
                current_row[j - 1] + 1
            )

            deletions = (
                previous_row[j] + 1
            )

            substitutions = (
                previous_row[j - 1]
                + (
                    first_character
                    != second_character
                )
            )

            current_row.append(
                min(
                    insertions,
                    deletions,
                    substitutions
                )
            )

        previous_row = current_row

    return previous_row[-1]


def detect_lookalike_domain(
    domain: str
):

    if not domain:
        return {
            "detected": False,
            "domain": None,
            "matched_brand": None,
            "normalized_domain": None,
            "distance": None
        }

    domain = domain.lower().rstrip(".")

    trusted_domains = {
        "microsoft.com": "microsoft",
        "google.com": "google",
        "apple.com": "apple",
        "amazon.com": "amazon",
        "paypal.com": "paypal",
        "linkedin.com": "linkedin",
        "netflix.com": "netflix",
        "facebook.com": "facebook",
        "instagram.com": "instagram",
        "github.com": "github",
        "docusign.com": "docusign",
        "dropbox.com": "dropbox"
    }

    if domain in trusted_domains:

        return {
            "detected": False,
            "domain": domain,
            "matched_brand": None,
            "normalized_domain": domain,
            "distance": 0
        }

    normalized_domain = (
        normalize_lookalike_domain(domain)
    )

    best_brand = None
    best_distance = None

    for trusted_domain, brand in trusted_domains.items():

        if normalized_domain == trusted_domain:

            return {
                "detected": True,
                "domain": domain,
                "matched_brand": brand,
                "normalized_domain": normalized_domain,
                "distance": 0
            }

        distance = levenshtein_distance(
            normalized_domain,
            trusted_domain
        )

        if (
            distance <= 2
            and (
                best_distance is None
                or distance < best_distance
            )
        ):

            best_distance = distance
            best_brand = brand

    if best_brand:

        return {
            "detected": True,
            "domain": domain,
            "matched_brand": best_brand,
            "normalized_domain": normalized_domain,
            "distance": best_distance
        }

    return {
        "detected": False,
        "domain": domain,
        "matched_brand": None,
        "normalized_domain": normalized_domain,
        "distance": None
    }


def analyze_sender(
    from_address: str,
    reply_to: str
):

    from_domain = extract_domain(
        from_address
    )

    reply_to_domain = extract_domain(
        reply_to
    )

    display_name = extract_display_name(
        from_address
    )

    # --------------------------------
    # MISSING FROM
    # --------------------------------

    if not from_address:

        return {
            "status": "suspicious",
            "reason": "missing_from_address",
            "from": None,
            "display_name": None,
            "from_domain": None,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "domain_match": False,
            "display_name_suspicious": False,
            "lookalike_domain": None
        }

    # --------------------------------
    # DISPLAY NAME ANALYSIS
    # --------------------------------

    display_name_suspicious = False

    if display_name:

        trusted_names = [
            "microsoft",
            "google",
            "apple",
            "amazon",
            "paypal",
            "linkedin",
            "netflix",
            "facebook",
            "instagram",
            "github",
            "docusign",
            "dropbox"
        ]

        display_name_lower = (
            display_name.lower()
        )

        for trusted_name in trusted_names:

            if trusted_name in display_name_lower:

                if from_domain:

                    if not from_domain.endswith(
                        trusted_name + ".com"
                    ):

                        display_name_suspicious = True

                break

    # --------------------------------
    # LOOKALIKE DOMAIN
    # --------------------------------

    lookalike_domain = (
        detect_lookalike_domain(
            from_domain
        )
    )

    # --------------------------------
    # MISSING REPLY-TO
    # --------------------------------

    if not reply_to:

        if (
            display_name_suspicious
            or lookalike_domain["detected"]
        ):

            reason = "suspicious_sender"

            if lookalike_domain["detected"]:
                reason = "lookalike_domain"

            elif display_name_suspicious:
                reason = "suspicious_display_name"

            return {
                "status": "suspicious",
                "reason": reason,
                "from": from_address,
                "display_name": display_name,
                "from_domain": from_domain,
                "reply_to": None,
                "reply_to_domain": None,
                "domain_match": None,
                "display_name_suspicious": display_name_suspicious,
                "lookalike_domain": lookalike_domain
            }

        return {
            "status": "normal",
            "reason": "reply_to_not_present",
            "from": from_address,
            "display_name": display_name,
            "from_domain": from_domain,
            "reply_to": None,
            "reply_to_domain": None,
            "domain_match": None,
            "display_name_suspicious": False,
            "lookalike_domain": lookalike_domain
        }

    # --------------------------------
    # INVALID DOMAINS
    # --------------------------------

    if not from_domain or not reply_to_domain:

        return {
            "status": "suspicious",
            "reason": "invalid_email_domain",
            "from": from_address,
            "display_name": display_name,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "domain_match": False,
            "display_name_suspicious": display_name_suspicious,
            "lookalike_domain": lookalike_domain
        }

    # --------------------------------
    # DOMAIN COMPARISON
    # --------------------------------

    domain_match = (
        from_domain == reply_to_domain
    )

    # --------------------------------
    # LOOKALIKE DOMAIN
    # --------------------------------

    if lookalike_domain["detected"]:

        return {
            "status": "suspicious",
            "reason": "lookalike_domain",
            "from": from_address,
            "display_name": display_name,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "domain_match": domain_match,
            "display_name_suspicious": display_name_suspicious,
            "lookalike_domain": lookalike_domain
        }

    # --------------------------------
    # DISPLAY NAME
    # --------------------------------

    if display_name_suspicious:

        return {
            "status": "suspicious",
            "reason": "suspicious_display_name",
            "from": from_address,
            "display_name": display_name,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "domain_match": domain_match,
            "display_name_suspicious": True,
            "lookalike_domain": lookalike_domain
        }

    # --------------------------------
    # REPLY-TO MATCH
    # --------------------------------

    if domain_match:

        return {
            "status": "normal",
            "reason": "from_and_reply_to_domains_match",
            "from": from_address,
            "display_name": display_name,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "domain_match": True,
            "display_name_suspicious": False,
            "lookalike_domain": lookalike_domain
        }

    # --------------------------------
    # REPLY-TO MISMATCH
    # --------------------------------

    return {
        "status": "suspicious",
        "reason": "reply_to_domain_mismatch",
        "from": from_address,
        "display_name": display_name,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_to_domain,
        "domain_match": False,
        "display_name_suspicious": False,
        "lookalike_domain": lookalike_domain
    }
