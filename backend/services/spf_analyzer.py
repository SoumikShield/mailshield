import ipaddress
import re

import dns.resolver


def get_spf_record(domain: str):

    try:
        answers = dns.resolver.resolve(
            domain,
            "TXT"
        )

        spf_records = []

        for answer in answers:

            record = "".join(
                part.decode("utf-8")
                if isinstance(part, bytes)
                else str(part)
                for part in answer.strings
            )

            if record.lower().startswith("v=spf1"):
                spf_records.append(record)

        if not spf_records:
            return {
                "domain": domain,
                "status": "not_found",
                "record": None
            }

        return {
            "domain": domain,
            "status": "found",
            "record": spf_records[0]
        }

    except dns.resolver.NXDOMAIN:

        return {
            "domain": domain,
            "status": "domain_not_found",
            "record": None
        }

    except dns.resolver.NoAnswer:

        return {
            "domain": domain,
            "status": "no_txt_record",
            "record": None
        }

    except dns.resolver.Timeout:

        return {
            "domain": domain,
            "status": "dns_timeout",
            "record": None
        }

    except Exception as e:

        return {
            "domain": domain,
            "status": "error",
            "record": None,
            "error": str(e)
        }


def extract_sending_ip(received_headers: list):

    for header in received_headers:

        ip_matches = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            header
        )

        if ip_matches:
            return ip_matches[0]

    return None


def evaluate_spf(
    domain: str,
    sending_ip: str,
    spf_record: str
):

    if not sending_ip:
        return "unknown"

    if not spf_record:
        return "none"

    try:
        ip = ipaddress.ip_address(
            sending_ip
        )

    except ValueError:
        return "unknown"

    mechanisms = spf_record.split()

    for mechanism in mechanisms:

        mechanism = mechanism.strip()

        if mechanism.lower() == "v=spf1":
            continue

        qualifier = "+"

        if mechanism[0] in [
            "+",
            "-",
            "~",
            "?"
        ]:
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        if mechanism.startswith("ip4:"):

            network = mechanism[4:]

            try:
                if ip.version == 4 and ip in ipaddress.ip_network(
                    network,
                    strict=False
                ):
                    return {
                        "+": "pass",
                        "-": "fail",
                        "~": "softfail",
                        "?": "neutral"
                    }[qualifier]

            except ValueError:
                continue

        elif mechanism.startswith("ip6:"):

            network = mechanism[4:]

            try:
                if ip.version == 6 and ip in ipaddress.ip_network(
                    network,
                    strict=False
                ):
                    return {
                        "+": "pass",
                        "-": "fail",
                        "~": "softfail",
                        "?": "neutral"
                    }[qualifier]

            except ValueError:
                continue

        elif mechanism == "all":

            return {
                "+": "pass",
                "-": "fail",
                "~": "softfail",
                "?": "neutral"
            }[qualifier]

    return "neutral"

