import re

from email import policy
from email.parser import BytesParser


def extract_urls(text: str):

    url_pattern = r'https?://[^\s<>"\']+'

    return re.findall(
        url_pattern,
        text
    )


def extract_ips(text: str):

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    return re.findall(
        ip_pattern,
        text
    )


def extract_domains(urls: list):

    domains = []

    for url in urls:

        domain_match = re.search(
            r'https?://([^/:]+)',
            url
        )

        if domain_match:

            domain = domain_match.group(1)

            if domain not in domains:
                domains.append(domain)

    return domains


def parse_email(content: bytes):

    message = BytesParser(
        policy=policy.default
    ).parsebytes(content)

    body = ""
    attachments = []

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if disposition == "attachment":

                filename = part.get_filename()

                if filename:
                    attachments.append(filename)

            elif content_type == "text/plain" and not body:

                body = part.get_content()

    else:

        body = message.get_content()

    urls = extract_urls(body)

    ips = extract_ips(body)

    domains = extract_domains(urls)

    security_headers = {
        "authentication_results": message.get(
            "Authentication-Results"
        ),
        "received": message.get_all(
            "Received",
            []
        ),
        "return_path": message.get(
            "Return-Path"
        ),
        "message_id": message.get(
            "Message-ID"
        ),
        "x_originating_ip": message.get(
            "X-Originating-IP"
        ),
        "dkim_signature": message.get(
            "DKIM-Signature"
        )
    }

    return {
        "from": message.get("From"),
        "to": message.get("To"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "reply_to": message.get("Reply-To"),
        "body": body,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "attachments": attachments,
        "security_headers": security_headers
    }