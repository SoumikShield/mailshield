import os

import requests

from dotenv import load_dotenv


load_dotenv()


URLHAUS_API_URL = (
    "https://urlhaus-api.abuse.ch/v1/url/"
)


def check_urlhaus(url: str):

    auth_key = os.getenv(
        "URLHAUS_AUTH_KEY"
    )

    if not auth_key:

        return {
            "status": "not_configured",
            "url": url,
            "malicious": False,
            "message": "URLhaus API key is not configured"
        }

    if not url:

        return {
            "status": "invalid",
            "url": url,
            "malicious": False
        }

    headers = {
        "Auth-Key": auth_key
    }

    data = {
        "url": url
    }

    try:

        response = requests.post(
            URLHAUS_API_URL,
            headers=headers,
            data=data,
            timeout=10
        )

        if response.status_code != 200:

            return {
                "status": "api_error",
                "url": url,
                "malicious": False,
                "http_status": response.status_code
            }

        result = response.json()

        query_status = result.get(
            "query_status"
        )

        if query_status == "no_results":

            return {
                "status": "not_found",
                "url": url,
                "malicious": False,
                "query_status": query_status
            }

        if query_status == "invalid_url":

            return {
                "status": "invalid",
                "url": url,
                "malicious": False,
                "query_status": query_status
            }

        return {
            "status": "found",
            "url": url,
            "malicious": True,
            "query_status": query_status,
            "url_status": result.get(
                "url_status"
            ),
            "threat": result.get(
                "threat"
            ),
            "tags": result.get(
                "tags",
                []
            ),
            "date_added": result.get(
                "date_added"
            ),
            "reporter": result.get(
                "reporter"
            )
        }

    except requests.Timeout:

        return {
            "status": "timeout",
            "url": url,
            "malicious": False
        }

    except requests.RequestException as e:

        return {
            "status": "connection_error",
            "url": url,
            "malicious": False,
            "error": str(e)
        }

    except ValueError:

        return {
            "status": "invalid_response",
            "url": url,
            "malicious": False
        }


def check_urls_with_urlhaus(
    urls: list
):

    results = []

    for url in urls:

        result = check_urlhaus(
            url
        )

        results.append(
            result
        )

    malicious_count = sum(
        1
        for result in results
        if result["malicious"]
    )

    return {
        "source": "URLhaus",
        "total_urls": len(urls),
        "malicious_urls": malicious_count,
        "results": results
    }
