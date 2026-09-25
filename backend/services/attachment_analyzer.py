import re


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".dll",
    ".msi",
    ".msp",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".jar",
    ".lnk",
    ".reg",
    ".iso",
    ".img"
}


MACRO_CAPABLE_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm"
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz"
}


def get_extension(filename: str):
    if not filename:
        return None

    filename = filename.strip().lower()

    match = re.search(
        r"(\.[a-z0-9]+)$",
        filename
    )

    if not match:
        return None

    return match.group(1)


def detect_double_extension(filename: str):
    if not filename:
        return False

    filename = filename.strip().lower()

    extensions = re.findall(
        r"\.[a-z0-9]+",
        filename
    )

    if len(extensions) < 2:
        return False

    dangerous_extensions = (
        DANGEROUS_EXTENSIONS
    )

    return (
        extensions[-1] in dangerous_extensions
        and extensions[-2] not in dangerous_extensions
    )


def analyze_attachment(filename: str):
    if not filename:
        return {
            "filename": filename,
            "status": "unknown",
            "extension": None,
            "reasons": []
        }

    extension = get_extension(filename)

    reasons = []

    if extension in DANGEROUS_EXTENSIONS:
        reasons.append(
            "dangerous_file_type"
        )

    if extension in MACRO_CAPABLE_EXTENSIONS:
        reasons.append(
            "macro_enabled_document"
        )

    if extension in ARCHIVE_EXTENSIONS:
        reasons.append(
            "archive_file"
        )

    if detect_double_extension(filename):
        reasons.append(
            "double_extension"
        )

    if reasons:
        status = "suspicious"
    else:
        status = "normal"

    return {
        "filename": filename,
        "extension": extension,
        "status": status,
        "reasons": reasons
    }


def analyze_attachments(attachments: list):
    results = []

    for filename in attachments:
        results.append(
            analyze_attachment(filename)
        )

    suspicious_count = sum(
        1
        for result in results
        if result["status"] == "suspicious"
    )

    return {
        "total_attachments": len(attachments),
        "suspicious_attachments": suspicious_count,
        "attachments": results
    }

