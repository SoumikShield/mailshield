def add_signal(
    signals: list,
    score: int,
    category: str,
    reason: str
):
    signals.append({
        "category": category,
        "score": score,
        "reason": reason
    })


def calculate_risk(
    spf: dict | None,
    dkim: dict | None,
    dkim_verification: dict | None,
    dmarc_alignment: dict | None,
    sender_analysis: dict | None,
    url_analysis: dict | None,
    attachment_analysis: dict | None = None
):
    signals = []

    # ---------------------------------
    # SPF
    # ---------------------------------

    if spf:

        spf_result = spf.get(
            "result"
        )

        if spf_result == "fail":

            add_signal(
                signals,
                25,
                "SPF",
                "SPF authentication failed"
            )

        elif spf_result == "softfail":

            add_signal(
                signals,
                15,
                "SPF",
                "SPF returned softfail"
            )

        elif spf_result == "neutral":

            add_signal(
                signals,
                5,
                "SPF",
                "SPF result was neutral"
            )

    # ---------------------------------
    # DKIM
    # ---------------------------------

    if dkim_verification:

        dkim_status = dkim_verification.get(
            "status"
        )

        if dkim_status == "fail":

            add_signal(
                signals,
                20,
                "DKIM",
                "DKIM cryptographic verification failed"
            )

        elif dkim_status == "error":

            add_signal(
                signals,
                10,
                "DKIM",
                "DKIM verification encountered an error"
            )

    # ---------------------------------
    # DMARC
    # ---------------------------------

    if dmarc_alignment:

        dmarc_result = dmarc_alignment.get(
            "dmarc_result"
        )

        if dmarc_result == "fail":

            add_signal(
                signals,
                25,
                "DMARC",
                "DMARC authentication or alignment failed"
            )

    # ---------------------------------
    # SENDER ANALYSIS
    # ---------------------------------

    if sender_analysis:

        if sender_analysis.get(
            "status"
        ) == "suspicious":

            reason = sender_analysis.get(
                "reason",
                "Suspicious sender characteristics detected"
            )

            add_signal(
                signals,
                20,
                "SENDER",
                reason
            )

        lookalike = sender_analysis.get(
            "lookalike_domain",
            {}
        )

        if lookalike.get(
            "detected"
        ):

            brand = lookalike.get(
                "matched_brand"
            )

            if brand:

                reason = (
                    f"Possible {brand} "
                    "lookalike domain detected"
                )

            else:

                reason = (
                    "Possible lookalike domain detected"
                )

            add_signal(
                signals,
                30,
                "SENDER",
                reason
            )

        if sender_analysis.get(
            "display_name_suspicious"
        ):

            add_signal(
                signals,
                20,
                "SENDER",
                "Suspicious display-name impersonation detected"
            )

    # ---------------------------------
    # URL ANALYSIS
    # ---------------------------------

    if url_analysis:

        suspicious_urls = url_analysis.get(
            "suspicious_urls",
            0
        )

        if suspicious_urls > 0:

            url_score = min(
                suspicious_urls * 15,
                45
            )

            add_signal(
                signals,
                url_score,
                "URL",
                f"{suspicious_urls} suspicious URL(s) detected"
            )

        for url in url_analysis.get(
            "urls",
            []
        ):

            reasons = url.get(
                "reasons",
                []
            )

            if "url_shortener" in reasons:

                add_signal(
                    signals,
                    10,
                    "URL",
                    "URL shortener detected"
                )

                break

    # ---------------------------------
    # ATTACHMENT ANALYSIS
    # ---------------------------------

    if attachment_analysis:

        suspicious_attachments = attachment_analysis.get(
            "suspicious_attachments",
            0
        )

        if suspicious_attachments > 0:

            attachment_score = min(
                suspicious_attachments * 20,
                40
            )

            add_signal(
                signals,
                attachment_score,
                "ATTACHMENT",
                f"{suspicious_attachments} suspicious attachment(s) detected"
            )

        dangerous_file_detected = False
        double_extension_detected = False
        macro_document_detected = False
        archive_detected = False

        for attachment in attachment_analysis.get(
            "attachments",
            []
        ):

            reasons = attachment.get(
                "reasons",
                []
            )

            if "dangerous_file_type" in reasons:

                dangerous_file_detected = True

            if "double_extension" in reasons:

                double_extension_detected = True

            if "macro_enabled_document" in reasons:

                macro_document_detected = True

            if "archive_file" in reasons:

                archive_detected = True

        if dangerous_file_detected:

            add_signal(
                signals,
                30,
                "ATTACHMENT",
                "Potentially dangerous executable or script attachment detected"
            )

        if double_extension_detected:

            add_signal(
                signals,
                25,
                "ATTACHMENT",
                "Suspicious double-extension attachment detected"
            )

        if macro_document_detected:

            add_signal(
                signals,
                15,
                "ATTACHMENT",
                "Macro-enabled document attachment detected"
            )

        if archive_detected:

            add_signal(
                signals,
                5,
                "ATTACHMENT",
                "Archive attachment detected"
            )

    # ---------------------------------
    # CALCULATE SCORE
    # ---------------------------------

    raw_score = sum(
        signal["score"]
        for signal in signals
    )

    risk_score = min(
        raw_score,
        100
    )

    # ---------------------------------
    # RISK LEVEL
    # ---------------------------------

    if risk_score >= 75:

        risk_level = "critical"

    elif risk_score >= 50:

        risk_level = "high"

    elif risk_score >= 25:

        risk_level = "medium"

    else:

        risk_level = "low"

    # ---------------------------------
    # DISPOSITION
    # ---------------------------------

    if risk_score >= 75:

        disposition = "malicious"

    elif risk_score >= 25:

        disposition = "suspicious"

    else:

        disposition = "safe"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "disposition": disposition,
        "signals": signals,
        "signal_count": len(signals)
    }