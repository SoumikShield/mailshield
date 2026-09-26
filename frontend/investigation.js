const API_BASE = "https://mailshield-backend-cvev.onrender.com";


// ========================================
// HELPERS
// ========================================

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.textContent =
        value === null ||
        value === undefined ||
        value === ""
            ? "—"
            : value;
}


function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function getEmailId() {

    const params =
        new URLSearchParams(
            window.location.search
        );

    return params.get("id");
}


function getResultClass(result) {

    if (!result) {
        return "result-neutral";
    }

    const normalized =
        String(result).toLowerCase();


    if (
        normalized === "pass" ||
        normalized === "safe"
    ) {
        return "result-pass";
    }


    if (
        normalized === "fail" ||
        normalized === "suspicious" ||
        normalized === "malicious"
    ) {
        return "result-fail";
    }


    if (
        normalized === "softfail" ||
        normalized === "neutral" ||
        normalized === "medium"
    ) {
        return "result-warning";
    }


    return "result-neutral";
}


function getRiskClass(value) {

    const normalized =
        String(value || "")
            .toLowerCase();


    if (
        normalized === "safe" ||
        normalized === "low"
    ) {
        return "risk-safe";
    }


    if (
        normalized === "suspicious" ||
        normalized === "medium"
    ) {
        return "risk-warning";
    }


    if (
        normalized === "high"
    ) {
        return "risk-high-text";
    }


    if (
        normalized === "malicious" ||
        normalized === "critical"
    ) {
        return "risk-danger";
    }


    return "risk-neutral";
}


function setResult(
    elementId,
    result
) {

    const element =
        document.getElementById(
            elementId
        );

    if (!element) {
        return;
    }


    element.textContent =
        result || "unknown";


    element.className =
        "auth-result " +
        getResultClass(result);
}


// ========================================
// PAGE STATE
// ========================================

function showLoading() {

    document.getElementById(
        "loadingState"
    ).style.display = "flex";

    document.getElementById(
        "investigationContent"
    ).style.display = "none";

    document.getElementById(
        "errorState"
    ).style.display = "none";
}


function showContent() {

    document.getElementById(
        "loadingState"
    ).style.display = "none";

    document.getElementById(
        "investigationContent"
    ).style.display = "block";

    document.getElementById(
        "errorState"
    ).style.display = "none";
}


function showError(message) {

    document.getElementById(
        "loadingState"
    ).style.display = "none";

    document.getElementById(
        "investigationContent"
    ).style.display = "none";

    document.getElementById(
        "errorState"
    ).style.display = "flex";

    setText(
        "errorMessage",
        message
    );
}


// ========================================
// RISK
// ========================================

function renderRiskAnalysis(
    risk
) {

    if (!risk) {
        return;
    }


    const score =
        Number(
            risk.risk_score || 0
        );


    setText(
        "riskScore",
        score
    );


    const riskBar =
        document.getElementById(
            "riskBar"
        );


    if (riskBar) {

        riskBar.style.width =
            `${Math.min(score, 100)}%`;


        if (score >= 75) {

            riskBar.className =
                "risk-bar risk-critical";

        } else if (score >= 50) {

            riskBar.className =
                "risk-bar risk-high";

        } else if (score >= 25) {

            riskBar.className =
                "risk-bar risk-medium";

        } else {

            riskBar.className =
                "risk-bar risk-low";
        }
    }


    const level =
        risk.risk_level ||
        "unknown";


    const levelElement =
        document.getElementById(
            "riskLevel"
        );


    levelElement.textContent =
        level.toUpperCase();


    levelElement.className =
        "risk-level " +
        getRiskClass(level);


    const disposition =
        risk.disposition ||
        "unknown";


    const dispositionElement =
        document.getElementById(
            "riskDisposition"
        );


    dispositionElement.textContent =
        disposition.toUpperCase();


    dispositionElement.className =
        "risk-disposition " +
        getRiskClass(disposition);


    setText(
        "signalCount",
        risk.signal_count || 0
    );


    renderSignals(
        risk.signals || []
    );
}


// ========================================
// TIMELINE
// ========================================

function renderTimeline(
    data
) {

    const container =
        document.getElementById(
            "investigationTimeline"
        );


    if (!container) {
        return;
    }


    const risk =
        data.risk_analysis || {};


    const signals =
        risk.signals || [];


    const spf =
        data.spf || {};


    const dkim =
        data.dkim_verification || {};


    const dmarc =
        data.dmarc_alignment || {};


    const sender =
        data.sender_analysis || {};


    const urlAnalysis =
        data.url_analysis || {};


    const attachmentAnalysis =
        data.attachment_analysis || {};


    const timeline = [];


    // -------------------------------
    // EMAIL
    // -------------------------------

    timeline.push({
        title: "Email Received",
        description:
            "MailShield parsed the email structure and security headers.",
        status: "complete"
    });


    // -------------------------------
    // SENDER
    // -------------------------------

    timeline.push({
        title: "Sender Analysis",
        description:
            sender.reason ||
            "Sender identity and impersonation indicators analyzed.",
        status:
            sender.status === "suspicious"
                ? "warning"
                : "complete"
    });


    // -------------------------------
    // SPF
    // -------------------------------

    timeline.push({
        title: "SPF Authentication",
        description:
            spf.result
                ? `SPF result: ${spf.result}.`
                : "SPF authentication was not available.",
        status:
            spf.result === "fail"
                ? "danger"
                : spf.result === "softfail"
                    ? "warning"
                    : "complete"
    });


    // -------------------------------
    // DKIM
    // -------------------------------

    timeline.push({
        title: "DKIM Verification",
        description:
            dkim.status
                ? `DKIM verification: ${dkim.status}.`
                : "DKIM verification was not available.",
        status:
            dkim.status === "fail"
                ? "danger"
                : dkim.status === "error"
                    ? "warning"
                    : "complete"
    });


    // -------------------------------
    // DMARC
    // -------------------------------

    timeline.push({
        title: "DMARC Alignment",
        description:
            dmarc.dmarc_result
                ? `DMARC result: ${dmarc.dmarc_result}.`
                : "DMARC alignment was not available.",
        status:
            dmarc.dmarc_result === "fail"
                ? "danger"
                : "complete"
    });


    // -------------------------------
    // URL
    // -------------------------------

    timeline.push({
        title: "URL Intelligence",
        description:
            `${urlAnalysis.suspicious_urls || 0} suspicious URL(s) detected from ${urlAnalysis.total_urls || 0} URL(s).`,
        status:
            (urlAnalysis.suspicious_urls || 0) > 0
                ? "warning"
                : "complete"
    });


    // -------------------------------
    // ATTACHMENTS
    // -------------------------------

    const attachmentCount =
        attachmentAnalysis.suspicious_attachments || 0;

    const totalAttachments =
        attachmentAnalysis.total_attachments || 0;

    timeline.push({
        title: "Attachment Analysis",
        description:
            `${attachmentCount} suspicious attachment(s) detected from ${totalAttachments} attachment(s).`,
        status:
            attachmentCount > 0
                ? "warning"
                : "complete"
    });


    // -------------------------------
    // RISK ENGINE
    // -------------------------------

    timeline.push({
        title: "Risk Engine",
        description:
            `Generated a risk score of ${risk.risk_score || 0} using ${risk.signal_count || signals.length} detection signal(s).`,
        status:
            (risk.risk_score || 0) >= 75
                ? "danger"
                : (risk.risk_score || 0) >= 25
                    ? "warning"
                    : "complete"
    });


    // -------------------------------
    // FINAL
    // -------------------------------

    timeline.push({
        title: "Final Disposition",
        description:
            `Email classified as ${(risk.disposition || "unknown").toUpperCase()}.`,
        status:
            risk.disposition === "malicious"
                ? "danger"
                : risk.disposition === "suspicious"
                    ? "warning"
                    : "complete"
    });


    container.innerHTML =
        timeline.map(
            (item, index) => `

                <div class="timeline-item">

                    <div
                        class="timeline-marker ${item.status}"
                    >
                        ${String(
                            index + 1
                        ).padStart(2, "0")}
                    </div>


                    <div class="timeline-content">

                        <strong>
                            ${escapeHtml(
                                item.title
                            )}
                        </strong>

                        <span>
                            ${escapeHtml(
                                item.description
                            )}
                        </span>

                    </div>

                </div>

            `
        ).join("");
}


// ========================================
// SIGNALS
// ========================================

function renderSignals(
    signals
) {

    const container =
        document.getElementById(
            "signalList"
        );


    if (!signals.length) {

        container.innerHTML = `

            <div class="empty-state">
                No risk signals detected.
            </div>

        `;

        return;
    }


    container.innerHTML =
        signals.map(
            signal => `

                <div class="signal-item">

                    <div class="signal-category">

                        ${escapeHtml(
                            signal.category
                        )}

                    </div>


                    <div class="signal-details">

                        <strong>
                            ${escapeHtml(
                                signal.reason
                            )}
                        </strong>

                        <span>
                            Contributed
                            +${escapeHtml(
                                signal.score
                            )}
                            risk points
                        </span>

                    </div>


                    <div class="signal-score">

                        +${escapeHtml(
                            signal.score
                        )}

                    </div>

                </div>

            `
        ).join("");
}


// ========================================
// MESSAGE
// ========================================

function renderMessage(
    data
) {

    const email =
        data.email || {};


    setText(
        "emailSubject",
        email.subject
    );


    setText(
        "emailFilename",
        data.filename
    );


    setText(
        "fromValue",
        email.from
    );


    setText(
        "toValue",
        email.to
    );


    setText(
        "replyToValue",
        email.reply_to
    );


    setText(
        "dateValue",
        email.date
    );


    setText(
        "messageIdValue",
        email.security_headers?.message_id
    );


    const statusElement =
        document.getElementById(
            "emailStatus"
        );


    const status =
        data.status ||
        "analyzed";


    statusElement.textContent =
        status.toUpperCase();


    statusElement.className =
        "status-badge " +
        getResultClass(status);
}


// ========================================
// SPF
// ========================================

function renderSpf(
    spf
) {

    if (!spf) {

        setResult(
            "spfResult",
            "unknown"
        );

        return;
    }


    setResult(
        "spfResult",
        spf.result
    );


    setText(
        "spfDomain",
        spf.domain
    );


    setText(
        "spfIp",
        spf.sending_ip
    );


    setText(
        "spfRecordStatus",
        spf.record_status
    );
}


// ========================================
// DKIM
// ========================================

function renderDkim(
    dkim,
    verification
) {

    if (!dkim) {

        setResult(
            "dkimResult",
            "unknown"
        );

        return;
    }


    const result =
        verification?.verified
            ? "pass"
            : verification?.status ||
              "fail";


    setResult(
        "dkimResult",
        result
    );


    setText(
        "dkimDomain",
        dkim.domain
    );


    setText(
        "dkimSelector",
        dkim.selector
    );


    setText(
        "dkimAlgorithm",
        dkim.algorithm
    );


    setText(
        "dkimVerified",
        verification?.verified
            ? "Verified"
            : "Not Verified"
    );
}


// ========================================
// DMARC
// ========================================

function renderDmarc(
    alignment
) {

    if (!alignment) {

        setResult(
            "dmarcResult",
            "unknown"
        );

        return;
    }


    setResult(
        "dmarcResult",
        alignment.dmarc_result
    );


    setText(
        "dmarcDomain",
        alignment.from_domain
    );


    setText(
        "dmarcSpfAlignment",
        alignment.spf?.aligned
            ? "Aligned"
            : "Not Aligned"
    );


    setText(
        "dmarcDkimAlignment",
        alignment.dkim?.aligned
            ? "Aligned"
            : "Not Aligned"
    );
}


// ========================================
// SENDER
// ========================================

function renderSender(
    analysis
) {

    if (!analysis) {
        return;
    }


    const statusElement =
        document.getElementById(
            "senderStatus"
        );


    statusElement.textContent =
        analysis.reason ||
        analysis.status ||
        "Unknown";


    statusElement.className =
        "analysis-banner " +
        getResultClass(
            analysis.status
        );


    setText(
        "senderFromDomain",
        analysis.from_domain
    );


    setText(
        "senderReplyDomain",
        analysis.reply_to_domain
    );


    setText(
        "senderDomainMatch",
        analysis.domain_match === true
            ? "Yes"
            : analysis.domain_match === false
                ? "No"
                : "N/A"
    );


    setText(
        "senderDisplayName",
        analysis.display_name
    );


    const lookalike =
        analysis.lookalike_domain;


    if (lookalike) {

        setText(
            "lookalikeDetection",
            lookalike.detected
                ? "Detected"
                : "Not Detected"
        );


        setText(
            "matchedBrand",
            lookalike.matched_brand
        );

    }
}


// ========================================
// URLS
// ========================================

function renderUrls(
    analysis
) {

    if (!analysis) {
        return;
    }


    setText(
        "totalUrls",
        analysis.total_urls
    );


    setText(
        "suspiciousUrls",
        analysis.suspicious_urls
    );


    const container =
        document.getElementById(
            "urlList"
        );


    const urls =
        analysis.urls || [];


    if (!urls.length) {

        container.innerHTML = `

            <div class="empty-state">
                No URLs detected.
            </div>

        `;

        return;
    }


    container.innerHTML =
        urls.map(
            url => {

                const reasons =
                    url.reasons || [];


                return `

                    <div class="url-item">

                        <div class="url-main">

                            <div class="url-status ${
                                getResultClass(
                                    url.status
                                )
                            }">

                                ${escapeHtml(
                                    url.status
                                )}

                            </div>

                            <div class="url-value">

                                ${escapeHtml(
                                    url.url
                                )}

                            </div>

                        </div>


                        <div class="url-meta">

                            <span>
                                ${escapeHtml(
                                    url.domain
                                )}
                            </span>

                            <span>
                                ${
                                    reasons.length
                                        ? escapeHtml(
                                            reasons.join(
                                                ", "
                                            )
                                        )
                                        : "No indicators"
                                }
                            </span>

                        </div>

                    </div>

                `;
            }
        ).join("");
}


// ========================================
// ATTACHMENTS
// ========================================

function renderAttachments(
    analysis
) {

    const container =
        document.getElementById(
            "attachmentList"
        );


    if (!container) {
        return;
    }


    /*
     * Backward compatibility:
     *
     * Older MongoDB records contain:
     *
     * data.email.attachments
     *
     * as a simple array.
     *
     * New records contain:
     *
     * data.attachment_analysis
     *
     * as an analysis object.
     */

    if (Array.isArray(analysis)) {

        if (!analysis.length) {

            container.innerHTML = `

                <div class="empty-state">
                    No attachments detected.
                </div>

            `;

            return;
        }


        container.innerHTML =
            analysis.map(
                attachment => `

                    <div class="attachment-item">

                        <span class="attachment-icon">
                            FILE
                        </span>

                        <span>
                            ${escapeHtml(
                                attachment
                            )}
                        </span>

                    </div>

                `
            ).join("");

        return;
    }


    if (!analysis) {

        container.innerHTML = `

            <div class="empty-state">
                No attachments detected.
            </div>

        `;

        return;
    }


    const attachments =
        analysis.attachments || [];


    if (!attachments.length) {

        container.innerHTML = `

            <div class="empty-state">
                No attachments detected.
            </div>

        `;

        return;
    }


    container.innerHTML = `

        <div class="attachment-summary">

            <div class="attachment-stat">

                <span>
                    TOTAL
                </span>

                <strong>
                    ${escapeHtml(
                        analysis.total_attachments || 0
                    )}
                </strong>

            </div>


            <div class="attachment-stat">

                <span>
                    SUSPICIOUS
                </span>

                <strong>
                    ${escapeHtml(
                        analysis.suspicious_attachments || 0
                    )}
                </strong>

            </div>

        </div>


        <div class="attachment-results">

            ${
                attachments.map(
                    attachment => {

                        const reasons =
                            attachment.reasons || [];

                        const status =
                            attachment.status ||
                            "unknown";

                        return `

                            <div class="attachment-item">

                                <span class="attachment-icon">
                                    FILE
                                </span>


                                <div class="attachment-details">

                                    <strong>
                                        ${escapeHtml(
                                            attachment.filename
                                        )}
                                    </strong>

                                    <span>
                                        Extension:
                                        ${escapeHtml(
                                            attachment.extension ||
                                            "unknown"
                                        )}
                                    </span>


                                    ${
                                        reasons.length
                                            ? `
                                                <div class="attachment-reasons">

                                                    ${reasons.map(
                                                        reason => `
                                                            <span>
                                                                ${escapeHtml(
                                                                    reason
                                                                )}
                                                            </span>
                                                        `
                                                    ).join("")}

                                                </div>
                                            `
                                            : `
                                                <div class="attachment-reasons">
                                                    <span>
                                                        No suspicious indicators
                                                    </span>
                                                </div>
                                            `
                                    }

                                </div>


                                <span
                                    class="attachment-status ${getResultClass(
                                        status
                                    )}"
                                >
                                    ${escapeHtml(
                                        status
                                    )}
                                </span>

                            </div>

                        `;
                    }
                ).join("")
            }

        </div>

    `;
}


// ========================================
// HEADERS
// ========================================

function renderHeaders(
    headers
) {

    const element =
        document.getElementById(
            "securityHeaders"
        );


    if (!headers) {

        element.textContent =
            "No security headers available.";

        return;
    }


    element.textContent =
        JSON.stringify(
            headers,
            null,
            2
        );
}


// ========================================
// BODY
// ========================================

function renderBody(
    body
) {

    const element =
        document.getElementById(
            "emailBody"
        );


    element.textContent =
        body ||
        "No message body available.";
}


// ========================================
// LOAD INVESTIGATION
// ========================================

async function loadInvestigation() {

    const emailId =
        getEmailId();


    if (!emailId) {

        showError(
            "No email ID was provided."
        );

        return;
    }


    showLoading();


    try {

        const response =
            await fetch(
                `${API_BASE}/emails/${encodeURIComponent(
                    emailId
                )}`
            );


        if (!response.ok) {

            let message =
                "Unable to load email.";

            try {

                const error =
                    await response.json();

                message =
                    error.detail ||
                    message;

            } catch {
                // Ignore JSON parsing errors.
            }


            throw new Error(
                message
            );
        }


        const data =
            await response.json();


        renderMessage(
            data
        );


        renderRiskAnalysis(
            data.risk_analysis
        );


        renderTimeline(
            data
        );


        renderSpf(
            data.spf
        );


        renderDkim(
            data.dkim,
            data.dkim_verification
        );


        renderDmarc(
            data.dmarc_alignment
        );


        renderSender(
            data.sender_analysis
        );


        renderUrls(
            data.url_analysis
        );


        /*
         * NEW BACKEND STRUCTURE
         *
         * Attachment analysis is now stored
         * separately from the raw attachment list.
         */
        renderAttachments(
            data.attachment_analysis ||
            data.email?.attachments
        );


        renderHeaders(
            data.email?.security_headers
        );


        renderBody(
            data.email?.body
        );


        showContent();

    } catch (error) {

        console.error(
            "Investigation error:",
            error
        );


        showError(
            error.message ||
            "Unable to load investigation."
        );
    }
}


// ========================================
// START
// ========================================

document.addEventListener(
    "DOMContentLoaded",
    loadInvestigation
);