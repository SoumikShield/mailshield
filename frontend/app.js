const API_BASE = "https://mailshield-backend-cvev.onrender.com";

// ========================================
// DOM ELEMENTS
// ========================================

const totalEmailsElement =
    document.getElementById("totalEmails");

const safeEmailsElement =
    document.getElementById("safeEmails");

const suspiciousEmailsElement =
    document.getElementById("suspiciousEmails");

const maliciousEmailsElement =
    document.getElementById("maliciousEmails");

const recentInvestigationsElement =
    document.getElementById("investigationTable");

const highRiskActivityElement =
    document.getElementById("highRiskActivity");

const threatChartElement =
    document.getElementById("threatDonut");

const threatLegendElement =
    document.getElementById("safeLegend");

const uploadEmailButton =
    document.getElementById("uploadEmailButton");

const emailFileInput =
    document.getElementById("emailFileInput");


// ========================================
// HELPERS
// ========================================

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


function formatDisposition(
    disposition
) {

    if (!disposition) {
        return "UNKNOWN";
    }

    return String(disposition)
        .toUpperCase();
}


function getRiskClass(
    value
) {

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


function formatDate(
    value
) {

    if (!value) {
        return "—";
    }


    try {

        const date =
            new Date(value);


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return value;
        }


        return date.toLocaleString(
            [],
            {
                dateStyle: "medium",
                timeStyle: "short"
            }
        );

    } catch {

        return value;
    }
}


// ========================================
// KPI CARDS
// ========================================

function updateKpis(
    data
) {

    const counts =
        data.disposition_counts || {};


    totalEmailsElement.textContent =
        data.total_emails || 0;


    safeEmailsElement.textContent =
        counts.safe || 0;


    suspiciousEmailsElement.textContent =
        counts.suspicious || 0;


    maliciousEmailsElement.textContent =
        counts.malicious || 0;
}


// ========================================
// THREAT DISTRIBUTION
// ========================================

function renderThreatDistribution(
    data
) {

    const counts =
        data.disposition_counts || {};


    const safe =
        counts.safe || 0;

    const suspicious =
        counts.suspicious || 0;

    const malicious =
        counts.malicious || 0;


    const total =
        safe +
        suspicious +
        malicious;


    if (!total) {

        threatChartElement.style.background =
            "conic-gradient(rgba(255,255,255,0.08) 0deg 360deg)";

        threatLegendElement.innerHTML = `

            <div class="legend-empty">
                No analyzed emails yet.
            </div>

        `;

        return;
    }


    const safeDegrees =
        (safe / total) * 360;


    const suspiciousDegrees =
        (suspicious / total) * 360;


    const maliciousDegrees =
        (malicious / total) * 360;


    document.getElementById("threatDonut").style.background =
        `
        conic-gradient(
            var(--safe) 0deg ${safeDegrees}deg,
            var(--warning)
                ${safeDegrees}deg
                ${safeDegrees + suspiciousDegrees}deg,
            var(--danger)
                ${safeDegrees + suspiciousDegrees}deg
                ${safeDegrees + suspiciousDegrees + maliciousDegrees}deg
        )
        `;


    threatLegendElement.innerHTML = `

        <div class="legend-item">

            <span class="legend-dot safe-dot"></span>

            <div>
                <strong>${safe}</strong>
                <span>Safe</span>
            </div>

        </div>


        <div class="legend-item">

            <span class="legend-dot warning-dot"></span>

            <div>
                <strong>${suspicious}</strong>
                <span>Suspicious</span>
            </div>

        </div>


        <div class="legend-item">

            <span class="legend-dot danger-dot"></span>

            <div>
                <strong>${malicious}</strong>
                <span>Malicious</span>
            </div>

        </div>

    `;
}


// ========================================
// HIGH RISK ACTIVITY
// ========================================

function renderHighRiskActivity(
    emails
) {

    if (!highRiskActivityElement) {
        return;
    }


    if (
        !emails ||
        !emails.length
    ) {

        highRiskActivityElement.innerHTML = `

            <div class="panel-empty">

                <div class="empty-icon">
                    ✓
                </div>

                <strong>
                    No high-risk activity
                </strong>

                <span>
                    No analyzed email currently has
                    a risk score of 50 or higher.
                </span>

            </div>

        `;

        return;
    }


    highRiskActivityElement.innerHTML =
        emails.map(
            email => {

                const score =
                    email.risk_score || 0;


                const level =
                    email.risk_level ||
                    "unknown";


                const disposition =
                    email.disposition ||
                    "unknown";


                return `

                    <div
                        class="high-risk-item"
                        data-email-id="${escapeHtml(
                            email.id
                        )}"
                        tabindex="0"
                        role="button"
                    >

                        <div class="high-risk-score">

                            <strong>
                                ${escapeHtml(score)}
                            </strong>

                            <span>
                                RISK
                            </span>

                        </div>


                        <div class="high-risk-details">

                            <strong>
                                ${escapeHtml(
                                    email.subject ||
                                    "(No subject)"
                                )}
                            </strong>

                            <span>
                                ${escapeHtml(
                                    email.from ||
                                    "Unknown sender"
                                )}
                            </span>

                        </div>


                        <div
                            class="high-risk-status ${getRiskClass(
                                disposition
                            )}"
                        >

                            ${escapeHtml(
                                formatDisposition(
                                    disposition
                                )
                            )}

                            <small>
                                ${escapeHtml(
                                    level
                                )}
                            </small>

                        </div>

                    </div>

                `;
            }
        ).join("");


    document
        .querySelectorAll(
            ".high-risk-item"
        )
        .forEach(
            item => {

                const emailId =
                    item.dataset.emailId;


                item.addEventListener(
                    "click",
                    () => {

                        window.location.href =
                            `investigation.html?id=${encodeURIComponent(
                                emailId
                            )}`;

                    }
                );


                item.addEventListener(
                    "keydown",
                    event => {

                        if (
                            event.key === "Enter" ||
                            event.key === " "
                        ) {

                            event.preventDefault();

                            item.click();

                        }

                    }
                );

            }
        );
}


// ========================================
// RECENT INVESTIGATIONS
// ========================================

function renderRecentInvestigations(
    emails
) {

    if (
        !emails ||
        !emails.length
    ) {

        recentInvestigationsElement.innerHTML = `

            <div class="table-empty">
                No investigations available.
            </div>

        `;

        return;
    }


    recentInvestigationsElement.innerHTML =
        emails.map(
            email => {

                const score =
                    email.risk_score ?? 0;


                const disposition =
                    email.disposition ||
                    "unknown";


                const level =
                    email.risk_level ||
                    "unknown";


                return `

                    <div
                        class="investigation-row"
                        data-email-id="${escapeHtml(
                            email.id
                        )}"
                        tabindex="0"
                        role="button"
                    >

                        <div class="investigation-subject">

                            <strong>
                                ${escapeHtml(
                                    email.subject ||
                                    "(No subject)"
                                )}
                            </strong>

                            <span>
                                ${escapeHtml(
                                    email.from ||
                                    "Unknown sender"
                                )}
                            </span>

                        </div>


                        <div class="investigation-disposition">

                            <span
                                class="${getRiskClass(
                                    disposition
                                )}"
                            >
                                ${escapeHtml(
                                    formatDisposition(
                                        disposition
                                    )
                                )}
                            </span>

                        </div>


                        <div class="investigation-risk">

                            <strong>
                                ${escapeHtml(score)}
                            </strong>

                            <span>
                                ${escapeHtml(level)}
                            </span>

                        </div>


                        <div class="open-investigation">
                            Open →
                        </div>

                    </div>

                `;
            }
        ).join("");


    document
        .querySelectorAll(
            ".investigation-row"
        )
        .forEach(
            row => {

                const emailId =
                    row.dataset.emailId;


                row.addEventListener(
                    "click",
                    () => {

                        window.location.href =
                            `investigation.html?id=${encodeURIComponent(
                                emailId
                            )}`;

                    }
                );


                row.addEventListener(
                    "keydown",
                    event => {

                        if (
                            event.key === "Enter" ||
                            event.key === " "
                        ) {

                            event.preventDefault();

                            row.click();

                        }

                    }
                );

            }
        );
}


// ========================================
// LOAD DASHBOARD
// ========================================

async function loadDashboard() {

    try {

        const response =
            await fetch(
                `${API_BASE}/emails/dashboard/summary`
            );


        if (!response.ok) {

            throw new Error(
                `Dashboard API returned ${response.status}`
            );

        }


        const data =
            await response.json();


        updateKpis(
            data
        );


        renderThreatDistribution(
            data
        );


        renderHighRiskActivity(
            data.high_risk_emails || []
        );


        renderRecentInvestigations(
            data.recent_emails || []
        );


    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );


        if (highRiskActivityElement) {

            highRiskActivityElement.innerHTML = `

                <div class="panel-empty">

                    <div class="empty-icon">
                        !
                    </div>

                    <strong>
                        Dashboard data unavailable
                    </strong>

                    <span>
                        Unable to connect to the
                        MailShield API.
                    </span>

                </div>

            `;

        }


        recentInvestigationsElement.innerHTML = `

            <div class="table-empty">

                Unable to load investigations.

            </div>

        `;
    }
}


// ========================================
// EMAIL UPLOAD
// ========================================

function setupUpload() {

    if (
        !uploadEmailButton ||
        !emailFileInput
    ) {
        return;
    }


    uploadEmailButton.addEventListener(
        "click",
        () => {

            emailFileInput.click();

        }
    );


    emailFileInput.addEventListener(
        "change",
        async event => {

            const file =
                event.target.files[0];


            if (!file) {
                return;
            }


            if (
                !file.name
                    .toLowerCase()
                    .endsWith(".eml")
            ) {

                alert(
                    "Only .eml files are supported."
                );

                emailFileInput.value = "";

                return;
            }


            uploadEmailButton.disabled =
                true;


            uploadEmailButton.textContent =
                "Analyzing...";


            try {

                const formData =
                    new FormData();


                formData.append(
                    "file",
                    file
                );


                const response =
                    await fetch(
                        `${API_BASE}/emails/upload`,
                        {
                            method: "POST",
                            body: formData
                        }
                    );


                const result =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        result.detail ||
                        "Email upload failed."
                    );

                }


                if (
                    result.id
                ) {

                    window.location.href =
                        `investigation.html?id=${encodeURIComponent(
                            result.id
                        )}`;

                    return;
                }


                await loadDashboard();

            } catch (error) {

                console.error(
                    "Upload error:",
                    error
                );


                alert(
                    error.message ||
                    "Unable to upload email."
                );

            } finally {

                uploadEmailButton.disabled =
                    false;


                uploadEmailButton.textContent =
                    "Analyze Email";


                emailFileInput.value = "";

            }

        }
    );
}


// ========================================
// START
// ========================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadDashboard();

        setupUpload();

        setInterval(
            loadDashboard,
            30000
        );

    }
);