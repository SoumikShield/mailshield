const API_BASE =
    "https://mailshield-backend-cvev.onrender.com";


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

const threatDonutElement =
    document.getElementById("threatDonut");

const donutTotalElement =
    document.getElementById("donutTotal");

const safeLegendElement =
    document.getElementById("safeLegend");

const suspiciousLegendElement =
    document.getElementById("suspiciousLegend");

const maliciousLegendElement =
    document.getElementById("maliciousLegend");

const highRiskCountElement =
    document.getElementById("highRiskCount");

const investigationTableElement =
    document.getElementById("investigationTable");

const refreshButton =
    document.getElementById("refreshButton");

const uploadButton =
    document.getElementById("uploadButton");

const uploadModal =
    document.getElementById("uploadModal");

const closeModalButton =
    document.getElementById("closeModal");

const dropZone =
    document.getElementById("dropZone");

const emailFileInput =
    document.getElementById("emailFile");

const selectedFileElement =
    document.getElementById("selectedFile");

const analyzeSubmit =
    document.getElementById("analyzeSubmit");

const uploadResult =
    document.getElementById("uploadResult");


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


function formatDisposition(value) {

    if (!value) {
        return "UNKNOWN";
    }

    return String(value)
        .toUpperCase();
}


function getDispositionClass(value) {

    const normalized =
        String(value || "")
            .toLowerCase();

    if (normalized === "safe") {
        return "safe";
    }

    if (normalized === "suspicious") {
        return "suspicious";
    }

    if (normalized === "malicious") {
        return "malicious";
    }

    return "";
}


function getSeverityClass(value) {

    const normalized =
        String(value || "")
            .toLowerCase();

    if (
        normalized === "low" ||
        normalized === "safe"
    ) {
        return "severity-low";
    }

    if (
        normalized === "medium" ||
        normalized === "suspicious"
    ) {
        return "severity-medium";
    }

    if (
        normalized === "high" ||
        normalized === "critical" ||
        normalized === "malicious"
    ) {
        return "severity-critical";
    }

    return "severity-low";
}


// ========================================
// KPI CARDS
// ========================================

function updateKpis(data) {

    const counts =
        data.disposition_counts || {};

    totalEmailsElement.textContent =
        data.total_emails ?? 0;

    safeEmailsElement.textContent =
        counts.safe ?? 0;

    suspiciousEmailsElement.textContent =
        counts.suspicious ?? 0;

    maliciousEmailsElement.textContent =
        counts.malicious ?? 0;
}


// ========================================
// THREAT DISTRIBUTION
// ========================================

function renderThreatDistribution(data) {

    const counts =
        data.disposition_counts || {};

    const safe =
        counts.safe ?? 0;

    const suspicious =
        counts.suspicious ?? 0;

    const malicious =
        counts.malicious ?? 0;

    const total =
        safe +
        suspicious +
        malicious;

    if (donutTotalElement) {

        donutTotalElement.textContent =
            total;
    }

    if (safeLegendElement) {

        safeLegendElement.textContent =
            safe;
    }

    if (suspiciousLegendElement) {

        suspiciousLegendElement.textContent =
            suspicious;
    }

    if (maliciousLegendElement) {

        maliciousLegendElement.textContent =
            malicious;
    }

    if (!threatDonutElement) {
        return;
    }

    if (!total) {

        threatDonutElement.style.background =
            "conic-gradient(rgba(255,255,255,0.08) 0deg 360deg)";

        return;
    }

    const safeDegrees =
        (safe / total) * 360;

    const suspiciousDegrees =
        (suspicious / total) * 360;

    const maliciousStart =
        safeDegrees +
        suspiciousDegrees;

    threatDonutElement.style.background =
        `
        conic-gradient(
            var(--safe)
            0deg
            ${safeDegrees}deg,

            var(--warning)
            ${safeDegrees}deg
            ${maliciousStart}deg,

            var(--danger)
            ${maliciousStart}deg
            360deg
        )
        `;
}


// ========================================
// HIGH RISK ACTIVITY
// ========================================

function renderHighRiskActivity(emails) {

    if (!highRiskCountElement) {
        return;
    }

    highRiskCountElement.textContent =
        Array.isArray(emails)
            ? emails.length
            : 0;
}


// ========================================
// RECENT INVESTIGATIONS
// ========================================

function renderRecentInvestigations(emails) {

    if (!investigationTableElement) {
        return;
    }

    if (
        !Array.isArray(emails) ||
        emails.length === 0
    ) {

        investigationTableElement.innerHTML = `
            <tr>
                <td
                    colspan="5"
                    class="loading-row"
                >
                    No investigations available.
                </td>
            </tr>
        `;

        return;
    }

    investigationTableElement.innerHTML =
        emails.map(email => {

            const id =
                email.id || "";

            const level =
                email.risk_level || "low";

            const disposition =
                email.disposition || "unknown";

            const score =
                email.risk_score ?? 0;

            const severityClass =
                getSeverityClass(level);

            const dispositionClass =
                getDispositionClass(disposition);

            return `
                <tr
                    class="investigation-row"
                    data-email-id="${escapeHtml(id)}"
                    tabindex="0"
                >

                    <td>
                        <span
                            class="severity ${severityClass}"
                        >
                            <span
                                class="severity-dot"
                            ></span>

                            ${escapeHtml(
                                formatDisposition(level)
                            )}
                        </span>
                    </td>

                    <td class="email-cell">
                        <span class="email-sender">
                            ${escapeHtml(
                                email.from ||
                                "Unknown sender"
                            )}
                        </span>
                    </td>

                    <td class="subject-cell">
                        ${escapeHtml(
                            email.subject ||
                            "(No subject)"
                        )}
                    </td>

                    <td class="risk-score">
                        ${escapeHtml(score)}
                    </td>

                    <td>
                        <span
                            class="disposition ${dispositionClass}"
                        >
                            ${escapeHtml(
                                formatDisposition(
                                    disposition
                                )
                            )}
                        </span>
                    </td>

                </tr>
            `;
        }).join("");

    document
        .querySelectorAll(
            ".investigation-row"
        )
        .forEach(row => {

            const emailId =
                row.dataset.emailId;

            row.addEventListener(
                "click",
                () => {

                    if (!emailId) {
                        return;
                    }

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
        });
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

        updateKpis(data);

        renderThreatDistribution(data);

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

        if (totalEmailsElement) {
            totalEmailsElement.textContent = "—";
        }

        if (safeEmailsElement) {
            safeEmailsElement.textContent = "—";
        }

        if (suspiciousEmailsElement) {
            suspiciousEmailsElement.textContent = "—";
        }

        if (maliciousEmailsElement) {
            maliciousEmailsElement.textContent = "—";
        }

        if (highRiskCountElement) {
            highRiskCountElement.textContent = "—";
        }

        if (investigationTableElement) {

            investigationTableElement.innerHTML = `
                <tr>
                    <td
                        colspan="5"
                        class="loading-row"
                    >
                        Unable to load investigations.
                    </td>
                </tr>
            `;
        }
    }
}


// ========================================
// UPLOAD MODAL
// ========================================

function openUploadModal() {

    if (!uploadModal) {
        return;
    }

    uploadModal.classList.add("open");
}


function closeUploadModal() {

    if (!uploadModal) {
        return;
    }

    uploadModal.classList.remove("open");
}


function resetUploadState() {

    if (selectedFileElement) {

        selectedFileElement.textContent =
            "No file selected";
    }

    if (uploadResult) {

        uploadResult.textContent =
            "";
    }

    if (emailFileInput) {

        emailFileInput.value =
            "";
    }

    if (analyzeSubmit) {

        analyzeSubmit.disabled =
            true;

        analyzeSubmit.textContent =
            "Run Investigation";
    }
}


// ========================================
// FILE SELECTION
// ========================================

function handleFileSelection(file) {

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

        resetUploadState();

        return;
    }

    if (selectedFileElement) {

        selectedFileElement.textContent =
            file.name;
    }

    if (uploadResult) {

        uploadResult.textContent =
            "";
    }

    if (analyzeSubmit) {

        analyzeSubmit.disabled =
            false;
    }
}


// ========================================
// UPLOAD EMAIL
// ========================================

async function uploadEmail() {

    if (
        !emailFileInput ||
        !emailFileInput.files ||
        !emailFileInput.files.length
    ) {
        return;
    }

    const file =
        emailFileInput.files[0];

    if (
        !file.name
            .toLowerCase()
            .endsWith(".eml")
    ) {

        alert(
            "Only .eml files are supported."
        );

        return;
    }

    if (analyzeSubmit) {

        analyzeSubmit.disabled =
            true;

        analyzeSubmit.textContent =
            "Analyzing...";
    }

    if (uploadResult) {

        uploadResult.textContent =
            "Analyzing email...";
    }

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

        let result = {};

        try {

            result =
                await response.json();

        } catch {

            result = {};
        }

        if (!response.ok) {

            throw new Error(
                result.detail ||
                `Email upload failed (${response.status}).`
            );
        }

        if (result.id) {

            window.location.href =
                `investigation.html?id=${encodeURIComponent(
                    result.id
                )}`;

            return;
        }

        closeUploadModal();

        resetUploadState();

        await loadDashboard();

    } catch (error) {

        console.error(
            "Upload error:",
            error
        );

        if (uploadResult) {

            uploadResult.textContent =
                error.message ||
                "Unable to upload email.";
        }

    } finally {

        if (analyzeSubmit) {

            analyzeSubmit.disabled =
                !(
                    emailFileInput &&
                    emailFileInput.files &&
                    emailFileInput.files.length
                );

            analyzeSubmit.textContent =
                "Run Investigation";
        }
    }
}


// ========================================
// UPLOAD SETUP
// ========================================

function setupUpload() {

    if (uploadButton) {

        uploadButton.addEventListener(
            "click",
            openUploadModal
        );
    }

    if (closeModalButton) {

        closeModalButton.addEventListener(
            "click",
            () => {

                closeUploadModal();

                resetUploadState();
            }
        );
    }

    if (uploadModal) {

        uploadModal.addEventListener(
            "click",
            event => {

                if (
                    event.target === uploadModal
                ) {

                    closeUploadModal();

                    resetUploadState();
                }
            }
        );
    }

    if (emailFileInput) {

        emailFileInput.addEventListener(
            "change",
            event => {

                const file =
                    event.target.files[0];

                handleFileSelection(file);
            }
        );
    }

    if (dropZone) {

        dropZone.addEventListener(
            "dragover",
            event => {

                event.preventDefault();

                dropZone.classList.add(
                    "dragging"
                );
            }
        );

        dropZone.addEventListener(
            "dragleave",
            () => {

                dropZone.classList.remove(
                    "dragging"
                );
            }
        );

        dropZone.addEventListener(
            "drop",
            event => {

                event.preventDefault();

                dropZone.classList.remove(
                    "dragging"
                );

                const file =
                    event.dataTransfer.files[0];

                if (!file) {
                    return;
                }

                try {

                    const dataTransfer =
                        new DataTransfer();

                    dataTransfer.items.add(
                        file
                    );

                    emailFileInput.files =
                        dataTransfer.files;

                } catch {

                    // Browser does not support
                    // assigning dropped files.
                }

                handleFileSelection(file);
            }
        );
    }

    if (analyzeSubmit) {

        analyzeSubmit.addEventListener(
            "click",
            uploadEmail
        );
    }
}


// ========================================
// REFRESH SETUP
// ========================================

function setupRefresh() {

    if (!refreshButton) {
        return;
    }

    refreshButton.addEventListener(
        "click",
        loadDashboard
    );
}


// ========================================
// START
// ========================================

loadDashboard();

setupUpload();

setupRefresh();

setInterval(
    loadDashboard,
    30000
);