// static/script.js
// ---------------------------------------------------------------
// DPDP Compliance Scanner — Frontend Logic
//
// Handles:
//   - Scan form submission
//   - SSE progress stream connection
//   - Real-time UI updates (progress bar, log, stage indicators)
//   - Results panel population
//   - PDF download trigger
// ---------------------------------------------------------------

let currentJobId = null;
let eventSource  = null;


// ── Helpers ─────────────────────────────────────────────────────

function show(id)   { document.getElementById(id).classList.remove("hidden"); }
function hide(id)   { document.getElementById(id).classList.add("hidden"); }
function el(id)     { return document.getElementById(id); }
function text(id, v){ el(id).textContent = v; }


// ── Prefill domain from chip button ─────────────────────────────

function prefill(domain) {
    el("domainInput").value = domain;
    el("domainInput").focus();
}


// ── Start a new scan ─────────────────────────────────────────────

async function startScan() {
    const domain = el("domainInput").value.trim()
        .replace(/^https?:\/\//i, "")
        .replace(/\/$/, "");

    if (!domain) {
        el("domainInput").focus();
        el("domainInput").style.borderColor = "var(--red)";
        setTimeout(() => el("domainInput").style.borderColor = "", 1500);
        return;
    }

    // Reset UI state
    closeEventSource();
    resetProgressPanel();
    hide("resultsCard");
    hide("errorCard");

    // Disable the scan button
    el("scanBtn").disabled = true;
    text("scanBtnText", "Scanning...");

    // Show progress panel
    text("progressTitle", "Scanning...");
    text("progressDomain", domain);
    show("progressCard");
    show("spinner");

    // POST to /scan to start the background job
    try {
        const response = await fetch("/scan", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ domain })
        });

        if (!response.ok) {
            const err = await response.json();
            showError(err.error || "Failed to start scan.");
            return;
        }

        const data = await response.json();
        currentJobId = data.job_id;

        // Open the SSE progress stream
        connectProgressStream(currentJobId);

    } catch (err) {
        showError(`Network error: ${err.message}`);
    }
}


// ── SSE: Connect to progress stream ─────────────────────────────

function connectProgressStream(jobId) {
    eventSource = new EventSource(`/progress/${jobId}`);

    // Progress updates
    eventSource.addEventListener("progress", (e) => {
        const data = JSON.parse(e.data);
        updateProgress(data);
    });

    // Final result
    eventSource.addEventListener("result", (e) => {
        const data = JSON.parse(e.data);
        closeEventSource();
        showResults(data);
    });

    // Error from server
    eventSource.addEventListener("error", (e) => {
        let msg = "An unexpected error occurred.";
        try {
            const data = JSON.parse(e.data);
            msg = data.message || msg;
        } catch (_) {}
        closeEventSource();
        showError(msg);
    });

    // SSE connection error (network issue)
    eventSource.onerror = () => {
        // Only treat as error if we haven't finished yet
        if (currentJobId) {
            closeEventSource();
            showError("Lost connection to the server. Please try again.");
        }
    };
}


function closeEventSource() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}


// ── Update progress UI ───────────────────────────────────────────

function updateProgress(data) {
    const { stage, message, percent } = data;

    // Update progress bar
    el("progressBar").style.width = `${percent}%`;
    text("progressPercent", `${percent}%`);

    // Add log line
    const logBox = el("logBox");
    // Remove "latest" class from previous line
    const prev = logBox.querySelector(".latest");
    if (prev) prev.classList.remove("latest");

    const line = document.createElement("span");
    line.className = "log-line latest";
    line.textContent = message;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;

    // Update stage indicators
    const stageOrder = ["crawl", "audit", "verify", "score", "report"];
    const stageIndex  = stageOrder.indexOf(stage);

    stageOrder.forEach((s, i) => {
        const el_stage = el(`stage-${s}`);
        if (!el_stage) return;

        if (i < stageIndex) {
            el_stage.className = "stage done";
        } else if (i === stageIndex) {
            el_stage.className = "stage active";
        } else {
            el_stage.className = "stage";
        }
    });

    // Update title when done
    if (stage === "done") {
        text("progressTitle", "Scan Complete");
        hide("spinner");
        stageOrder.forEach(s => {
            const el_stage = el(`stage-${s}`);
            if (el_stage) el_stage.className = "stage done";
        });
    }
}


// ── Show results panel ───────────────────────────────────────────

function showResults(data) {
    hide("progressCard");
    show("resultsCard");

    // Re-enable scan button
    el("scanBtn").disabled = false;
    text("scanBtnText", "Scan Now");

    // Score circle
    const circle = el("scoreCircle");
    circle.style.borderColor = data.color;
    el("scoreNumber").style.color = data.color;
    text("scoreNumber", data.score);

    // Grade and risk level
    el("scoreGrade").style.color = data.color;
    text("scoreGrade", `Grade ${data.grade}`);
    text("scoreRisk",  data.risk_level);
    text("scoreUrl",   data.target_url);
    text("scoreMeta",  `Scanned on ${data.scan_date} in ${data.duration}s`);

    // Stats
    text("statPassed",   data.passed);
    text("statFailed",   data.failed);
    text("statCritical", data.critical);
    text("statHigh",     data.high);
    text("statMedium",   data.medium);

    // Verification verdict
    if (data.verification_verdict) {
        const verdictConfig = {
            "authentic":         { icon: "✅", text: "Contact Verification: Authentic",              cls: "verify-authentic"  },
            "suspicious":        { icon: "⚠️", text: "Contact Verification: Suspicious — review needed", cls: "verify-suspicious" },
            "fake_detected":     { icon: "❌", text: "Contact Verification: Fake/Placeholder detected",  cls: "verify-fake"       },
            "no_contacts_found": { icon: "❓", text: "Contact Verification: No contacts found",          cls: "verify-unknown"    },
        };
        const vc = verdictConfig[data.verification_verdict] || verdictConfig["no_contacts_found"];
        const vBox = el("verifyVerdict");
        vBox.className = `verify-verdict ${vc.cls}`;
        text("verifyIcon", vc.icon);
        text("verifyText", vc.text);
        show("verifyVerdict");
    }

    // Checks table
    const tbody = el("checksBody");
    tbody.innerHTML = "";
    Object.entries(data.checks).forEach(([ruleId, check]) => {
        const row = document.createElement("tr");
        const passBadge = check.passed
            ? '<span class="badge badge-pass">Pass</span>'
            : '<span class="badge badge-fail">Fail</span>';
        const sevBadge = `<span class="badge badge-${check.severity.toLowerCase()}">${check.severity}</span>`;
        row.innerHTML = `
            <td><strong>${ruleId}</strong></td>
            <td>${check.label}</td>
            <td>${sevBadge}</td>
            <td>${passBadge}</td>
        `;
        tbody.appendChild(row);
    });

    // Score deductions
    if (data.deductions && data.deductions.length > 0) {
        el("deductionsLabel").style.display = "";
        const list = el("deductionsList");
        list.innerHTML = "";
        data.deductions.forEach(d => {
            const row = document.createElement("div");
            row.className = "deduction-row";
            row.innerHTML = `
                <span class="deduction-pts">−${d.points_deducted}pts</span>
                <span class="badge badge-${d.severity.toLowerCase()}">${d.severity}</span>
                <span class="deduction-label">${d.label}</span>
            `;
            list.appendChild(row);
        });
    }

    // Scroll to results
    el("resultsCard").scrollIntoView({ behavior: "smooth", block: "start" });
}


// ── Show error panel ─────────────────────────────────────────────

function showError(message) {
    hide("progressCard");
    show("errorCard");

    el("scanBtn").disabled = false;
    text("scanBtnText", "Scan Now");
    text("errorMsg", message);

    el("errorCard").scrollIntoView({ behavior: "smooth", block: "start" });
}


// ── Download PDF ─────────────────────────────────────────────────

function downloadPDF() {
    if (!currentJobId) return;
    // Open the download URL in a new tab — browser handles the file download
    window.open(`/download/${currentJobId}`, "_blank");
}


// ── Reset and start a new scan ───────────────────────────────────

function newScan() {
    closeEventSource();
    currentJobId = null;

    hide("resultsCard");
    hide("errorCard");
    hide("progressCard");
    hide("verifyVerdict");

    el("domainInput").value = "";
    el("domainInput").focus();

    el("scanBtn").disabled = false;
    text("scanBtnText", "Scan Now");

    // Scroll back to top
    window.scrollTo({ top: 0, behavior: "smooth" });
}


// ── Reset progress panel state ───────────────────────────────────

function resetProgressPanel() {
    el("progressBar").style.width = "0%";
    text("progressPercent", "0%");
    el("logBox").innerHTML = "";

    ["crawl", "audit", "verify", "score", "report"].forEach(s => {
        const stageEl = el(`stage-${s}`);
        if (stageEl) stageEl.className = "stage";
    });
}


// ── Allow pressing Enter to start scan ───────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    el("domainInput").addEventListener("keydown", (e) => {
        if (e.key === "Enter") startScan();
    });
});