# app.py
# ---------------------------------------------------------------
# DPDP Compliance Scanner — Flask Web Interface
#
# Routes:
#   GET  /                      Main page
#   POST /scan                  Start a new scan, returns job_id
#   GET  /progress/<job_id>     SSE stream of real-time progress
#   GET  /result/<job_id>       JSON result for a completed scan
#   GET  /download/<job_id>     Download the generated PDF
#   GET  /history               List of recent scans
# ---------------------------------------------------------------

import os
import uuid
import json
import queue
import threading
import traceback
from datetime import datetime
from pathlib import Path
from flask import (
    Flask, render_template, request, jsonify,
    Response, send_file, stream_with_context
)

# Import your existing scanner pipeline
from crawler  import run_crawler, fetch_page, normalize_url
from auditor  import run_audit, get_verification_result
from scorer   import generate_score_report
from reporter import generate_pdf_report

app = Flask(__name__)

# ---------------------------------------------------------------
# IN-MEMORY JOB STORE
# Stores scan state, progress messages, and results per job_id.
# In production you'd use Redis, but for a college project this
# works perfectly — data persists as long as the server is running.
# ---------------------------------------------------------------
jobs = {}          # job_id → job dict
jobs_lock = threading.Lock()

# How many recent scans to keep in history
MAX_HISTORY = 20


def create_job(domain: str) -> str:
    """Create a new scan job and return its ID."""
    job_id = str(uuid.uuid4())[:8]   # Short 8-char ID e.g. "a3f9c12e"
    with jobs_lock:
        jobs[job_id] = {
            "id":         job_id,
            "domain":     domain,
            "status":     "queued",    # queued | running | done | error
            "created_at": datetime.now().isoformat(),
            "progress":   queue.Queue(),  # SSE message queue
            "report":     None,
            "pdf_path":   None,
            "error":      None
        }
    return job_id


def push(job_id: str, event: str, data: dict):
    """
    Push a Server-Sent Event message into the job's queue.
    The SSE stream endpoint reads from this queue and forwards
    each message to the browser in real time.

    event types:
        progress  — status update message (shown in the UI log)
        result    — final scan results (triggers UI update)
        error     — something went wrong
    """
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id]["progress"].put({
                "event": event,
                "data":  json.dumps(data)
            })


def run_scan(job_id: str, domain: str):
    """
    The full scanner pipeline, run in a background thread.
    Pushes progress events to the SSE queue at each stage.
    """
    import time
    scan_start = time.time()

    try:
        with jobs_lock:
            jobs[job_id]["status"] = "running"

        # ── STAGE 1: Crawl ──────────────────────────────────────
        push(job_id, "progress", {
            "stage":   "crawl",
            "message": f"🌐 Checking robots.txt and crawling {domain}...",
            "percent": 10
        })

        crawl_result = run_crawler(domain)

        pages_found = len(crawl_result.get("pages_found", {}))
        push(job_id, "progress", {
            "stage":   "crawl",
            "message": f"✓ Crawl complete — {pages_found} compliance page(s) found",
            "percent": 25
        })

        # ── STAGE 2: Homepage HTML for DPDP-05 ──────────────────
        push(job_id, "progress", {
            "stage":   "crawl",
            "message": "🍪 Checking cookie consent banner...",
            "percent": 30
        })

        homepage_html = fetch_page(normalize_url(domain)) or ""

        # ── STAGE 3: Audit ──────────────────────────────────────
        push(job_id, "progress", {
            "stage":   "audit",
            "message": "🔍 Running 12 DPDP compliance checks...",
            "percent": 40
        })

        audit_results = run_audit(crawl_result, homepage_html)

        passed = sum(1 for r in audit_results.values() if r["passed"])
        failed = len(audit_results) - passed

        push(job_id, "progress", {
            "stage":   "audit",
            "message": f"✓ Audit complete — {passed} passed, {failed} failed",
            "percent": 60
        })

        # ── STAGE 4: Contact Verification ───────────────────────
        push(job_id, "progress", {
            "stage":   "verify",
            "message": "🔎 Verifying contact authenticity (DNS, SMTP, Wayback Machine)...",
            "percent": 65
        })

        base_url            = crawl_result.get("base_url", "")
        verification_result = get_verification_result(base_url)

        if verification_result:
            verdict = verification_result.get("overall_verdict", "unverified")
            verdict_labels = {
                "authentic":         "✓ Contacts appear genuine",
                "suspicious":        "⚠ Contacts have concerns",
                "fake_detected":     "✗ Placeholder contacts detected",
                "no_contacts_found": "? No contact details found",
            }
            push(job_id, "progress", {
                "stage":   "verify",
                "message": f"✓ Verification complete — {verdict_labels.get(verdict, verdict)}",
                "percent": 75
            })

        # ── STAGE 5: Score ──────────────────────────────────────
        push(job_id, "progress", {
            "stage":   "score",
            "message": "📊 Calculating risk score and grade...",
            "percent": 80
        })

        scan_duration = time.time() - scan_start
        report = generate_score_report(
            crawl_result,
            audit_results,
            scan_duration,
            verification_result
        )

        push(job_id, "progress", {
            "stage":   "score",
            "message": (
                f"✓ Score: {report['risk_score']}/100 "
                f"(Grade {report['risk_grade']} — {report['risk_level']})"
            ),
            "percent": 88
        })

        # ── STAGE 6: PDF Report ─────────────────────────────────
        push(job_id, "progress", {
            "stage":   "report",
            "message": "📄 Generating PDF audit report...",
            "percent": 92
        })

        pdf_path = generate_pdf_report(report)

        push(job_id, "progress", {
            "stage":   "report",
            "message": "✓ PDF report generated successfully",
            "percent": 98
        })

        # ── DONE ────────────────────────────────────────────────
        total_time = round(time.time() - scan_start, 1)

        with jobs_lock:
            jobs[job_id]["status"]   = "done"
            jobs[job_id]["report"]   = report
            jobs[job_id]["pdf_path"] = pdf_path

        push(job_id, "progress", {
            "stage":   "done",
            "message": f"✓ Scan complete in {total_time}s",
            "percent": 100
        })

        # Push the final result event — triggers the UI results panel
        push(job_id, "result", {
            "job_id":     job_id,
            "score":      report["risk_score"],
            "grade":      report["risk_grade"],
            "risk_level": report["risk_level"],
            "color":      report["grade_color"],
            "passed":     report["summary"]["passed"],
            "failed":     report["summary"]["failed"],
            "total":      report["summary"]["total_checks"],
            "critical":   report["summary"]["critical_failures"],
            "high":       report["summary"]["high_failures"],
            "medium":     report["summary"]["medium_failures"],
            "target_url": report["target_url"],
            "scan_date":  report["scan_date"],
            "duration":   total_time,
            "verification_verdict": (
                verification_result.get("overall_verdict")
                if verification_result else None
            ),
            "deductions": report["score_breakdown"]["deductions"][:5],
            "checks":     {
                k: {"label": v["label"], "passed": v["passed"], "severity": v["severity"]}
                for k, v in report["checks"].items()
            }
        })

    except Exception as e:
        error_msg = str(e)
        tb        = traceback.format_exc()
        print(f"[ERROR] Scan {job_id} failed: {error_msg}\n{tb}")

        with jobs_lock:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"]  = error_msg

        push(job_id, "error", {
            "message": f"Scan failed: {error_msg}",
            "detail":  tb
        })


# ---------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main scanner page."""
    # Pass recent scan history to the template
    with jobs_lock:
        recent = [
            {
                "id":         j["id"],
                "domain":     j["domain"],
                "status":     j["status"],
                "created_at": j["created_at"],
                "score":      j["report"]["risk_score"] if j["report"] else None,
                "grade":      j["report"]["risk_grade"] if j["report"] else None,
                "color":      j["report"]["grade_color"] if j["report"] else None,
            }
            for j in list(jobs.values())[-MAX_HISTORY:]
            if j["status"] == "done"
        ]
    recent.reverse()  # Most recent first
    return render_template("index.html", recent_scans=recent)


@app.route("/scan", methods=["POST"])
def start_scan():
    """
    Accepts a domain from the form, creates a job, starts the
    scan in a background thread, and returns the job_id.
    """
    data   = request.get_json() or {}
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    # Basic domain validation
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    if not domain or " " in domain:
        return jsonify({"error": "Invalid domain format"}), 400

    job_id = create_job(domain)

    # Start scan in background thread so the response returns immediately
    thread = threading.Thread(
        target=run_scan,
        args=(job_id, domain),
        daemon=True
    )
    thread.start()

    return jsonify({"job_id": job_id, "domain": domain})


@app.route("/progress/<job_id>")
def progress_stream(job_id: str):
    """
    Server-Sent Events endpoint.
    The browser connects here and receives a stream of progress
    events in real time as the scan runs in the background thread.

    SSE format (required by the spec):
        event: <event_type>\n
        data: <json_string>\n\n
    """
    with jobs_lock:
        if job_id not in jobs:
            return jsonify({"error": "Job not found"}), 404

    def generate():
        # Send an initial ping so the browser knows the connection is open
        yield "event: ping\ndata: {}\n\n"

        job_queue = jobs[job_id]["progress"]

        while True:
            try:
                # Block for up to 1 second waiting for a message
                msg = job_queue.get(timeout=1)
                yield f"event: {msg['event']}\ndata: {msg['data']}\n\n"

                # Stop streaming once the scan is done or errored
                if msg["event"] in ("result", "error"):
                    break

            except queue.Empty:
                # No message yet — send a keepalive comment to prevent timeout
                yield ": keepalive\n\n"

                # Check if job finished without sending result event
                with jobs_lock:
                    status = jobs.get(job_id, {}).get("status")
                if status in ("done", "error"):
                    break

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no"   # Disable Nginx buffering if behind a proxy
        }
    )


@app.route("/result/<job_id>")
def get_result(job_id: str):
    """Returns the full JSON report for a completed scan."""
    with jobs_lock:
        job = jobs.get(job_id)

    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job["status"] == "running":
        return jsonify({"status": "running"}), 202

    if job["status"] == "error":
        return jsonify({"error": job["error"]}), 500

    if job["report"]:
        return jsonify(job["report"])

    return jsonify({"error": "No result available"}), 404


@app.route("/download/<job_id>")
def download_pdf(job_id: str):
    """Serves the generated PDF for download."""
    with jobs_lock:
        job = jobs.get(job_id)

    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job["status"] != "done" or not job["pdf_path"]:
        return jsonify({"error": "PDF not ready yet"}), 404

    pdf_path = Path(job["pdf_path"])
    if not pdf_path.exists():
        return jsonify({"error": "PDF file not found on disk"}), 404

    domain_slug = job["domain"].replace(".", "_")
    filename    = f"DPDP_Audit_{domain_slug}.pdf"

    return send_file(
        str(pdf_path),
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


@app.route("/history")
def history():
    """Returns recent scan history as JSON."""
    with jobs_lock:
        recent = [
            {
                "id":         j["id"],
                "domain":     j["domain"],
                "status":     j["status"],
                "created_at": j["created_at"],
                "score":      j["report"]["risk_score"] if j["report"] else None,
                "grade":      j["report"]["risk_grade"] if j["report"] else None,
                "color":      j["report"]["grade_color"] if j["report"] else None,
            }
            for j in list(jobs.values())[-MAX_HISTORY:]
        ]
    return jsonify(list(reversed(recent)))


# ---------------------------------------------------------------
# RUN
# ---------------------------------------------------------------
if __name__ == "__main__":
    # Create static folder if it doesn't exist
    Path("static").mkdir(exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)