# test/run_local_tests.py
# ---------------------------------------------------------------------------
# Automated Local Regression Test Suite
#
# Runs passive pre-consent tracker and security auditing against 3 local
# test fixtures to prevent regressions across code updates:
#   1. blocked_test_page.html   (Expected: Inconclusive bot-gate detection)
#   2. consent_test.html        (Expected: Non-compliant trackers & form issues)
#   3. compliant_test_page.html (Expected: Zero pre-consent trackers / clean)
# ---------------------------------------------------------------------------

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import os
import time
import socket
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tracker_audit import audit_page


class QuietHTTPHandler(SimpleHTTPRequestHandler):
    """Serve test fixtures quietly without cluttering stdout."""
    def log_message(self, format, *args):
        pass


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def run_tests():
    test_dir = PROJECT_ROOT / "test"
    port = find_free_port()
    
    # Custom handler serving test directory
    class TestDirHandler(QuietHTTPHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(test_dir), **kwargs)

    server = HTTPServer(('127.0.0.1', port), TestDirHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"
    print(f"\n{'=' * 65}")
    print(f"  DPDP SCANNER — 3-PAGE LOCAL REGRESSION TEST SUITE")
    print(f"  Test Server running on: {base_url}")
    print(f"{'=' * 65}\n")

    passed_tests = 0
    total_tests = 3

    try:
        # -------------------------------------------------------------------
        # TEST 1: Blocked / Bot Protection Gate Detection
        # -------------------------------------------------------------------
        print("[1/3] Testing 'blocked_test_page.html' (Bot Block Detection)...")
        res_blocked = audit_page(f"{base_url}/blocked_test_page.html", settle_ms=1000)
        
        assert res_blocked["status"] == "inconclusive", (
            f"Expected status 'inconclusive', got '{res_blocked['status']}'"
        )
        assert "access denied" in (res_blocked.get("error") or "").lower(), (
            f"Expected 'access denied' in block reason, got: {res_blocked.get('error')}"
        )
        print("  [OK] PASS: Blocked gate accurately identified as inconclusive.")
        passed_tests += 1

        # -------------------------------------------------------------------
        # TEST 2: Non-Compliant Trackers & Insecure Forms Detection
        # -------------------------------------------------------------------
        print("\n[2/3] Testing 'consent_test.html' (Deliberately Non-Compliant)...")
        res_noncomp = audit_page(f"{base_url}/consent_test.html", settle_ms=1500)
        
        assert res_noncomp["status"] == "ok", (
            f"Expected status 'ok', got '{res_noncomp['status']}'"
        )
        trackers = [t["name"] for t in res_noncomp.get("tracker_requests", [])]
        print(f"  Detected Trackers: {trackers}")
        assert len(trackers) >= 3, f"Expected at least 3 trackers, detected: {trackers}"
        
        # Verify specific tracker names
        assert any("Google" in t for t in trackers), "Missing Google Tag Manager / Analytics"
        assert any("Meta" in t or "Facebook" in t for t in trackers), "Missing Meta Pixel"
        assert any("Clarity" in t for t in trackers), "Missing Microsoft Clarity"

        # Verify form issues
        form_issues = res_noncomp.get("form_issues", [])
        print(f"  Detected Form Issues: {len(form_issues)}")
        assert len(form_issues) >= 2, f"Expected >= 2 form issues, got {len(form_issues)}"
        
        # Verify session cookie HttpOnly check
        cookie_issues = res_noncomp.get("cookie_issues", [])
        session_flagged = any(
            c["name"] == "session_id" and any("HttpOnly" in iss for iss in c["issues"])
            for c in cookie_issues
        )
        assert session_flagged, "Expected session_id to be flagged for missing HttpOnly"

        print("  [OK] PASS: All non-compliant trackers, forms, and session cookies flagged.")
        passed_tests += 1

        # -------------------------------------------------------------------
        # TEST 3: Fully Compliant Site
        # -------------------------------------------------------------------
        print("\n[3/3] Testing 'compliant_test_page.html' (Compliant Architecture)...")
        res_comp = audit_page(f"{base_url}/compliant_test_page.html", settle_ms=1000)
        
        assert res_comp["status"] == "ok", (
            f"Expected status 'ok', got '{res_comp['status']}'"
        )
        comp_trackers = res_comp.get("tracker_requests", [])
        assert len(comp_trackers) == 0, (
            f"False positive alert: Expected 0 trackers on compliant page, found: {comp_trackers}"
        )
        comp_forms = res_comp.get("form_issues", [])
        assert len(comp_forms) == 0, (
            f"False positive alert: Expected 0 form issues on compliant page, found: {comp_forms}"
        )
        print("  [OK] PASS: Clean verification with 0 false positives on compliant fixture.")
        passed_tests += 1

    finally:
        server.shutdown()
        server.server_close()

    print(f"\n{'=' * 65}")
    print(f"  LOCAL REGRESSION TEST SUMMARY: {passed_tests}/{total_tests} PASSED")
    print(f"{'=' * 65}\n")
    return passed_tests == total_tests


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
