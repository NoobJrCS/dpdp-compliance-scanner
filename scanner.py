# scanner.py
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import time
import argparse
from crawler  import run_crawler, fetch_page, normalize_url
from auditor  import run_audit, get_verification_result
from scorer   import generate_score_report
from reporter import generate_pdf_report
from tracker_audit import audit_page


def parse_args():
    parser = argparse.ArgumentParser(
        description="DPDP Act 2023 Compliance Scanner for Indian Websites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py flipkart.com
  python scanner.py --from-json report_flipkart_com.json
        """
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain to scan (e.g. flipkart.com)"
    )
    parser.add_argument(
        "--from-json",
        metavar="FILE",
        help="Skip crawling — generate PDF report from a saved JSON file"
    )

    args = parser.parse_args()

    if not args.domain and not args.from_json:
        parser.print_help()
        sys.exit(1)

    return args


def main():
    args       = parse_args()
    scan_start = time.time()

    # ---------------------------------------------------------------
    # PATH A: Regenerate PDF from existing JSON (no re-crawling)
    # ---------------------------------------------------------------
    if args.from_json:
        print(f"\n  Loading report from: {args.from_json}")
        try:
            with open(args.from_json, "r", encoding="utf-8") as f:
                report = json.load(f)
        except FileNotFoundError:
            print(f"  ✗ File not found: {args.from_json}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"  ✗ Invalid JSON file: {e}")
            sys.exit(1)

    # ---------------------------------------------------------------
    # PATH B: Full scan (crawl → audit → score → report)
    # ---------------------------------------------------------------
    else:
        domain = args.domain

        # STAGE 1 — Crawl
        crawl_result = run_crawler(domain)

        if crawl_result.get("blocked"):
            print(f"\n{'=' * 60}")
            print(f"  [!] SCAN INCONCLUSIVE: {crawl_result.get('blocked_reason')}")
            print(f"      Target: {domain}")
            print(f"      Automated audit cannot proceed without human browser verification.")
            print(f"{'=' * 60}\n")
            sys.exit(0)

        if not crawl_result.get("pages_found"):
            print(f"\n{'=' * 60}")
            print(f"  [!] SCAN INCONCLUSIVE: No compliance pages could be retrieved.")
            print(f"      Target: {domain}")
            print(f"      Automated audit cannot proceed without privacy policy text.")
            print(f"{'=' * 60}\n")
            sys.exit(0)

        # STAGE 2 — Homepage HTML for cookie banner check (DPDP-05)
        print("Fetching homepage HTML for cookie banner detection...")
        homepage_html = fetch_page(normalize_url(domain)) or ""

        # STAGE 2.5 — Passive Pre-Consent Tracker & Security Audit
        print("Running passive pre-consent tracker & security audit...")
        try:
            passive_audit = audit_page(domain, settle_ms=2500)
        except Exception as e:
            print(f"  [WARN] Passive audit skipped: {e}")
            passive_audit = None

        # STAGE 3 — Audit (also runs contact verification internally)
        audit_results = run_audit(crawl_result, homepage_html)

        # STAGE 4 — Retrieve the full verification result that was
        # cached inside auditor.py during the contact_authentic checks
        # This gives us the rich data needed for the PDF report section
        base_url            = crawl_result.get("base_url", "")
        verification_result = get_verification_result(base_url)

        # STAGE 5 — Score
        scan_duration = time.time() - scan_start
        report = generate_score_report(
            crawl_result,
            audit_results,
            scan_duration,
            verification_result,   # ← passed through to the report dict
            passive_audit_result=passive_audit
        )

        # Print terminal summary
        print_score_summary(report)

        # Save raw JSON
        json_filename = f"report_{domain.replace('.', '_')}.json"
        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"  [OK] JSON saved to: {json_filename}")
        except OSError as e:
            print(f"  [ERROR] Could not save JSON: {e}")

    # STAGE 6 — Generate PDF Report
    print("\n  Generating PDF report...")
    try:
        pdf_path = generate_pdf_report(report)
        print(f"  [OK] PDF report ready: {pdf_path}")
    except Exception as e:
        print(f"  [ERROR] PDF generation failed: {e}")

    print(f"\n  Total scan time: {time.time() - scan_start:.1f}s\n")


def print_score_summary(report: dict):
    score   = report["risk_score"]
    grade   = report["risk_grade"]
    level   = report["risk_level"]
    summary = report["summary"]

    print(f"\n{'=' * 60}")
    print(f"  DPDP COMPLIANCE REPORT")
    print(f"  Target  : {report['target_url']}")
    print(f"  Date    : {report['scan_date']}")
    print(f"  Duration: {report['scan_duration_seconds']}s")
    print(f"{'=' * 60}")
    print(f"\n  RISK SCORE : {score}/100")
    print(f"  GRADE      : {grade}")
    print(f"  RISK LEVEL : {level}")
    print(f"\n  Checks Passed  : {summary['passed']}/{summary['total_checks']}")
    print(f"  Checks Failed  : {summary['failed']}/{summary['total_checks']}")
    print(f"    - Critical Failures : {summary['critical_failures']}")
    print(f"    - High Failures     : {summary['high_failures']}")
    print(f"    - Medium Failures   : {summary['medium_failures']}")

    deductions = report["score_breakdown"]["deductions"]
    if deductions:
        print(f"\n  SCORE DEDUCTIONS:")
        for d in deductions:
            print(f"    [-{d['points_deducted']:>2}pts] [{d['severity']:<8}] {d['label']}")

    if report["critical_violations"]:
        print(f"\n  [WARN] CRITICAL VIOLATIONS:")
        for v in report["critical_violations"]:
            print(f"    -> {v['label']}")
    else:
        print(f"\n  [OK] No Critical violations found.")

    recs = report["recommendations"]
    if recs:
        print(f"\n  TOP RECOMMENDATIONS:")
        for rec in recs[:3]:
            print(f"    * {rec[:55]}...")

    # Print verification verdict if available
    verification = report.get("verification")
    if verification:
        verdict = verification.get("overall_verdict", "unverified")
        verdict_labels = {
            "authentic":         "[OK] AUTHENTIC",
            "suspicious":        "[WARN] SUSPICIOUS",
            "fake_detected":     "[FAIL] FAKE/DUMMY DETECTED",
            "no_contacts_found": "[INFO] NO CONTACTS FOUND",
        }
        print(f"\n  CONTACT VERIFICATION : {verdict_labels.get(verdict, verdict)}")

    # Print passive pre-consent audit findings
    passive = report.get("passive_audit")
    if passive:
        print(f"\n{'=' * 60}")
        print(f"  PASSIVE PRE-CONSENT AUDIT (Readiness Indicators)")
        print(f"{'=' * 60}")
        if passive.get("status") == "inconclusive":
            print(f"  [!] INCONCLUSIVE: {passive.get('error')}")
            print(f"      Automated tracker results are NOT reliable for outreach.")
        else:
            summ = passive.get("summary") or {}
            tr_cnt = summ.get('trackers_count', len(passive.get('tracker_requests', [])))
            tc_cnt = summ.get('tracker_cookies_count', len(passive.get('tracker_cookies', [])))
            cf_cnt = summ.get('cookie_issues_count', len(passive.get('cookie_issues', [])))
            mh_cnt = summ.get('missing_headers_count', len(passive.get('missing_headers', [])))
            fi_cnt = summ.get('form_issues_count', len(passive.get('form_issues', [])))
            print(f"  Trackers firing before interaction : {tr_cnt}")
            print(f"  Tracker cookies set                : {tc_cnt}")
            print(f"  Cookie flag issues                 : {cf_cnt}")
            print(f"  Missing security headers           : {mh_cnt}")
            print(f"  Form issues                        : {fi_cnt}")

            trackers = passive.get("tracker_requests", [])
            if trackers:
                print(f"\n  TRACKER REQUESTS:")
                for t in trackers:
                    print(f"    * {t['name']:<24} [{t.get('category',''):<14}] x{t.get('request_count', 1)}")

            cookie_issues = passive.get("cookie_issues", [])
            if cookie_issues:
                print(f"\n  COOKIE FLAG ISSUES ({len(cookie_issues)}):")
                for c in cookie_issues[:5]:
                    print(f"    * {c['name']:<24} {', '.join(c.get('issues', []))}")
                if len(cookie_issues) > 5:
                    print(f"    ... and {len(cookie_issues) - 5} more")

            missing_headers = passive.get("missing_headers", [])
            if missing_headers:
                print(f"\n  MISSING SECURITY HEADERS:")
                for h in missing_headers:
                    print(f"    * {h['header']:<34} {h.get('why', '')}")

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    main()