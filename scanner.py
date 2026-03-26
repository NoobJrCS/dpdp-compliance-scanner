# scanner.py
import sys
import json
import time
import argparse
from crawler  import run_crawler, fetch_page, normalize_url
from auditor  import run_audit
from scorer   import generate_score_report
from reporter import generate_pdf_report


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

    # Must provide either a domain or --from-json
    if not args.domain and not args.from_json:
        parser.print_help()
        sys.exit(1)

    return args


def main():
    args = parse_args()
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
    # PATH B: Full scan (crawl → audit → score)
    # ---------------------------------------------------------------
    else:
        domain = args.domain

        # STAGE 1 — Crawl
        crawl_result = run_crawler(domain)

        # STAGE 2 — Homepage HTML for cookie banner check (DPDP-05)
        print("Fetching homepage HTML for cookie banner detection...")
        homepage_html = fetch_page(normalize_url(domain)) or ""

        # STAGE 3 — Audit
        audit_results = run_audit(crawl_result, homepage_html)

        # STAGE 4 — Score
        scan_duration = time.time() - scan_start
        report = generate_score_report(crawl_result, audit_results, scan_duration)

        # Print terminal summary
        print_score_summary(report)

        # Save raw JSON
        json_filename = f"report_{domain.replace('.', '_')}.json"
        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"  ✓ JSON saved to: {json_filename}")
        except OSError as e:
            print(f"  ✗ Could not save JSON: {e}")

    # ---------------------------------------------------------------
    # STAGE 5 — Generate PDF Report
    # ---------------------------------------------------------------
    print("\n  Generating PDF report...")

    try:
        pdf_path = generate_pdf_report(report)
        print(f"  ✓ PDF report ready: {pdf_path}")
    except Exception as e:
        print(f"  ✗ PDF generation failed: {e}")

    print(f"\n  Total scan time: {time.time() - scan_start:.1f}s\n")


def print_score_summary(report: dict):
    """
    Prints a clean, human-readable score summary to the terminal.
    """
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
    print(f"    ↳ Critical Failures : {summary['critical_failures']}")
    print(f"    ↳ High Failures     : {summary['high_failures']}")
    print(f"    ↳ Medium Failures   : {summary['medium_failures']}")

    deductions = report["score_breakdown"]["deductions"]
    if deductions:
        print(f"\n  SCORE DEDUCTIONS:")
        for d in deductions:
            print(f"    [-{d['points_deducted']:>2}pts] [{d['severity']:<8}] {d['label']}")

    if report["critical_violations"]:
        print(f"\n  ⚠️  CRITICAL VIOLATIONS:")
        for v in report["critical_violations"]:
            print(f"    → {v['label']}")
    else:
        print(f"\n  ✅ No Critical violations found.")

    recs = report["recommendations"]
    if recs:
        print(f"\n  TOP RECOMMENDATIONS:")
        for rec in recs[:3]:
            print(f"    • {rec[:55]}...")

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    main()