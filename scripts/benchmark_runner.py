# scripts/benchmark_runner.py
# ---------------------------------------------------------------------------
# 10-Site Ground Truth Benchmarking Runner
#
# Runs passive prospecting scans on 10 representative Indian web targets,
# persists the JSON evidence artifacts to results/<domain>.json, and
# extracts summary comparisons for ground truth evaluation.
# ---------------------------------------------------------------------------

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import time
from pathlib import Path
from urllib.parse import urlparse

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tracker_audit import audit_page
from robots_check import is_scraping_allowed

TARGET_SITES = [
    {
        "domain": "flipkart.com",
        "category": "Big Enterprise / eCommerce",
        "notes": "Custom React architecture, Akamai CDN, New Relic telemetry"
    },
    {
        "domain": "zomato.com",
        "category": "Big Enterprise / Food Delivery",
        "notes": "Cloudflare WAF, robots.txt disallows automated scraping"
    },
    {
        "domain": "razorpay.com",
        "category": "Big Enterprise / Fintech",
        "notes": "Enterprise payment gateway, strict WAF & security headers"
    },
    {
        "domain": "practo.com",
        "category": "Mid-Market / Healthcare",
        "notes": "Telehealth platform, standard footer compliance architecture"
    },
    {
        "domain": "bewakoof.com",
        "category": "Mid-Market / D2C Fashion",
        "notes": "High consumer volume, heavy advertising/retargeting pixel stack"
    },
    {
        "domain": "urbancompany.com",
        "category": "Mid-Market / Services Marketplace",
        "notes": "Hyperlocal services, mobile-first web event telemetry"
    },
    {
        "domain": "blissclub.com",
        "category": "Small Shopify / D2C Activewear",
        "notes": "Shopify storefront with eCommerce app pixels (Meta, GA, Klaviyo)"
    },
    {
        "domain": "mokobara.com",
        "category": "Small Shopify / D2C Travel Gear",
        "notes": "Shopify storefront with marketing/analytics tracking integrations"
    },
    {
        "domain": "uidai.gov.in",
        "category": "Government Portal / Critical Infra",
        "notes": "NIC infrastructure; expect zero commercial ad trackers, strict HSTS"
    },
    {
        "domain": "pw.live",
        "category": "EdTech Platform",
        "notes": "High student acquisition traffic, customer engagement analytics"
    },
]


def run_benchmark():
    results_dir = PROJECT_ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 75}")
    print(f"  DPDP SCANNER — 10-SITE GROUND TRUTH BENCHMARK EXPERIMENT")
    print(f"  Execution Mode : Passive Prospecting (No port 25 SMTP / No Clicks)")
    print(f"  Target Roster  : {len(TARGET_SITES)} sites across 5 key sectors")
    print(f"{'=' * 75}\n")

    summary_rows = []

    for i, target in enumerate(TARGET_SITES, 1):
        domain = target["domain"]
        category = target["category"]
        notes = target["notes"]

        print(f"[{i}/{len(TARGET_SITES)}] Processing: {domain} ({category})...")

        # Check robots.txt first to document permission baseline
        origin = f"https://{domain}"
        allowed_robots = is_scraping_allowed(origin, "/")
        print(f"    • robots.txt allows /: {'YES' if allowed_robots else 'NO (Disallows crawler)'}")

        scan_start = time.time()
        try:
            audit_data = audit_page(origin, settle_ms=4000, timeout_ms=35000)
            duration = round(time.time() - scan_start, 2)
            audit_data["benchmark_metadata"] = {
                "sector": category,
                "robots_allowed": allowed_robots,
                "notes": notes,
                "scan_duration_seconds": duration,
            }
        except Exception as e:
            duration = round(time.time() - scan_start, 2)
            audit_data = {
                "url": origin,
                "status": "error",
                "error": str(e),
                "summary": {},
                "tracker_requests": [],
                "monitoring_requests": [],
                "tracker_cookies": [],
                "cookie_issues": [],
                "missing_headers": [],
                "benchmark_metadata": {
                    "sector": category,
                    "robots_allowed": allowed_robots,
                    "notes": notes,
                    "scan_duration_seconds": duration,
                }
            }

        # Save individual JSON evidence artifact
        json_path = results_dir / f"{domain.replace('.', '_')}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2, ensure_ascii=False)
        print(f"    • Evidence saved: results/{json_path.name} ({duration}s)")

        status = audit_data.get("status", "unknown")
        status_detail = ""
        if status == "inconclusive":
            status_detail = audit_data.get("error", "Bot protection challenge")
        elif not allowed_robots:
            status_detail = "robots.txt disallow"

        trackers = [t["name"] for t in audit_data.get("tracker_requests", [])]
        monitoring = [m["name"] for m in audit_data.get("monitoring_requests", [])]
        cookies_count = len(audit_data.get("tracker_cookies", []))
        cookie_issues_count = len(audit_data.get("cookie_issues", []))
        missing_hdrs = [h["header"] for h in audit_data.get("missing_headers", [])]
        has_hsts = "strict-transport-security" not in [h.lower() for h in missing_hdrs] and "HSTS" not in missing_hdrs
        has_csp = "CSP" not in missing_hdrs and "content-security-policy" not in missing_hdrs

        print(f"    • Status: {status.upper()} {f'({status_detail[:45]}...)' if status_detail else ''}")
        print(f"    • Ad Trackers: {len(trackers)} {trackers[:4]}")
        if monitoring:
            print(f"    • Monitoring (APM): {monitoring}")
        print(f"    • HSTS Present: {has_hsts} | CSP Present: {has_csp}")

        summary_rows.append({
            "site": domain,
            "category": category,
            "robots_allowed": allowed_robots,
            "status": status,
            "inconclusive_reason": status_detail if status == "inconclusive" or not allowed_robots else "",
            "trackers_found": trackers,
            "trackers_count": len(trackers),
            "monitoring_found": monitoring,
            "tracker_cookies_count": cookies_count,
            "cookie_issues_count": cookie_issues_count,
            "has_hsts": has_hsts,
            "has_csp": has_csp,
            "missing_headers": missing_hdrs,
            "notes": notes,
        })
        print()

    # Save summary manifest
    summary_path = results_dir / "_benchmark_manifest.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_rows, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Benchmark run complete! Manifest saved to: results/_benchmark_manifest.json")
    return summary_rows


if __name__ == "__main__":
    run_benchmark()
