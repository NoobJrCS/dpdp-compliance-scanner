# scorer.py
import json
from datetime import date
from rules import DPDP_RULES

GRADE_THRESHOLDS = [
    { "min": 90, "grade": "A", "risk_level": "Low Risk",           "color": "#22c55e" },
    { "min": 75, "grade": "B", "risk_level": "Low-Moderate Risk",  "color": "#84cc16" },
    { "min": 60, "grade": "C", "risk_level": "Moderate Risk",      "color": "#eab308" },
    { "min": 45, "grade": "D", "risk_level": "High Risk",          "color": "#f97316" },
    { "min":  0, "grade": "F", "risk_level": "Critical Risk",      "color": "#ef4444" },
]


def resolve_grade(score: int) -> dict:
    for threshold in GRADE_THRESHOLDS:
        if score >= threshold["min"]:
            return threshold
    return GRADE_THRESHOLDS[-1]


def calculate_score(audit_results: dict) -> dict:
    points_map     = { rule["id"]: rule["points"] for rule in DPDP_RULES }
    total_score    = 100
    total_deducted = 0
    deductions     = []

    for rule_id, result in audit_results.items():
        points = points_map.get(rule_id, 0)
        if not result["passed"]:
            total_score    -= points
            total_deducted += points
            deductions.append({
                "rule_id":         rule_id,
                "label":           result["label"],
                "severity":        result["severity"],
                "points_deducted": points
            })

    final_score = max(0, min(100, total_score))
    deductions.sort(key=lambda x: x["points_deducted"], reverse=True)

    return {
        "max_possible_score": 100,
        "total_deducted":     total_deducted,
        "deductions":         deductions,
        "final_score":        final_score
    }


def build_summary(audit_results: dict) -> dict:
    total  = len(audit_results)
    passed = sum(1 for r in audit_results.values() if r["passed"])
    failed = total - passed

    return {
        "total_checks":      total,
        "passed":            passed,
        "failed":            failed,
        "critical_failures": sum(1 for r in audit_results.values() if not r["passed"] and r["severity"] == "Critical"),
        "high_failures":     sum(1 for r in audit_results.values() if not r["passed"] and r["severity"] == "High"),
        "medium_failures":   sum(1 for r in audit_results.values() if not r["passed"] and r["severity"] == "Medium"),
    }


def build_recommendations(audit_results: dict) -> list:
    recommendations_map = {
        rule["id"]: rule.get("recommendation", "")
        for rule in DPDP_RULES
    }
    severity_order = { "Critical": 0, "High": 1, "Medium": 2 }

    failed_rules = [
        (rule_id, result)
        for rule_id, result in audit_results.items()
        if not result["passed"]
    ]
    failed_rules.sort(key=lambda x: severity_order.get(x[1]["severity"], 99))

    recommendations = []
    for rule_id, result in failed_rules:
        rec_text = recommendations_map.get(rule_id, "")
        if rec_text:
            recommendations.append(f"[{result['severity']}] {rec_text}")

    return recommendations


def get_critical_violations(audit_results: dict) -> list:
    return [
        {
            "rule_id":  rule_id,
            "label":    result["label"],
            "severity": result["severity"]
        }
        for rule_id, result in audit_results.items()
        if not result["passed"] and result["severity"] == "Critical"
    ]


def _enrich_checks(audit_results: dict) -> dict:
    points_map = { rule["id"]: rule["points"] for rule in DPDP_RULES }
    enriched   = {}
    for rule_id, result in audit_results.items():
        points = points_map.get(rule_id, 0)
        enriched[rule_id] = {
            **result,
            "points_deducted": 0 if result["passed"] else points
        }
    return enriched


def generate_score_report(
    crawl_result:        dict,
    audit_results:       dict,
    scan_duration:       float,
    verification_result: dict | None = None   # ← new parameter
) -> dict:
    """
    Master scoring function. Builds the complete report dictionary
    that is saved as JSON and passed to the PDF report generator.

    verification_result: the full dict returned by verify_contacts()
    in verifier.py — passed through from scanner.py via auditor.py's
    get_verification_result(). Included in the report so the PDF
    template can render the contact verification section.
    """
    print("  Calculating DPDP Risk Score...")

    score_breakdown     = calculate_score(audit_results)
    final_score         = score_breakdown["final_score"]
    grade_info          = resolve_grade(final_score)
    summary             = build_summary(audit_results)
    recommendations     = build_recommendations(audit_results)
    critical_violations = get_critical_violations(audit_results)

    report = {
        # Header
        "target_url":            crawl_result.get("base_url", "Unknown"),
        "scan_date":             date.today().isoformat(),
        "scan_duration_seconds": round(scan_duration, 2),

        # Score
        "risk_score":  final_score,
        "risk_grade":  grade_info["grade"],
        "risk_level":  grade_info["risk_level"],
        "grade_color": grade_info["color"],

        # Breakdown
        "score_breakdown": score_breakdown,

        # Detailed checks
        "checks": _enrich_checks(audit_results),

        # Summary
        "summary": summary,

        # Violations & recommendations
        "critical_violations": critical_violations,
        "recommendations":     recommendations,

        # Contact verification — full result from verifier.py
        # None if no pages were crawled or verification wasn't run
        "verification": verification_result,

        # Crawl metadata
        "pages_crawled": [
            {
                "label":      label,
                "url":        data["url"],
                "char_count": data["char_count"]
            }
            for label, data in crawl_result.get("pages_found", {}).items()
        ],
        "crawl_errors":    crawl_result.get("errors", []),
        "audit_confidence": "low" if not crawl_result.get("pages_found") else "high"
    }

    return report