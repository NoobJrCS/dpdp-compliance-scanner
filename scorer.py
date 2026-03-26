# scorer.py
import json
from datetime import date
from rules import DPDP_RULES

# ---------------------------------------------------------------------------
# GRADE THRESHOLDS
# These map a numeric score (0–100) to a letter grade and risk label.
# Modeled after real-world GRC (Governance, Risk, Compliance) frameworks.
# ---------------------------------------------------------------------------
GRADE_THRESHOLDS = [
    { "min": 90, "grade": "A", "risk_level": "Low Risk",           "color": "#22c55e" },
    { "min": 75, "grade": "B", "risk_level": "Low-Moderate Risk",  "color": "#84cc16" },
    { "min": 60, "grade": "C", "risk_level": "Moderate Risk",      "color": "#eab308" },
    { "min": 45, "grade": "D", "risk_level": "High Risk",          "color": "#f97316" },
    { "min":  0, "grade": "F", "risk_level": "Critical Risk",      "color": "#ef4444" },
]

def resolve_grade(score: int) -> dict:
    """
    Maps a numeric score (0–100) to a letter grade, 
    risk level label, and a color code for the report.
    
    Score ranges:
        90–100 → A (Low Risk)
        75–89  → B (Low-Moderate Risk)
        60–74  → C (Moderate Risk)
        45–59  → D (High Risk)
        0–44   → F (Critical Risk)
    """
    for threshold in GRADE_THRESHOLDS:
        if score >= threshold["min"]:
            return threshold
    
    # Fallback (should never reach here due to min: 0 entry)
    return GRADE_THRESHOLDS[-1]

def calculate_score(audit_results: dict) -> dict:
    """
    Takes the audit results dictionary from Day 2 and calculates:
    - The numeric risk score (0–100, higher = better)
    - The total points deducted per failed rule
    - A breakdown of every deduction
    
    Scoring logic:
        Start at 100.
        For every FAILED check, subtract that rule's 'points' value.
        Floor at 0 (score can never go negative).
    
    Returns a score_breakdown dictionary.
    """
    
    # Build a lookup map: rule_id → points value, from rules.py
    points_map = { rule["id"]: rule["points"] for rule in DPDP_RULES }
    
    total_score     = 100
    total_deducted  = 0
    deductions      = []
    
    for rule_id, result in audit_results.items():
        points = points_map.get(rule_id, 0)
        
        if not result["passed"]:
            # This check failed — deduct points
            total_score    -= points
            total_deducted += points
            
            deductions.append({
                "rule_id":        rule_id,
                "label":          result["label"],
                "severity":       result["severity"],
                "points_deducted": points
            })
    
    # Floor the score at 0 — it should never go negative
    final_score = max(0, total_score)
    
    # Sort deductions by points_deducted descending
    # (biggest violations shown first in the report)
    deductions.sort(key=lambda x: x["points_deducted"], reverse=True)
    
    return {
        "max_possible_score": 100,
        "total_deducted":     total_deducted,
        "deductions":         deductions,
        "final_score":        final_score
    }
    
def build_summary(audit_results: dict) -> dict:
    """
    Counts passes/failures broken down by severity level.
    
    Returns a summary dictionary used in the JSON output
    and the executive summary section of the report.
    """
    total    = len(audit_results)
    passed   = sum(1 for r in audit_results.values() if r["passed"])
    failed   = total - passed
    
    critical_failures = [
        r for r in audit_results.values()
        if not r["passed"] and r["severity"] == "Critical"
    ]
    high_failures = [
        r for r in audit_results.values()
        if not r["passed"] and r["severity"] == "High"
    ]
    medium_failures = [
        r for r in audit_results.values()
        if not r["passed"] and r["severity"] == "Medium"
    ]
    
    return {
        "total_checks":      total,
        "passed":            passed,
        "failed":            failed,
        "critical_failures": len(critical_failures),
        "high_failures":     len(high_failures),
        "medium_failures":   len(medium_failures)
    }

def build_recommendations(audit_results: dict) -> list[str]:
    """
    For every failed check, returns the corresponding 
    'recommendation' text from rules.py.
    
    Ordered by severity: Critical first, then High, then Medium.
    This ensures the most urgent fixes appear at the top of the report.
    """
    
    # Build a lookup map: rule_id → recommendation text
    recommendations_map = { 
        rule["id"]: rule.get("recommendation", "") 
        for rule in DPDP_RULES 
    }
    
    # Severity ordering for sorting
    severity_order = { "Critical": 0, "High": 1, "Medium": 2 }
    
    # Collect failed rules
    failed_rules = [
        (rule_id, result)
        for rule_id, result in audit_results.items()
        if not result["passed"]
    ]
    
    # Sort by severity
    failed_rules.sort(
        key=lambda x: severity_order.get(x[1]["severity"], 99)
    )
    
    # Build recommendation strings
    recommendations = []
    for rule_id, result in failed_rules:
        rec_text = recommendations_map.get(rule_id, "")
        if rec_text:
            recommendations.append(
                f"[{result['severity']}] {rec_text}"
            )
    
    return recommendations

def get_critical_violations(audit_results: dict) -> list[dict]:
    """
    Returns a list of all Critical-severity checks that failed.
    
    These are surfaced prominently at the top of the JSON output
    and the report — they represent direct legal violations that
    require immediate remediation.
    """
    return [
        {
            "rule_id":  rule_id,
            "label":    result["label"],
            "severity": result["severity"]
        }
        for rule_id, result in audit_results.items()
        if not result["passed"] and result["severity"] == "Critical"
    ]
    
def generate_score_report(
    crawl_result:  dict,
    audit_results: dict,
    scan_duration: float
) -> dict:
    
    print("  Calculating DPDP Risk Score...")
    
    # Run all sub-calculations
    score_breakdown  = calculate_score(audit_results)
    final_score      = score_breakdown["final_score"]
    grade_info       = resolve_grade(final_score)
    summary          = build_summary(audit_results)
    recommendations  = build_recommendations(audit_results)
    critical_violations = get_critical_violations(audit_results)
    
    # Build the complete report dictionary
    report = {
        # --- Header ---
        "target_url":             crawl_result.get("base_url", "Unknown"),
        "scan_date":              date.today().isoformat(),
        "scan_duration_seconds":  round(scan_duration, 2),
        
        # --- Score ---
        "risk_score":  final_score,
        "risk_grade":  grade_info["grade"],
        "risk_level":  grade_info["risk_level"],
        "grade_color": grade_info["color"],
        
        # --- Breakdown ---
        "score_breakdown": score_breakdown,
        
        # --- Detailed Checks ---
        # Enrich audit_results with points_deducted info from rules.py
        "checks": _enrich_checks(audit_results),
        
        # --- Summary ---
        "summary": summary,
        
        # --- Violations & Recommendations ---
        "critical_violations": critical_violations,
        "recommendations":     recommendations,
        
        # --- Crawl Metadata ---
        "pages_crawled": [
            { "label": label, "url": data["url"], "char_count": data["char_count"] }
            for label, data in crawl_result.get("pages_found", {}).items()
        ],
        "crawl_errors": crawl_result.get("errors", [])
        
    }
    
    return report


def _enrich_checks(audit_results: dict) -> dict:
    """
    Helper: adds 'points_deducted' to each check result 
    for easy reference in the report template.
    """
    points_map = { rule["id"]: rule["points"] for rule in DPDP_RULES }
    enriched = {}
    
    for rule_id, result in audit_results.items():
        points = points_map.get(rule_id, 0)
        enriched[rule_id] = {
            **result,  # copies all existing keys (label, passed, severity, etc.)
            "points_deducted": 0 if result["passed"] else points
        }
    
    return enriched