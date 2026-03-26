# reporter.py
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS

# Paths — resolve relative to this file's location
BASE_DIR      = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR   = BASE_DIR / "reports"
CSS_FILE      = TEMPLATES_DIR / "styles.css"
HTML_TEMPLATE = "report.html"


def sanitize_report(report: dict) -> dict:
    """
    EDGE CASE 5: Ensures all keys the Jinja2 template expects are present.
    Fills in safe default values for any missing keys.
    Prevents UndefinedError crashes when the crawler fails entirely
    and the report dict is incomplete.

    Only fills in MISSING keys — never overwrites real data.
    """
    defaults = {
        "target_url":            "Unknown",
        "scan_date":             "Unknown",
        "scan_duration_seconds": 0,
        "risk_score":            0,
        "risk_grade":            "F",
        "risk_level":            "Unaudited",
        "grade_color":           "#ef4444",
        "audit_confidence":      "low",
        "score_breakdown": {
            "deductions":     [],
            "total_deducted": 0
        },
        "checks": {},
        "summary": {
            "total_checks":      0,
            "passed":            0,
            "failed":            0,
            "critical_failures": 0,
            "high_failures":     0,
            "medium_failures":   0
        },
        "critical_violations": [],
        "recommendations":     [],
        "pages_crawled":       [],
        "crawl_errors":        []
    }

    for key, value in defaults.items():
        report.setdefault(key, value)

    summary_defaults = {
        "total_checks":      0,
        "passed":            0,
        "failed":            0,
        "critical_failures": 0,
        "high_failures":     0,
        "medium_failures":   0
    }
    for key, value in summary_defaults.items():
        report["summary"].setdefault(key, value)

    return report


def generate_pdf_report(report: dict) -> str:
    """
    Takes the complete report dictionary and:
      1. Sanitizes it (fills in any missing keys)
      2. Renders it into the Jinja2 HTML template
      3. Converts the rendered HTML to a PDF via WeasyPrint
      4. Saves the PDF to the /reports/ folder

    Returns the path to the generated PDF file.
    """
    report = sanitize_report(report)

    REPORTS_DIR.mkdir(exist_ok=True)

    # ---------------------------------------------------------------
    # STEP 1: Render the Jinja2 HTML Template
    # ---------------------------------------------------------------
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True
    )

    template = env.get_template(HTML_TEMPLATE)

    rendered_html = template.render(
        report=report,
        css_path=str(CSS_FILE)
    )

    # ---------------------------------------------------------------
    # STEP 2: Convert HTML → PDF using WeasyPrint
    # ---------------------------------------------------------------
    domain_slug = (
        report.get("target_url", "unknown")
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "")
        .replace(".", "_")
        .strip("_")
    )
    output_filename = f"compliance_report_{domain_slug}.pdf"
    output_path     = REPORTS_DIR / output_filename

    print(f"  Generating PDF report...")
    print(f"  Template : {HTML_TEMPLATE}")
    print(f"  Output   : {output_path}")

    html_obj = HTML(
        string=rendered_html,
        base_url=str(TEMPLATES_DIR)
    )

    css_obj = CSS(filename=str(CSS_FILE))

    html_obj.write_pdf(
        target=str(output_path),
        stylesheets=[css_obj]
    )

    print(f"  ✓ PDF report generated: {output_path}")
    return str(output_path)