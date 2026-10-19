# reporter.py
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

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
        "crawl_errors":        [],
        "passive_audit":       None
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

    for check_val in report.get("checks", {}).values():
        if isinstance(check_val, dict):
            check_val.setdefault("points_deducted", 0)

    for p in report.get("pages_crawled", []):
        if isinstance(p, dict):
            p.setdefault("char_count", 0)

    return report


def _generate_pdf_with_playwright(rendered_html: str, output_path: Path):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(rendered_html, wait_until="load")
        if CSS_FILE.exists():
            page.add_style_tag(path=str(CSS_FILE))
        page.pdf(
            path=str(output_path),
            format="A4",
            print_background=True,
            prefer_css_page_size=True,
            margin={"top": "0mm", "bottom": "0mm", "left": "0mm", "right": "0mm"}
        )
        browser.close()


def generate_pdf_report(report: dict) -> str:
    """
    Takes the complete report dictionary and:
      1. Sanitizes it (fills in any missing keys)
      2. Renders it into the Jinja2 HTML template
      3. Converts the rendered HTML to a PDF via WeasyPrint (or Playwright fallback)
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
    # STEP 2: Convert HTML → PDF using WeasyPrint or Playwright
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

    if WEASYPRINT_AVAILABLE:
        try:
            html_obj = HTML(
                string=rendered_html,
                base_url=str(TEMPLATES_DIR)
            )
            css_obj = CSS(filename=str(CSS_FILE))
            html_obj.write_pdf(
                target=str(output_path),
                stylesheets=[css_obj]
            )
            print(f"  [OK] PDF report generated via WeasyPrint: {output_path}")
            return str(output_path)
        except Exception as e:
            print(f"  [WARNING] WeasyPrint generation failed ({e}). Falling back to Playwright...")

    _generate_pdf_with_playwright(rendered_html, output_path)
    print(f"  [OK] PDF report generated via Playwright: {output_path}")
    return str(output_path)