# DPDP Compliance Scanner

An automated audit tool that scans Indian websites for compliance
with the **Digital Personal Data Protection Act 2023 (DPDP Act)**
and generates a professional GRC-style PDF report.

---

## What It Does

Most Indian websites are not yet compliant with the DPDP Act 2023,
India's first comprehensive data protection law. This tool
automatically crawls a website, runs 10 compliance checks derived
from the Act, calculates a weighted risk score, and generates a
printable PDF audit report — entirely without human intervention.

---

## Sample Report

> PDF reports generated for real Indian websites are attached to the
> [v1.0.0 Release](https://github.com/YOUR_USERNAME/dpdp-compliance-scanner/releases/tag/v1.0.0).

**Scan of practo.com:**
- Risk Score: 71/100 (Grade C — Moderate Risk)
- 7/10 checks passed
- 0 Critical violations, 2 High violations

---

## DPDP Rules Checked

| Rule ID  | Check                                    | Severity | Points |
|----------|------------------------------------------|----------|--------|
| DPDP-01  | Privacy Policy Page Exists               | Critical | 25     |
| DPDP-02  | DPDP Act Referenced in Policy            | High     | 15     |
| DPDP-03  | Grievance Officer Email Present          | Critical | 20     |
| DPDP-04  | Grievance Officer Role Mentioned         | High     | 10     |
| DPDP-05  | Cookie Consent Banner Detected           | High     | 10     |
| DPDP-06  | Data Retention Period Mentioned          | Medium   | 8      |
| DPDP-07  | User Rights (Access/Correction/Erasure)  | High     | 5      |
| DPDP-08  | Third-Party Data Sharing Disclosed       | Medium   | 3      |
| DPDP-09  | Contact Info for Data Queries            | Medium   | 2      |
| DPDP-10  | Children's Data Safeguards Mentioned     | Medium   | 2      |

---

## Architecture

```
scanner.py          ← CLI entry point (argparse)
    │
    ├── crawler.py      ← Playwright-based web crawler
    │       Fetches fully JS-rendered pages
    │       Extracts compliance-relevant links from footer
    │       Respects robots.txt crawl delay
    │
    ├── auditor.py      ← Audit engine (10 DPDP rules)
    │       keyword_exact    — regex pattern matching
    │       keyword_context  — spaCy NLP sentence analysis
    │       email_pattern    — contact/DPO email detection
    │       homepage_html    — cookie banner detection
    │
    ├── scorer.py       ← Risk scoring engine
    │       Weighted deduction model (starts at 100)
    │       A/B/C/D/F grading with risk labels
    │       Prioritised remediation recommendations
    │
    └── reporter.py     ← PDF report generator
            Jinja2 HTML templating
            WeasyPrint HTML → PDF conversion
            Professional GRC-style 6-page output
```

---

## Installation

### Prerequisites
- Python 3.9+
- pip

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/dpdp-compliance-scanner.git
cd dpdp-compliance-scanner

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install Playwright browser
playwright install chromium

# 5. Install spaCy language model
python -m spacy download en_core_web_sm

# 6. Install WeasyPrint system dependencies (Linux/WSL only)
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0
```

---

## Usage

### Basic scan
```bash
python scanner.py flipkart.com
```

### Regenerate PDF from saved JSON (no re-crawl)
```bash
python scanner.py --from-json report_flipkart_com.json
```

---

## Output

Every scan produces two outputs:

1. **Terminal summary** — score, grade, deductions, top recommendations  
2. **PDF report** — professional GRC audit document saved to `reports/compliance_report_domain_com.pdf`

### PDF Report Structure

| Page | Content |
|------|---------|
| 1 | Cover page — URL, risk score circle, grade, scan metadata |
| 2 | Executive summary — violation counts, score breakdown chart |
| 3 | Detailed findings — all 10 DPDP rules with pass/fail and points |
| 4 | Remediation recommendations — prioritised by severity |
| 5 | Scan metadata — crawled pages, errors, audit configuration |
| 6 | Legal disclaimer |

---

## Real-World Test Results

| Website            | Score  | Grade | Critical | High | Medium |
|--------------------|--------|-------|----------|------|--------|
| flipkart.com       | 10/100 | F     | 2        | 3    | 4      |
| practo.com         | 25/100 | F     | 1        | 4    | 4      |
| razorpay.com       | 90/100 | A     | —        | 1    | —      |
| zomato.com         | 0/100  | F     | 2        | 4    | 4      |
| policybazaar.com   | 0/100  | F     | 2        | 4    | 4      |


---

## Limitations

- Automated analysis may produce false positives or negatives
- JavaScript-heavy sites may not render fully within the timeout window
- Some sites actively block crawlers — the tool will flag these as
  low-confidence scans
- This tool is for educational and research purposes only and does
  not constitute legal advice

---

## Tech Stack

| Layer        | Technology                     |
|--------------|-------------------------------|
| Web Crawling | Playwright (headless Chromium) |
| HTML Parsing | BeautifulSoup4 + lxml          |
| NLP Analysis | spaCy (en_core_web_sm)         |
| Templating   | Jinja2                         |
| PDF Output   | WeasyPrint                     |
| Language     | Python 3.11                    |

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

**Niket**