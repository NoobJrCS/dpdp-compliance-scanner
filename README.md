# DPDP Compliance Scanner

An automated audit tool that scans Indian websites for compliance
with the **Digital Personal Data Protection Act 2023 (DPDP Act)**,
verifies the authenticity of Grievance Officer contact details,
and generates a professional 7-page GRC-style PDF audit report.
Also available as a web interface — no terminal required.

---

## What It Does

Most Indian websites are not yet compliant with the DPDP Act 2023,
India's first comprehensive data protection law. This tool
automatically crawls a website, runs 12 compliance checks derived
from the Act, verifies contact authenticity through DNS/SMTP/Wayback
Machine, calculates a weighted risk score, and generates a
professional PDF audit report — all in under 60 seconds.

---

## DPDP Rules Checked

| Rule ID  | Check                                          | Severity | Points |
|----------|------------------------------------------------|----------|--------|
| DPDP-01  | Privacy Policy Page Exists                     | Critical | 25     |
| DPDP-02  | DPDP Act Referenced in Policy                  | High     | 15     |
| DPDP-03  | Grievance Officer Email Present                | Critical | 20     |
| DPDP-04  | Grievance Officer Role Mentioned               | High     | 10     |
| DPDP-05  | Cookie Consent Banner Detected                 | High     | 10     |
| DPDP-06  | Data Retention Period Mentioned                | Medium   | 8      |
| DPDP-07  | User Rights (Access/Correction/Erasure)        | High     | 5      |
| DPDP-08  | Third-Party Data Sharing Disclosed             | Medium   | 2      |
| DPDP-09  | Contact Info for Data Queries                  | Medium   | 1      |
| DPDP-10  | Children's Data Safeguards Mentioned           | Medium   | 2      |
| DPDP-11  | Grievance Officer Contact is Not a Placeholder | High     | 1      |
| DPDP-12  | Grievance Officer Name is Not a Placeholder    | Medium   | 1      |

**Total: 100 points.** Score = 100 minus points for each failed check.
Grade: A (90+) · B (75+) · C (60+) · D (45+) · F (<45)

---

## Contact Authenticity Verification

Beyond checking whether a Grievance Officer contact exists,
the tool verifies whether the contact details are real:

| Layer | Check |
|-------|-------|
| 1 | Placeholder detection (name, email, phone) |
| 2 | DNS domain resolution |
| 3 | MX record verification |
| 4 | SMTP reachability (live handshake, no email sent) |
| 5 | Domain consistency (email matches website domain) |
| 6 | Phone carrier verification (TRAI number series) |
| 7 | Historical comparison via Wayback Machine API |

---

## Architecture

```
app.py              ← Flask web server (routes + SSE progress stream)
scanner.py          ← CLI entry point (argparse)
    │
    ├── crawler.py      ← Playwright-based web crawler
    │       Fetches fully JS-rendered pages
    │       Extracts compliance links from footer
    │       Respects robots.txt and crawl delay
    │       Exponential backoff retry on failure
    │
    ├── rules.py        ← 12 DPDP rule definitions with weights
    │
    ├── auditor.py      ← Audit engine (12 DPDP rules)
    │       keyword_exact    — regex pattern matching
    │       keyword_context  — spaCy NLP sentence analysis
    │       email_pattern    — contact/DPO email detection
    │       homepage_html    — cookie banner detection
    │       contact_authentic — routes to verifier.py
    │
    ├── verifier.py     ← Contact authenticity verifier
    │       DNS, MX, SMTP, carrier, placeholder, Wayback Machine
    │
    ├── scorer.py       ← Risk scoring engine
    │       Weighted deduction model (starts at 100)
    │       A/B/C/D/F grading with risk labels
    │       Prioritised remediation recommendations
    │
    └── reporter.py     ← PDF report generator
            Jinja2 HTML templating
            WeasyPrint HTML → PDF conversion
            Professional GRC-style 7-page output
```

---

## Installation

### Prerequisites
- Python 3.9+
- pip

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/NoobJrCS/dpdp-compliance-scanner.git
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

### Web Interface (Recommended)

```bash
python app.py
```

Open `http://localhost:5000` in your browser. Enter any domain,
click Scan Now, and watch the live progress stream. Download the
PDF report when the scan completes.

### Command Line

```bash
# Basic scan
python scanner.py flipkart.com

# Regenerate PDF from saved JSON (no re-crawl)
python scanner.py --from-json report_flipkart_com.json
```

---

## Output

Every scan produces:

1. **Real-time progress stream** — live log in the web UI
2. **Terminal summary** — score, grade, deductions, top recommendations
3. **JSON file** — machine-readable full report
4. **PDF report** — professional 7-page GRC audit document

### PDF Report Structure (7 Pages)

| Page | Content |
|------|---------|
| 1 | Cover — URL, risk score circle, grade, scan metadata |
| 2 | Executive summary — violation counts, score breakdown chart |
| 3 | Detailed findings — all 12 DPDP rules with pass/fail and points |
| 4 | Remediation recommendations — prioritised by severity |
| 5 | Scan metadata — crawled pages, errors, audit configuration |
| 6 | Contact authenticity verification — email, phone, name, history |
| 7 | Legal disclaimer |

---

## Tech Stack

| Layer            | Technology                      |
|------------------|---------------------------------|
| Web Framework    | Flask (SSE for live progress)   |
| Web Crawling     | Playwright (headless Chromium)  |
| HTML Parsing     | BeautifulSoup4 + lxml           |
| NLP Analysis     | spaCy (en_core_web_sm)          |
| DNS / MX Lookup  | dnspython                       |
| SMTP Verify      | Python smtplib                  |
| History Check    | Wayback Machine CDX API         |
| Phone Verify     | TRAI number series lookup       |
| Templating       | Jinja2                          |
| PDF Output       | WeasyPrint                      |
| Language         | Python 3.11                     |

---

## Limitations

- Automated analysis may produce false positives or negatives
- JavaScript-heavy or bot-blocked sites may not render fully
- SMTP probing is blocked by many large mail servers (inconclusive — not penalised)
- Rules are English-language only — Hindi/regional policies not supported
- TRAI number series table is not exhaustive
- This tool is for educational and research purposes only and does
  not constitute legal advice

---

## Future Scope

- Hindi and regional language support (spaCy multilingual models)
- Batch scanning with CSV input and sector-wise comparison report
- LLM-powered policy analysis for near-zero false negatives
- Continuous monitoring with email alerts on score changes
- Browser extension for real-time compliance badge on any Indian site
- Public deployment with national compliance leaderboard

---

## License

MIT License — free to use, modify, and distribute.

---

## Authors

**Niket**
**Nikunj**