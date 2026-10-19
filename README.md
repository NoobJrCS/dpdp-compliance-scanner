# DPDP Compliance Scanner

An automated audit tool that scans Indian websites for compliance
with the **Digital Personal Data Protection Act 2023 (DPDP Act)**,
verifies the authenticity of Grievance Officer and Data Protection Officer (DPO) contact details,
performs passive pre-consent tracker and security header auditing,
and generates a professional corporate-style 8-page GRC audit PDF report.
Also available as an interactive web interface with dark mode and real-time progress streaming.

---

## What It Does

Most Indian websites are not yet compliant with the DPDP Act 2023,
India's first comprehensive data protection law. This tool
automatically crawls a website, runs 12 compliance checks derived
from statutory provisions of the Act, performs passive pre-consent tracker auditing,
verifies contact authenticity through multi-layer verification (DNS, MX, Wayback Machine, TRAI carrier records),
calculates a weighted risk score, and generates an executive PDF audit report — all in under 60 seconds.

---

## DPDP Rules Checked

| Rule ID  | Statutory Check                                            | Severity | Points | Legal Reference |
|----------|------------------------------------------------------------|----------|--------|-----------------|
| DPDP-01  | Privacy Policy Page Exists                                 | Critical | 25     | DPDP Act Sec. 5 |
| DPDP-02  | DPDP Act or Data Protection Law Referenced                 | High     | 15     | General Framework |
| DPDP-03  | DPO or Designated Contact Published                        | Critical | 20     | DPDP Act Sec. 8(9), 13 |
| DPDP-04  | Grievance Redressal Mechanism Documented                   | High     | 10     | DPDP Act Sec. 13 |
| DPDP-05  | Cookie Consent Banner / Notice Detected                    | Medium   | 10     | DPDP Act Sec. 6 |
| DPDP-06  | Data Retention & Erasure Policy Disclosed                  | Medium   | 8      | DPDP Act Sec. 8(7) |
| DPDP-07  | Data Principal Rights Documented (Access/Correction/Erasure) | High   | 5      | DPDP Act Ch. III |
| DPDP-08  | Third-Party Data Sharing Disclosed                         | Medium   | 2      | DPDP Act Sec. 6 |
| DPDP-09  | Contact Channel for Data Queries Present                   | Medium   | 1      | General Inquiries |
| DPDP-10  | Children's Data Processing Safeguards                      | Medium   | 2      | DPDP Act Sec. 9 |
| DPDP-11  | DPO / Contact Authenticity (Non-Placeholder Email)         | High     | 1      | Verification Layer |
| DPDP-12  | Officer Identity Verification (Non-Placeholder Name)       | Medium   | 1      | Verification Layer |

**Total: 100 points.** Score = 100 minus points for each failed check.  
Grade: A (90+) · B (75+) · C (60+) · D (45+) · F (<45)

> **Note on Scoring & Severity Heuristics:**  
> Point allocations (totaling 100) and severity ratings (Critical, High, Medium) are an engineering & risk governance heuristic devised for this audit tool to prioritize remediation, rather than statutory penalty schedules prescribed by the Act.

---

## Contact Authenticity Verification & Modes

Beyond checking whether compliance contacts are declared in the policy text, the tool validates authenticity across multiple layers:

| Layer | Check | Prospecting Mode (Default) | Client Mode (`--client-mode`) |
|-------|-------|----------------------------|-------------------------------|
| 1 | Placeholder detection (name, email, phone) | Active | Active |
| 2 | DNS domain resolution | Active | Active |
| 3 | MX record verification | Active | Active |
| 4 | SMTP reachability (live handshake on port 25) | Skipped (Zero outbound port 25) | Active (RCPT TO probe) |
| 5 | Domain consistency (email matches website domain) | Active | Active |
| 6 | Phone carrier verification (TRAI number series) | Active | Active |
| 7 | Historical comparison via Wayback Machine API | Active | Active |

- **Prospecting Mode (Default)**: Strictly passive, non-intrusive scanning suitable for unsolicited outreach and assessment. Outbound port 25 SMTP handshakes are disabled.
- **Client Mode**: Designed for authorized audits of contracted clients, enabling deep SMTP socket probing to confirm mailbox deliverability.

---

## Passive Pre-Consent Tracker & Security Audit

The scanner passively evaluates the target's first-load posture before any consent or user interaction:
- **Advertising & Analytics Trackers**: Flags third-party scripts (e.g. Meta Pixel, Google Analytics, Hotjar, TikTok Pixel, LinkedIn Insight Tag) that fire prior to consent.
- **Monitoring & APM Tools Separated**: Performance and error monitoring tools (New Relic, Datadog, Sentry) are categorized as engineering diagnostics and kept out of the ad tracker count to eliminate false positives.
- **Accurate Cookie Flag Evaluation**: Evaluates `Secure` and `SameSite` flags on cookies, and checks `HttpOnly` strictly on session-like authentication tokens (since JavaScript-set client cookies cannot carry `HttpOnly` by design).
- **HTTP Security Headers**: Checks for HSTS, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and framing/clickjacking defenses.

---

## Architecture

```
app.py              ← Flask web server (routes + SSE progress stream + dark mode)
scanner.py          ← CLI entry point (argparse)
    │
    ├── crawler.py      ← Playwright-based web crawler
    │       Fetches fully JS-rendered pages
    │       Extracts compliance links from footer
    │       Respects robots.txt and crawl delay
    │       Exponential backoff retry on failure
    │       Defensive error handling (no evasion — clean inconclusive reporting)
    │
    ├── tracker_audit.py ← Passive pre-consent tracker & security auditor
    │       Separates APM monitoring tools from ad trackers
    │       Cookie flags (HttpOnly session regex, Secure, SameSite)
    │       HTTP response security headers
    │
    ├── rules.py        ← 12 DPDP rule definitions with weights & heuristics
    │
    ├── auditor.py      ← Audit engine (12 DPDP rules)
    │       keyword_exact    — regex pattern matching
    │       keyword_context  — spaCy NLP sentence analysis
    │       email_pattern    — contact/DPO email detection
    │       homepage_html    — cookie banner detection
    │       contact_authentic — routes to verifier.py (with caching)
    │
    ├── verifier.py     ← Contact authenticity verifier
    │       DNS, MX, SMTP (client mode), carrier, placeholder, Wayback Machine
    │
    ├── scorer.py       ← Risk scoring engine
    │       Weighted deduction model (starts at 100)
    │       A/B/C/D/F grading with risk labels
    │       Prioritised remediation recommendations
    │
    └── reporter.py     ← PDF report generator
            Jinja2 HTML templating
            WeasyPrint / Playwright HTML → PDF conversion
            Professional corporate-style 8-page GRC output
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
```

---

## Usage

### Web Interface (Recommended)

```bash
python app.py
```

Open `http://localhost:5000` in your browser. Enter any domain,
click Scan Now, and watch the live progress stream. Features interactive
accordion details, filter pills, theme toggle (dark/light), and instant PDF report download.

### Command Line

```bash
# Standard prospecting scan (passive verification only)
python scanner.py flipkart.com

# Authorized client scan (enables active port 25 SMTP handshake)
python scanner.py clientcompany.com --client-mode

# Regenerate PDF from saved JSON (no re-crawl)
python scanner.py --from-json report_flipkart_com.json
```

---

## Output

Every scan produces:

1. **Real-time progress stream** — live log in the web UI
2. **Terminal summary** — score, grade, deductions, top recommendations
3. **JSON file** — machine-readable full report
4. **PDF report** — professional 8-page corporate GRC audit document

### PDF Report Structure (8 Pages)

| Page | Content |
|------|---------|
| 1 | Cover — Target URL, risk score gauge, grade, scan metadata |
| 2 | Executive summary — violation counts, score breakdown chart |
| 3 | Detailed findings — all 12 DPDP rules with pass/fail status and point deductions |
| 4 | Remediation recommendations — prioritised by severity |
| 5 | Scan metadata — crawled pages, character counts, errors, audit configuration |
| 6 | Contact authenticity verification — email, phone, name, Wayback Machine historical comparison |
| 7 | Passive pre-consent tracker & security audit — third-party trackers, APM diagnostics, cookie flags, security headers |
| 8 | Legal disclaimer and methodology limitations |

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
| PDF Engine       | Playwright / WeasyPrint         |
| Language         | Python 3.11                     |

---

## Limitations

- Automated analysis represents technical readiness indicators, not definitive legal conclusions.
- Sites behind aggressive WAF challenges that refuse headless browser access are classified as inconclusive to ensure legal defensibility without evasion.
- SMTP probing is restricted to authorized client audits; prospecting scans rely on passive DNS/MX records.
- Rules currently target English-language policy documentation.

---

## License

MIT License — free to use, modify, and distribute.

---

## Authors

**Niket**  
**Nikunj**