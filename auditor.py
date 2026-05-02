# auditor.py
import re
import spacy
from rules import DPDP_RULES
from verifier import verify_contacts

# Load spaCy model once at module level
try:
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except OSError:
    print("[WARNING] spaCy model not found. Contextual checks will use basic keyword matching.")
    print("Run: python -m spacy download en_core_web_sm")
    SPACY_AVAILABLE = False

# Module-level cache — verify_contacts() runs only ONCE per scan
_verification_cache = {}


# ---------------------------------------------------------------
# CHECK FUNCTIONS
# ---------------------------------------------------------------

def check_page_exists(crawl_result: dict, target_keyword: str) -> bool:
    for label in crawl_result["pages_found"].keys():
        if target_keyword.lower() in label.lower():
            return True
    return False


def check_keyword_exact(text: str, keywords: list) -> bool:
    text_lower = text.lower()
    for keyword in keywords:
        pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
        if re.search(pattern, text_lower):
            return True
    return False


def check_keyword_context(text: str, keywords: list) -> bool:
    if not SPACY_AVAILABLE:
        text_lower = text.lower()
        return any(kw.lower() in text_lower for kw in keywords)

    text_sample    = text[:30000]
    text_lower_full = text.lower()

    for keyword in keywords:
        if keyword.lower() in text_lower_full:
            return True

    doc = nlp(text_sample)
    keyword_roots = set()
    for keyword in keywords:
        kw_doc = nlp(keyword)
        for token in kw_doc:
            if not token.is_stop:
                keyword_roots.add(token.lemma_.lower())

    for sent in doc.sents:
        sent_lemmas = {token.lemma_.lower() for token in sent if not token.is_stop}
        if keyword_roots.intersection(sent_lemmas):
            return True

    return False


def check_email_pattern(text: str, patterns: list) -> bool:
    text_lower = text.lower()
    for pattern in patterns:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            return True
    return False


def check_homepage_html(homepage_html: str, keywords: list) -> bool:
    html_lower = homepage_html.lower()
    for keyword in keywords:
        if keyword.lower() in html_lower:
            return True
    return False


def check_contact_authentic(
    rule_id:      str,
    crawl_result: dict,
    base_url:     str
) -> bool:
    """
    Routes DPDP-11 and DPDP-12 checks to verifier.py.
    Caches the verification result so verify_contacts() only
    runs once per scan regardless of how many rules use it.
    """
    global _verification_cache

    if base_url not in _verification_cache:
        all_text = "\n\n".join(
            page["text"]
            for page in crawl_result.get("pages_found", {}).values()
        )
        if not all_text:
            _verification_cache[base_url] = None
        else:
            _verification_cache[base_url] = verify_contacts(all_text, base_url)

    verification = _verification_cache.get(base_url)

    if verification is None:
        return False

    # DPDP-11 — Email authenticity
    if rule_id == "DPDP-11":
        if not verification.get("emails_found"):
            return False
        email_failures = [
            f for f in verification.get("failures", [])
            if f.lower().startswith("email")
        ]
        return len(email_failures) == 0

    # DPDP-12 — Name authenticity
    if rule_id == "DPDP-12":
        if not verification.get("names_found"):
            return False
        name_failures = [
            f for f in verification.get("failures", [])
            if f.lower().startswith("name")
        ]
        return len(name_failures) == 0

    return False


def get_verification_result(base_url: str) -> dict | None:
    """
    Returns the cached verification result for a given URL.
    Called by scanner.py after run_audit() to include the full
    verification data in the report dictionary for the PDF.
    Returns None if no verification was run (e.g. no pages crawled).
    """
    return _verification_cache.get(base_url)


# ---------------------------------------------------------------
# HELPER: Get text for a given target_page setting
# ---------------------------------------------------------------

def get_text_for_target(crawl_result: dict, target_page: str) -> str:
    pages = crawl_result.get("pages_found", {})

    if target_page == "homepage":
        return ""
    elif target_page == "any":
        return "\n\n---PAGE BREAK---\n\n".join(
            page["text"] for page in pages.values()
        )
    else:
        matched_texts = []
        for label, page_data in pages.items():
            if target_page.lower() in label.lower():
                matched_texts.append(page_data["text"])
        return "\n\n".join(matched_texts) if matched_texts else ""


# ---------------------------------------------------------------
# MASTER AUDIT RUNNER
# ---------------------------------------------------------------

def run_audit(
    crawl_result:  dict,
    homepage_html: str = ""
) -> dict:
    """
    Runs all DPDP rules against the crawled content.
    Returns a dict of {rule_id: {label, passed, severity, ...}}.
    """
    global _verification_cache
    _verification_cache = {}  # Reset cache for each new scan

    base_url     = crawl_result.get("base_url", "")
    audit_results = {}

    print(f"\n{'=' * 60}")
    print(f"  RUNNING DPDP COMPLIANCE AUDIT")
    print(f"  Target: {base_url}")
    print(f"  Rules to check: {len(DPDP_RULES)}")
    print(f"{'=' * 60}\n")

    for rule in DPDP_RULES:
        rule_id    = rule["id"]
        check_type = rule["check_type"]
        target     = rule["target_page"]
        keywords   = rule["keywords"]
        passed     = False

        text = get_text_for_target(crawl_result, target)

        if check_type == "page_exists":
            passed = check_page_exists(crawl_result, keywords[0])

        elif check_type == "keyword_exact":
            passed = check_keyword_exact(text, keywords) if text else False

        elif check_type == "keyword_context":
            passed = check_keyword_context(text, keywords) if text else False

        elif check_type == "email_pattern":
            passed = check_email_pattern(text, keywords) if text else False

        elif check_type == "homepage_html":
            passed = check_homepage_html(homepage_html, keywords) if homepage_html else False

        elif check_type == "contact_authentic":
            passed = check_contact_authentic(rule_id, crawl_result, base_url)

        audit_results[rule_id] = {
            "label":       rule["label"],
            "description": rule["description"],
            "severity":    rule["severity"],
            "passed":      passed,
            "check_type":  check_type
        }

        status_icon = "✅ PASS" if passed else "❌ FAIL"
        print(f"  [{rule_id}] {status_icon} — {rule['label']} ({rule['severity']})")

    print(f"\n{'=' * 60}\n")

    return audit_results