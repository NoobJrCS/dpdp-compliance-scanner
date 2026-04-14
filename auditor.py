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

# Module-level cache so verify_contacts() runs only ONCE per scan
# regardless of how many contact_authentic rules exist
_verification_cache = {}


# ---------------------------------------------------------------
# CHECK FUNCTIONS
# ---------------------------------------------------------------

def check_page_exists(crawl_result: dict, target_keyword: str) -> bool:
    """
    Returns True if the crawler found at least one page whose
    label contains the target_keyword.
    """
    for label in crawl_result["pages_found"].keys():
        if target_keyword.lower() in label.lower():
            return True
    return False


def check_keyword_exact(text: str, keywords: list) -> bool:
    """
    Returns True if ANY of the keywords are found in the text.
    Case-insensitive. Uses word boundaries to avoid partial matches.
    """
    text_lower = text.lower()
    for keyword in keywords:
        pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
        if re.search(pattern, text_lower):
            return True
    return False


def check_keyword_context(text: str, keywords: list) -> bool:
    """
    Uses spaCy to find keywords within their sentence context.
    Falls back to basic keyword search if spaCy isn't available.
    """
    if not SPACY_AVAILABLE:
        text_lower = text.lower()
        return any(kw.lower() in text_lower for kw in keywords)

    # Truncate very long texts — spaCy has memory limits
    text_sample   = text[:30000]
    text_lower_full = text.lower()

    # First pass: quick substring check (fast path)
    for keyword in keywords:
        if keyword.lower() in text_lower_full:
            return True

    # Second pass: spaCy sentence-level analysis
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
    """
    Searches for email addresses matching the given regex patterns.
    """
    text_lower = text.lower()
    for pattern in patterns:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            return True
    return False


def check_homepage_html(homepage_html: str, keywords: list) -> bool:
    """
    Checks the raw homepage HTML for cookie consent-related elements.
    """
    html_lower = homepage_html.lower()
    for keyword in keywords:
        if keyword.lower() in html_lower:
            return True
    return False


def check_contact_authentic(
    rule_id:     str,
    crawl_result: dict,
    base_url:    str
) -> bool:
    """
    NEW CHECK TYPE: Verifies that contact details found in the policy
    are real and not placeholder/dummy values.

    Uses verifier.py to run 5 sub-checks:
      1. Email is not a known placeholder
      2. Email domain exists in DNS
      3. Email domain matches company website
      4. Name is not a known placeholder
      5. Phone number is not a dummy value

    Results are cached so verify_contacts() runs only once per scan,
    regardless of how many contact_authentic rules exist (DPDP-11,
    DPDP-12 both call this function but share the same result).

    DPDP-11 checks email authenticity.
    DPDP-12 checks name authenticity.
    """
    global _verification_cache

    # Run verification only once, cache the result
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
        return False  # No text to verify = treat as failed

    verdict = verification.get("overall_verdict", "unverified")

    # DPDP-11 — Email authenticity
    if rule_id == "DPDP-11":
        # Pass if no email failures detected
        email_failures = [
            f for f in verification.get("failures", [])
            if f.lower().startswith("email")
        ]
        # Also pass if no emails found at all (DPDP-03 will handle the missing email case)
        if not verification.get("emails_found"):
            return False  # No email found to verify = fail
        return len(email_failures) == 0

    # DPDP-12 — Name authenticity
    if rule_id == "DPDP-12":
        name_failures = [
            f for f in verification.get("failures", [])
            if f.lower().startswith("name")
        ]
        if not verification.get("names_found"):
            return False  # No name found to verify = fail
        return len(name_failures) == 0

    return False


# ---------------------------------------------------------------
# HELPER: Get text for a given target_page setting
# ---------------------------------------------------------------

def get_text_for_target(crawl_result: dict, target_page: str) -> str:
    """
    Returns the appropriate text based on the rule's target_page setting.
    """
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
    Master audit function. Takes the crawler output and runs
    every rule from rules.py against it.

    Returns a dictionary of results, one entry per rule.
    """

    # Reset the verification cache for this scan
    global _verification_cache
    _verification_cache = {}

    base_url = crawl_result.get("base_url", "")

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

        # Route to the correct check function
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

        # Store result
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