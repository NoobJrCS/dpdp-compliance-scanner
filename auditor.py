# auditor.py
import re
import spacy
from rules import DPDP_RULES

# Load spaCy model once at module level (loading it per-check would be very slow)
try:
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except OSError:
    print("[WARNING] spaCy model not found. Contextual checks will use basic keyword matching.")
    print("Run: python -m spacy download en_core_web_sm")
    SPACY_AVAILABLE = False

def check_page_exists(crawl_result: dict, target_keyword: str) -> bool:
    """
    Returns True if the crawler found at least one page whose 
    label contains the target_keyword.
    
    Example: target_keyword="privacy" matches "Privacy Policy", 
             "Privacy Notice", "Data Privacy" etc.
    """
    for label in crawl_result["pages_found"].keys():
        if target_keyword.lower() in label.lower():
            return True
    return False

def check_keyword_exact(text: str, keywords: list[str]) -> bool:
    """
    Returns True if ANY of the keywords are found in the text.
    Case-insensitive. Uses word boundaries to avoid partial matches.
    
    Example: keyword "dpo" won't match "depot" because of word boundaries.
    """
    text_lower = text.lower()
    
    for keyword in keywords:
        # re.escape handles special characters in the keyword
        # \b is a word boundary — ensures we match whole words only
        pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
        if re.search(pattern, text_lower):
            return True
    
    return False

def check_keyword_context(text: str, keywords: list[str]) -> bool:
    """
    Uses spaCy to find keywords within their sentence context.
    
    Why this is better than regex:
    - Understands that "our team handles grievances" is related to "grievance officer"
    - Works even when the exact phrase isn't present
    - Processes text sentence-by-sentence for accuracy
    
    Falls back to basic keyword search if spaCy isn't available.
    """
    
    # Fallback: if spaCy isn't available, do a simple substring check
    if not SPACY_AVAILABLE:
        text_lower = text.lower()
        return any(kw.lower() in text_lower for kw in keywords)
    
    # Truncate very long texts — spaCy has memory limits and legal 
    # policies can be 50,000+ characters. 30,000 chars is enough.
    text_sample = text[:30000]
    text_lower_full = text.lower()
    
    # First pass: quick substring check (fast)
    # If even a simple substring search finds nothing, no need for spaCy
    for keyword in keywords:
        if keyword.lower() in text_lower_full:
            return True  # Found it — no need to dig deeper
    
    # Second pass: spaCy sentence-level analysis
    # This catches paraphrased versions of our keywords
    doc = nlp(text_sample)
    
    # Build a set of root words from our keywords for fuzzy matching
    keyword_roots = set()
    for keyword in keywords:
        kw_doc = nlp(keyword)
        for token in kw_doc:
            if not token.is_stop:  # Ignore common words like "the", "a", "of"
                keyword_roots.add(token.lemma_.lower())  # lemma = root form of word
    
    # Check each sentence in the document
    for sent in doc.sents:
        sent_lemmas = {token.lemma_.lower() for token in sent if not token.is_stop}
        
        # If any keyword root appears in this sentence, it's a match
        if keyword_roots.intersection(sent_lemmas):
            return True
    
    return False

def check_email_pattern(text: str, patterns: list[str]) -> bool:
    """
    Searches for email addresses matching the given regex patterns.
    
    Can detect both:
    - Specific emails: grievance@company.com  (DPDP-03)
    - Any email:       contact@company.com    (DPDP-09)
    """
    text_lower = text.lower()
    
    for pattern in patterns:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            return True
    
    return False

def check_homepage_html(homepage_html: str, keywords: list[str]) -> bool:
    """
    Checks the raw homepage HTML for cookie consent-related 
    elements and text.
    
    Why raw HTML and not extracted text?
    Cookie banners are often hidden divs or loaded via JS. 
    Even if they're not visible as page text, their HTML 
    structure (class names, aria-labels, data attributes) 
    reveals their presence.
    
    Example: <div class="cookie-consent-banner"> is a strong signal
             even if the text inside is in an iframe.
    """
    html_lower = homepage_html.lower()
    
    for keyword in keywords:
        if keyword.lower() in html_lower:
            return True
    
    return False

def get_text_for_target(crawl_result: dict, target_page: str) -> str:
    """
    Returns the appropriate text based on the rule's target_page setting.
    
    - "any"      → concatenate ALL crawled page texts
    - "privacy"  → only text from pages with "privacy" in their label
    - "homepage" → returns empty string (homepage HTML handled separately)
    """
    pages = crawl_result.get("pages_found", {})
    
    if target_page == "homepage":
        return ""  # Homepage HTML is handled directly
    
    elif target_page == "any":
        # Combine all page texts with a separator
        return "\n\n---PAGE BREAK---\n\n".join(
            page["text"] for page in pages.values()
        )
    
    else:
        # Return text only from pages matching the target keyword
        matched_texts = []
        for label, page_data in pages.items():
            if target_page.lower() in label.lower():
                matched_texts.append(page_data["text"])
        
        return "\n\n".join(matched_texts) if matched_texts else ""
    
def run_audit(crawl_result: dict, homepage_html: str = "") -> dict:
    """
    Master audit function. Takes the crawler output and runs 
    every rule from rules.py against it.
    
    Returns a dictionary of results, one entry per rule.
    """
    
    audit_results = {}
    
    print(f"\n{'='*60}")
    print(f"  RUNNING DPDP COMPLIANCE AUDIT")
    print(f"  Target: {crawl_result.get('base_url', 'Unknown')}")
    print(f"  Rules to check: {len(DPDP_RULES)}")
    print(f"{'='*60}\n")
    
    for rule in DPDP_RULES:
        rule_id    = rule["id"]
        check_type = rule["check_type"]
        target     = rule["target_page"]
        keywords   = rule["keywords"]
        passed     = False  # Default to failed
        
        # Get the appropriate text for this rule
        text = get_text_for_target(crawl_result, target)
        
        # --- Route to the correct check function ---
        
        if check_type == "page_exists":
            passed = check_page_exists(crawl_result, keywords[0])
        
        elif check_type == "keyword_exact":
            if text:
                passed = check_keyword_exact(text, keywords)
            else:
                passed = False  # No text = no relevant page found
        
        elif check_type == "keyword_context":
            if text:
                passed = check_keyword_context(text, keywords)
            else:
                passed = False
        
        elif check_type == "email_pattern":
            if text:
                passed = check_email_pattern(text, keywords)
            else:
                passed = False
        
        elif check_type == "homepage_html":
            if homepage_html:
                passed = check_homepage_html(homepage_html, keywords)
            else:
                passed = False
        
        # Store result
        audit_results[rule_id] = {
            "label":       rule["label"],
            "description": rule["description"],
            "severity":    rule["severity"],
            "passed":      passed,
            "check_type":  check_type
        }
        
        # Print progress
        status_icon = "✅ PASS" if passed else "❌ FAIL"
        print(f"  [{rule_id}] {status_icon} — {rule['label']} ({rule['severity']})")
    
    print(f"\n{'='*60}\n")
    
    return audit_results