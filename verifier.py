# verifier.py
# ---------------------------------------------------------------
# Contact Authenticity Verifier
#
# Checks whether the Grievance Officer name, email, and phone
# number found in a privacy policy are real or fake/dummy.
#
# Verification is layered — multiple independent checks are run
# and each contributes to an overall authenticity verdict.
# ---------------------------------------------------------------

import re
import socket
import urllib.parse


# ---------------------------------------------------------------
# PLACEHOLDER PATTERNS
# These are strings commonly used as dummy/template values.
# Any match = immediate fake flag.
# ---------------------------------------------------------------

PLACEHOLDER_NAMES = [
    "john doe", "jane doe", "first last", "full name", "your name",
    "name here", "insert name", "tbd", "to be decided", "n/a", "na",
    "xxx", "yyy", "zzz", "test", "sample", "dummy", "placeholder",
    "contact person", "authorized person", "person name", "officer name",
    "grievance officer name", "data protection officer name",
    "enter name", "add name", "put name here"
]

PLACEHOLDER_EMAILS = [
    "example@example.com", "test@test.com", "email@email.com",
    "user@domain.com", "name@company.com", "abc@abc.com",
    "sample@sample.com", "dummy@dummy.com", "noreply@example.com",
    "contact@example.com", "admin@example.com", "info@example.com",
    "grievance@example.com", "youremail@domain.com",
    "email@yourcompany.com", "yourname@domain.com",
]

PLACEHOLDER_PHONES = [
    "0000000000", "1111111111", "2222222222", "3333333333",
    "4444444444", "5555555555", "6666666666", "7777777777",
    "8888888888", "9999999999", "1234567890", "9876543210",
    "0123456789", "9999999990", "0987654321",
    "00000000000", "99999999999",
]

# Free/personal email providers — suspicious for a corporate
# Grievance Officer (not an automatic fail, but flagged)
PERSONAL_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "live.com", "aol.com",
    "icloud.com", "protonmail.com", "zohomail.com"
]


# ---------------------------------------------------------------
# HELPER: Extract contact details from text
# ---------------------------------------------------------------

def extract_emails(text: str) -> list:
    """
    Extracts all email addresses from a block of text.
    Filters to ones near grievance/DPO-related keywords.
    """
    # Find all emails in the text
    all_emails = re.findall(
        r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}',
        text,
        re.IGNORECASE
    )

    # Prioritise emails near compliance-related keywords
    compliance_keywords = [
        "grievance", "dpo", "privacy", "data protection",
        "nodal", "officer", "compliance", "legal"
    ]

    priority_emails = []
    other_emails    = []

    for email in all_emails:
        # Check if this email appears near a keyword in the text
        email_pos = text.lower().find(email.lower())
        surrounding = text[max(0, email_pos - 150): email_pos + 150].lower()

        if any(kw in surrounding for kw in compliance_keywords):
            priority_emails.append(email)
        else:
            other_emails.append(email)

    # Return priority emails first, deduplicated
    seen = set()
    result = []
    for e in priority_emails + other_emails:
        if e.lower() not in seen:
            seen.add(e.lower())
            result.append(e)

    return result


def extract_phone_numbers(text: str) -> list:
    """
    Extracts Indian phone numbers from text.
    Handles formats: +91-XXXXXXXXXX, 91XXXXXXXXXX, 0XXXXXXXXXX, XXXXXXXXXX
    """
    patterns = [
        r'\+91[\s\-]?[6-9]\d{9}',    # +91-9876543210
        r'91[\s\-]?[6-9]\d{9}',       # 919876543210
        r'0[\s\-]?[6-9]\d{9}',        # 09876543210
        r'\b[6-9]\d{9}\b',            # 9876543210 (starts with 6-9)
    ]

    found = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        found.extend(matches)

    # Normalise: strip all non-digit characters, keep last 10 digits
    normalised = []
    seen = set()
    for num in found:
        digits = re.sub(r'\D', '', num)
        last10 = digits[-10:] if len(digits) >= 10 else digits
        if last10 not in seen:
            seen.add(last10)
            normalised.append(last10)

    return normalised


def extract_person_names(text: str) -> list:
    """
    Extracts likely person names near Grievance Officer mentions.
    Uses pattern: looks for capitalized words near keyword context.
    """
    # Find lines/sentences mentioning the grievance officer
    lines = text.split('\n')
    candidate_lines = []

    for line in lines:
        line_lower = line.lower()
        if any(kw in line_lower for kw in [
            "grievance officer", "data protection officer",
            "dpo", "nodal officer", "officer name", "name:"
        ]):
            candidate_lines.append(line)

    # Extract capitalized word sequences (likely names) from those lines
    names = []
    for line in candidate_lines:
        # Match 2-4 consecutive capitalized words (e.g. "Rahul Kumar Sharma")
        matches = re.findall(
            r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,3})\b',
            line
        )
        names.extend(matches)

    return list(set(names))


# ---------------------------------------------------------------
# VERIFICATION CHECKS
# ---------------------------------------------------------------

def check_email_placeholder(email: str) -> dict:
    """
    Check 1: Is this email a known placeholder/template value?
    """
    if email.lower() in PLACEHOLDER_EMAILS:
        return {
            "passed": False,
            "reason": f"'{email}' is a known placeholder email address."
        }
    return {"passed": True, "reason": "Not a known placeholder."}


def check_email_domain_exists(email: str) -> dict:
    """
    Check 2: Does the email domain actually exist?
    Performs a DNS lookup on the domain portion of the email.
    A domain with no DNS record cannot receive email.
    """
    try:
        domain = email.split("@")[1].lower()
    except IndexError:
        return {"passed": False, "reason": "Email format is invalid."}

    try:
        # Try to resolve the domain — if it fails, domain doesn't exist
        socket.gethostbyname(domain)
        return {
            "passed": True,
            "reason": f"Domain '{domain}' resolves successfully."
        }
    except socket.gaierror:
        return {
            "passed": False,
            "reason": f"Domain '{domain}' does not exist or cannot be resolved."
        }


def check_email_domain_consistency(email: str, base_url: str) -> dict:
    """
    Check 3: Does the email domain match the website's domain?
    e.g. grievance@flipkart.com on flipkart.com = consistent ✅
         grievance@gmail.com on flipkart.com     = suspicious ⚠️
         grievance@walmart.com on flipkart.com   = inconsistent ❌

    Note: This is a WARNING, not an automatic failure.
    Some companies legitimately use parent company or
    third-party compliance platform emails.
    """
    try:
        email_domain   = email.split("@")[1].lower()
        website_domain = urllib.parse.urlparse(base_url).netloc.lower()

        # Strip www. prefix for comparison
        website_domain = website_domain.replace("www.", "")
        # Get base domain (e.g. "flipkart.com" from "seller.flipkart.com")
        website_base   = ".".join(website_domain.split(".")[-2:])
        email_base     = ".".join(email_domain.split(".")[-2:])

        if email_base == website_base:
            return {
                "passed":  True,
                "warning": False,
                "reason":  f"Email domain '{email_domain}' matches website domain."
            }
        elif email_domain in PERSONAL_EMAIL_PROVIDERS:
            return {
                "passed":  True,   # Not a hard fail — some small businesses use Gmail
                "warning": True,
                "reason":  (
                    f"'{email_domain}' is a personal email provider. "
                    f"A corporate compliance email is expected for larger organisations."
                )
            }
        else:
            return {
                "passed":  True,   # Could be a parent company — not a hard fail
                "warning": True,
                "reason":  (
                    f"Email domain '{email_domain}' doesn't match "
                    f"website domain '{website_base}'. "
                    f"Could be a parent company or third-party platform."
                )
            }
    except Exception as e:
        return {"passed": True, "warning": False, "reason": f"Could not compare domains: {e}"}


def check_name_placeholder(name: str) -> dict:
    """
    Check 4: Is this name a known placeholder/template value?
    """
    if name.lower().strip() in PLACEHOLDER_NAMES:
        return {
            "passed": False,
            "reason": f"'{name}' is a known placeholder name."
        }

    # Also flag very short names (single word < 3 chars) as suspicious
    words = name.strip().split()
    if len(words) == 1 and len(words[0]) < 3:
        return {
            "passed": False,
            "reason": f"'{name}' is too short to be a real person's name."
        }

    return {"passed": True, "reason": "Name does not match known placeholders."}


def check_phone_placeholder(phone: str) -> dict:
    """
    Check 5: Is this phone number a known dummy value?
    Checks for repeating digits, sequential numbers, known fakes.
    """
    digits = re.sub(r'\D', '', phone)
    last10 = digits[-10:] if len(digits) >= 10 else digits

    # Check against known placeholder numbers
    if last10 in PLACEHOLDER_PHONES:
        return {
            "passed": False,
            "reason": f"'{phone}' is a known placeholder phone number."
        }

    # Check for repeating digit pattern (e.g. 9898989898, 1234512345)
    if len(set(last10)) <= 2:
        return {
            "passed": False,
            "reason": f"'{phone}' appears to use repeating digits — likely fake."
        }

    # Check for sequential digits (12345678, 98765432)
    ascending  = "0123456789"
    descending = "9876543210"
    if last10 in ascending * 2 or last10 in descending * 2:
        return {
            "passed": False,
            "reason": f"'{phone}' appears to be a sequential number — likely fake."
        }

    # Valid Indian mobile numbers start with 6, 7, 8, or 9
    if last10[0] not in "6789":
        return {
            "passed": False,
            "reason": f"'{phone}' does not start with 6–9. Not a valid Indian mobile number."
        }

    return {"passed": True, "reason": "Phone number appears legitimate."}


# ---------------------------------------------------------------
# MASTER VERIFIER
# ---------------------------------------------------------------

def verify_contacts(text: str, base_url: str) -> dict:
    """
    Master function. Extracts all contact details from the policy
    text and runs all authenticity checks on each one.

    Returns a structured verification report dictionary.
    """

    print("  Running contact authenticity verification...")

    emails = extract_emails(text)
    phones = extract_phone_numbers(text)
    names  = extract_person_names(text)

    results = {
        "emails_found":  emails,
        "phones_found":  phones,
        "names_found":   names,
        "email_checks":  [],
        "phone_checks":  [],
        "name_checks":   [],
        "overall_verdict": "unverified",
        "warnings":      [],
        "failures":      []
    }

    # ── Email Checks ────────────────────────────────────────────
    for email in emails[:5]:  # Check up to 5 emails max
        check_result = {
            "email":  email,
            "checks": {}
        }

        # Run all 3 email checks
        ph = check_email_placeholder(email)
        de = check_email_domain_exists(email)
        dc = check_email_domain_consistency(email, base_url)

        check_result["checks"]["is_placeholder"]      = ph
        check_result["checks"]["domain_exists"]       = de
        check_result["checks"]["domain_consistency"]  = dc

        # Collect failures and warnings
        if not ph["passed"]:
            results["failures"].append(f"Email '{email}': {ph['reason']}")
        if not de["passed"]:
            results["failures"].append(f"Email '{email}': {de['reason']}")
        if dc.get("warning"):
            results["warnings"].append(f"Email '{email}': {dc['reason']}")

        results["email_checks"].append(check_result)

    # ── Phone Checks ────────────────────────────────────────────
    for phone in phones[:3]:  # Check up to 3 phones max
        pp = check_phone_placeholder(phone)
        results["phone_checks"].append({
            "phone":  phone,
            "checks": {"is_placeholder": pp}
        })
        if not pp["passed"]:
            results["failures"].append(f"Phone '{phone}': {pp['reason']}")

    # ── Name Checks ─────────────────────────────────────────────
    for name in names[:3]:  # Check up to 3 names max
        np_ = check_name_placeholder(name)
        results["name_checks"].append({
            "name":   name,
            "checks": {"is_placeholder": np_}
        })
        if not np_["passed"]:
            results["failures"].append(f"Name '{name}': {np_['reason']}")

    # ── Overall Verdict ─────────────────────────────────────────
    has_failures = len(results["failures"]) > 0
    has_warnings = len(results["warnings"]) > 0
    nothing_found = not emails and not phones and not names

    if nothing_found:
        results["overall_verdict"] = "no_contacts_found"
    elif has_failures:
        results["overall_verdict"] = "fake_detected"
    elif has_warnings:
        results["overall_verdict"] = "suspicious"
    else:
        results["overall_verdict"] = "authentic"

    # ── Terminal Summary ─────────────────────────────────────────
    verdict_display = {
        "authentic":         "✅ AUTHENTIC   — Contact details appear genuine",
        "suspicious":        "⚠️  SUSPICIOUS  — Contact details have concerns",
        "fake_detected":     "❌ FAKE/DUMMY  — Placeholder contact details detected",
        "no_contacts_found": "❓ NOT FOUND   — No contact details could be extracted"
    }

    print(f"\n  Contact Verification Result:")
    print(f"  {verdict_display.get(results['overall_verdict'], 'Unknown')}")

    if results["failures"]:
        print(f"\n  Issues found:")
        for f in results["failures"]:
            print(f"    ✗ {f}")

    if results["warnings"]:
        print(f"\n  Warnings:")
        for w in results["warnings"]:
            print(f"    ⚠ {w}")

    print()
    return results