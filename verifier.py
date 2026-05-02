# verifier.py
# ---------------------------------------------------------------
# Contact Authenticity Verifier
#
# Checks whether the Grievance Officer name, email, and phone
# number found in a privacy policy are real or fake/dummy.
#
# Verification layers:
#   1. Placeholder detection       (name, email, phone)
#   2. DNS domain resolution       (email domain exists?)
#   3. MX record check             (domain can receive email?)
#   4. SMTP reachability           (email address accepted?)
#   5. Domain consistency          (email matches website?)
#   6. Phone carrier verification  (valid Indian number series?)
#   7. Historical verification     (Wayback Machine snapshot)
# ---------------------------------------------------------------

import re
import socket
import urllib.parse
import smtplib
import requests


# ---------------------------------------------------------------
# PLACEHOLDER LISTS
# ---------------------------------------------------------------

PLACEHOLDER_NAMES = [
    "john doe", "jane doe", "first last", "full name", "your name",
    "name here", "insert name", "tbd", "to be decided", "n/a", "na",
    "xxx", "yyy", "zzz", "test", "sample", "dummy", "placeholder",
    "contact person", "authorized person", "person name", "officer name",
    "grievance officer name", "data protection officer name",
    "enter name", "add name", "put name here", "ram kumar",
    "suresh sharma", "rajesh singh", "amit kumar", "nodal officer"
]

PLACEHOLDER_EMAILS = [
    "example@example.com", "test@test.com", "email@email.com",
    "user@domain.com", "name@company.com", "abc@abc.com",
    "sample@sample.com", "dummy@dummy.com", "noreply@example.com",
    "contact@example.com", "admin@example.com", "info@example.com",
    "grievance@example.com", "youremail@domain.com",
    "email@yourcompany.com", "yourname@domain.com",
    "grievance@abc.com", "dpo@xyz.com",
    "contact@abccompany.com", "legal@yourcompany.com"
]

PLACEHOLDER_PHONES = [
    "0000000000", "1111111111", "2222222222", "3333333333",
    "4444444444", "5555555555", "6666666666", "7777777777",
    "8888888888", "9999999999", "1234567890", "9876543210",
    "0123456789", "9999999990", "0987654321",
    "00000000000", "99999999999",
]

PERSONAL_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "live.com", "aol.com",
    "icloud.com", "protonmail.com", "zohomail.com"
]

# ---------------------------------------------------------------
# INDIAN MOBILE NUMBER SERIES
# Source: TRAI number series allocation
# Key: first 4 digits of 10-digit mobile number
# ---------------------------------------------------------------
INDIAN_NUMBER_SERIES = {
    # Airtel
    "9810": "Airtel", "9811": "Airtel", "9818": "Airtel",
    "9868": "Airtel", "9871": "Airtel", "9999": "Airtel",
    "7011": "Airtel", "7012": "Airtel", "7015": "Airtel",
    "9870": "Airtel", "9899": "Airtel", "8010": "Airtel",
    # Jio
    "7000": "Jio", "7001": "Jio", "7002": "Jio",
    "7003": "Jio", "7004": "Jio", "7005": "Jio",
    "6000": "Jio", "6001": "Jio", "6002": "Jio",
    "6003": "Jio", "6004": "Jio", "6005": "Jio",
    "8955": "Jio", "8956": "Jio", "8957": "Jio",
    # Vi (Vodafone Idea)
    "9820": "Vi", "9821": "Vi", "9833": "Vi",
    "9867": "Vi", "9892": "Vi", "7208": "Vi",
    "7209": "Vi", "7666": "Vi", "8097": "Vi",
    "8976": "Vi", "9769": "Vi",
    # BSNL
    "9415": "BSNL", "9416": "BSNL", "9417": "BSNL",
    "9418": "BSNL", "9419": "BSNL", "9420": "BSNL",
    "7006": "BSNL", "9436": "BSNL", "9437": "BSNL",
    "9438": "BSNL",
}


# ---------------------------------------------------------------
# EXTRACTION HELPERS
# ---------------------------------------------------------------

def extract_emails(text: str) -> list:
    """
    Extracts all email addresses from text.
    Prioritises emails near compliance-related keywords.
    """
    all_emails = re.findall(
        r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}',
        text,
        re.IGNORECASE
    )

    compliance_keywords = [
        "grievance", "dpo", "privacy", "data protection",
        "nodal", "officer", "compliance", "legal"
    ]

    priority_emails = []
    other_emails    = []

    for email in all_emails:
        email_pos   = text.lower().find(email.lower())
        surrounding = text[max(0, email_pos - 150): email_pos + 150].lower()
        if any(kw in surrounding for kw in compliance_keywords):
            priority_emails.append(email)
        else:
            other_emails.append(email)

    seen   = set()
    result = []
    for e in priority_emails + other_emails:
        if e.lower() not in seen:
            seen.add(e.lower())
            result.append(e)

    return result


def extract_phone_numbers(text: str) -> list:
    """
    Extracts Indian phone numbers from text.
    Returns last-10-digit normalised strings.
    """
    patterns = [
        r'\+91[\s\-]?[6-9]\d{9}',
        r'91[\s\-]?[6-9]\d{9}',
        r'0[\s\-]?[6-9]\d{9}',
        r'\b[6-9]\d{9}\b',
    ]

    found = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text))

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
    """
    lines = text.split('\n')
    candidate_lines = []

    for line in lines:
        line_lower = line.lower()
        if any(kw in line_lower for kw in [
            "grievance officer", "data protection officer",
            "dpo", "nodal officer", "officer name", "name:"
        ]):
            candidate_lines.append(line)

    names = []
    for line in candidate_lines:
        matches = re.findall(
            r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,3})\b',
            line
        )
        names.extend(matches)

    return list(set(names))


# ---------------------------------------------------------------
# EMAIL CHECKS
# ---------------------------------------------------------------

def check_email_placeholder(email: str) -> dict:
    """Check 1: Is this a known placeholder email?"""
    if email.lower() in PLACEHOLDER_EMAILS:
        return {
            "passed": False,
            "reason": f"'{email}' is a known placeholder email address."
        }
    return {"passed": True, "reason": "Not a known placeholder."}


def check_email_domain_exists(email: str) -> dict:
    """Check 2: Does the email domain resolve in DNS?"""
    try:
        domain = email.split("@")[1].lower()
    except IndexError:
        return {"passed": False, "reason": "Email format is invalid."}

    try:
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


def check_mx_record(email: str) -> dict:
    """
    Check 3: Does the email domain have MX records?
    A domain can exist in DNS but have no mail server configured.
    MX records confirm the domain is set up to actually receive email.
    Uses dnspython if installed, falls back to port 25 socket check.
    """
    try:
        domain = email.split("@")[1].lower()
    except IndexError:
        return {"passed": False, "reason": "Email format is invalid."}

    try:
        import dns.resolver
        dns.resolver.resolve(domain, 'MX')
        return {
            "passed": True,
            "reason": f"'{domain}' has valid MX records — can receive email."
        }
    except ImportError:
        pass
    except Exception:
        return {
            "passed": False,
            "reason": f"'{domain}' has no MX records — cannot receive email."
        }

    # Fallback: try port 25 socket check
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(domain, 25)
        return {
            "passed": True,
            "reason": f"'{domain}' appears to have a mail server (port 25 reachable)."
        }
    except socket.gaierror:
        return {
            "passed": False,
            "reason": f"'{domain}' does not appear to have a mail server configured."
        }


def check_smtp_reachable(email: str) -> dict:
    """
    Check 4: SMTP Reachability Check.

    Performs a real SMTP handshake to verify the email address
    is accepted by the mail server — WITHOUT sending any email.

    Steps:
      1. Looks up MX record to find the mail server
      2. Opens SMTP connection on port 25
      3. Sends HELO + MAIL FROM + RCPT TO
      4. Reads server response code
      5. Closes immediately — no email is sent

    Response codes:
      250 = Address accepted  → PASS
      550 = Address rejected  → FAIL (mailbox doesn't exist)
      Other / timeout         → INCONCLUSIVE (not a failure)

    Most large servers block SMTP probing — inconclusive is
    the expected result for Gmail, Microsoft, etc. We never
    penalise for an inconclusive result.
    """
    try:
        domain = email.split("@")[1].lower()
    except IndexError:
        return {"passed": False, "conclusive": True, "reason": "Email format is invalid."}

    mail_server = domain

    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_sorted  = sorted(mx_records, key=lambda r: r.preference)
        mail_server = str(mx_sorted[0].exchange).rstrip('.')
    except Exception:
        pass

    try:
        smtp = smtplib.SMTP(timeout=8)
        smtp.connect(mail_server, 25)
        smtp.helo("dpdpscanner.verify")
        smtp.mail("verify@dpdpscanner.in")
        code, message = smtp.rcpt(email)
        smtp.quit()

        if code == 250:
            return {
                "passed":     True,
                "conclusive": True,
                "reason":     f"SMTP server accepted '{email}' (code 250) — address exists."
            }
        elif code == 550:
            return {
                "passed":     False,
                "conclusive": True,
                "reason":     f"SMTP server rejected '{email}' (code 550) — mailbox does not exist."
            }
        else:
            return {
                "passed":     True,
                "conclusive": False,
                "reason":     f"SMTP response inconclusive (code {code})."
            }

    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected,
            ConnectionRefusedError, OSError) as e:
        return {
            "passed":     True,
            "conclusive": False,
            "reason":     f"SMTP check inconclusive — server likely blocks probing: {e}"
        }
    except Exception as e:
        return {
            "passed":     True,
            "conclusive": False,
            "reason":     f"SMTP check failed unexpectedly: {e}"
        }


def check_email_domain_consistency(email: str, base_url: str) -> dict:
    """Check 5: Does the email domain match the website domain?"""
    try:
        email_domain   = email.split("@")[1].lower()
        website_domain = urllib.parse.urlparse(base_url).netloc.lower()
        website_domain = website_domain.replace("www.", "")
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
                "passed":  True,
                "warning": True,
                "reason":  (
                    f"'{email_domain}' is a personal email provider. "
                    f"A corporate compliance email is expected."
                )
            }
        else:
            return {
                "passed":  True,
                "warning": True,
                "reason":  (
                    f"Email domain '{email_domain}' doesn't match "
                    f"website domain '{website_base}'. "
                    f"May be a parent company or third-party platform."
                )
            }
    except Exception as e:
        return {"passed": True, "warning": False, "reason": f"Could not compare domains: {e}"}


# ---------------------------------------------------------------
# PHONE CHECKS
# ---------------------------------------------------------------

def check_phone_placeholder(phone: str) -> dict:
    """Check: Is this a known dummy phone number?"""
    digits = re.sub(r'\D', '', phone)
    last10 = digits[-10:] if len(digits) >= 10 else digits

    if last10 in PLACEHOLDER_PHONES:
        return {"passed": False, "reason": f"'{phone}' is a known placeholder phone number."}

    if len(set(last10)) <= 2:
        return {"passed": False, "reason": f"'{phone}' uses repeating digits — likely fake."}

    ascending  = "0123456789"
    descending = "9876543210"
    if last10 in ascending * 2 or last10 in descending * 2:
        return {"passed": False, "reason": f"'{phone}' is a sequential number — likely fake."}

    if last10 and last10[0] not in "6789":
        return {"passed": False, "reason": f"'{phone}' does not start with 6–9. Invalid Indian mobile."}

    return {"passed": True, "reason": "Phone number passes basic validation."}


def check_phone_carrier(phone: str) -> dict:
    """
    Check: Phone Number Carrier Verification.

    Validates whether the phone number belongs to a known Indian
    telecom operator using TRAI number series (first 4 digits).

    If the series is found → returns operator name (Airtel/Jio/Vi/BSNL).
    If not found → warning (not hard failure — our list isn't exhaustive).
    """
    digits = re.sub(r'\D', '', phone)
    last10 = digits[-10:] if len(digits) >= 10 else digits

    if len(last10) < 10:
        return {"passed": False, "operator": None, "reason": "Number is less than 10 digits — invalid."}

    first4 = last10[:4]

    if first4 in INDIAN_NUMBER_SERIES:
        operator = INDIAN_NUMBER_SERIES[first4]
        return {
            "passed":   True,
            "operator": operator,
            "reason":   f"Valid number series. Operator: {operator}."
        }
    else:
        return {
            "passed":   True,
            "warning":  True,
            "operator": None,
            "reason":   (
                f"Number series '{first4}' not in known TRAI allocations. "
                f"May still be valid — treating as a warning."
            )
        }


# ---------------------------------------------------------------
# NAME CHECKS
# ---------------------------------------------------------------

def check_name_placeholder(name: str) -> dict:
    """Check: Is this a known placeholder name?"""
    if name.lower().strip() in PLACEHOLDER_NAMES:
        return {"passed": False, "reason": f"'{name}' is a known placeholder name."}

    words = name.strip().split()
    if len(words) == 1 and len(words[0]) < 3:
        return {"passed": False, "reason": f"'{name}' is too short to be a real person's name."}

    return {"passed": True, "reason": "Name does not match known placeholders."}


# ---------------------------------------------------------------
# HISTORICAL VERIFICATION
# ---------------------------------------------------------------

def check_wayback_history(base_url: str, current_emails: list) -> dict:
    """
    Historical Verification using the Wayback Machine API.

    Checks whether the privacy policy existed 6–12 months ago
    and whether contact details have changed since then.

    Steps:
      1. Queries Wayback Machine CDX API for 2024 snapshots
      2. Fetches the archived page text
      3. Extracts compliance emails from the snapshot
      4. Compares historical vs current emails
      5. Flags if email changed (could mean old address bounced)

    A changed email is a WARNING not a failure — companies
    legitimately update contact details. But unexplained changes
    are worth flagging for manual review.
    """
    privacy_url = base_url.rstrip("/") + "/privacy-policy"
    result = {
        "checked":           False,
        "snapshot_found":    False,
        "snapshot_url":      None,
        "snapshot_date":     None,
        "historical_emails": [],
        "emails_changed":    False,
        "reason":            ""
    }

    try:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={urllib.parse.quote(privacy_url)}"
            f"&output=json"
            f"&limit=1"
            f"&from=20240101"
            f"&to=20241231"
            f"&filter=statuscode:200"
            f"&fl=timestamp,original"
        )

        response = requests.get(cdx_url, timeout=8)
        response.raise_for_status()
        data = response.json()

        result["checked"] = True

        if not data or len(data) < 2:
            result["reason"] = (
                "No archived snapshot found for this URL in 2024. "
                "Cannot perform historical comparison."
            )
            return result

        timestamp    = data[1][0]
        original_url = data[1][1]
        snapshot_date = f"{timestamp[6:8]}/{timestamp[4:6]}/{timestamp[:4]}"
        snapshot_url  = f"https://web.archive.org/web/{timestamp}/{original_url}"

        result["snapshot_found"] = True
        result["snapshot_url"]   = snapshot_url
        result["snapshot_date"]  = snapshot_date

        snap_response = requests.get(snapshot_url, timeout=10)
        snap_text     = snap_response.text

        historical_emails = re.findall(
            r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}',
            snap_text,
            re.IGNORECASE
        )
        compliance_historical = [
            e for e in historical_emails
            if any(kw in e.lower() for kw in [
                "grievance", "dpo", "privacy", "legal", "compliance"
            ])
        ]

        result["historical_emails"] = list(set(compliance_historical))

        current_set    = set(e.lower() for e in current_emails)
        historical_set = set(e.lower() for e in compliance_historical)

        if historical_set and current_set:
            if historical_set != current_set:
                added   = current_set - historical_set
                removed = historical_set - current_set
                result["emails_changed"] = True
                result["reason"] = (
                    f"Email addresses changed since {snapshot_date}. "
                    f"Removed: {removed or 'none'}. "
                    f"Added: {added or 'none'}."
                )
            else:
                result["reason"] = (
                    f"Contact details consistent with snapshot from {snapshot_date}."
                )
        elif not historical_set:
            result["reason"] = (
                f"Snapshot found ({snapshot_date}) but no compliance "
                f"emails were present in the archived version."
            )
        else:
            result["reason"] = (
                f"Historical snapshot from {snapshot_date} found. "
                f"Could not compare — no current emails extracted."
            )

    except requests.exceptions.Timeout:
        result["reason"] = "Wayback Machine API timed out. Historical check skipped."
    except requests.exceptions.ConnectionError:
        result["reason"] = "Could not reach Wayback Machine. Historical check skipped."
    except Exception as e:
        result["reason"] = f"Historical check failed: {e}"

    return result


# ---------------------------------------------------------------
# MASTER VERIFIER
# ---------------------------------------------------------------

def verify_contacts(text: str, base_url: str) -> dict:
    """
    Master function. Extracts all contact details and runs
    all authenticity checks on each one.

    Returns a complete structured verification report.
    """
    print("  Running contact authenticity verification...")

    emails = extract_emails(text)
    phones = extract_phone_numbers(text)
    names  = extract_person_names(text)

    results = {
        "emails_found":    emails,
        "phones_found":    phones,
        "names_found":     names,
        "email_checks":    [],
        "phone_checks":    [],
        "name_checks":     [],
        "history":         {},
        "overall_verdict": "unverified",
        "warnings":        [],
        "failures":        []
    }

    # ── Email Checks ─────────────────────────────────────────────
    for email in emails[:5]:
        ph   = check_email_placeholder(email)
        de   = check_email_domain_exists(email)
        mx   = check_mx_record(email)
        smtp = check_smtp_reachable(email)
        dc   = check_email_domain_consistency(email, base_url)

        results["email_checks"].append({
            "email": email,
            "checks": {
                "is_placeholder":     ph,
                "domain_exists":      de,
                "mx_record":          mx,
                "smtp_reachable":     smtp,
                "domain_consistency": dc
            }
        })

        if not ph["passed"]:
            results["failures"].append(f"Email '{email}': {ph['reason']}")
        if not de["passed"]:
            results["failures"].append(f"Email '{email}': {de['reason']}")
        if not mx["passed"]:
            results["failures"].append(f"Email '{email}': {mx['reason']}")
        if not smtp["passed"] and smtp.get("conclusive"):
            results["failures"].append(f"Email '{email}': {smtp['reason']}")
        if dc.get("warning"):
            results["warnings"].append(f"Email '{email}': {dc['reason']}")

    # ── Phone Checks ─────────────────────────────────────────────
    for phone in phones[:3]:
        pp      = check_phone_placeholder(phone)
        carrier = check_phone_carrier(phone)

        results["phone_checks"].append({
            "phone": phone,
            "checks": {
                "is_placeholder": pp,
                "carrier":        carrier
            }
        })

        if not pp["passed"]:
            results["failures"].append(f"Phone '{phone}': {pp['reason']}")
        if carrier.get("warning"):
            results["warnings"].append(f"Phone '{phone}': {carrier['reason']}")
        if carrier.get("operator"):
            print(f"  [PHONE] {phone} → Operator: {carrier['operator']}")

    # ── Name Checks ──────────────────────────────────────────────
    for name in names[:3]:
        np_ = check_name_placeholder(name)
        results["name_checks"].append({
            "name":   name,
            "checks": {"is_placeholder": np_}
        })
        if not np_["passed"]:
            results["failures"].append(f"Name '{name}': {np_['reason']}")

    # ── Historical Verification ───────────────────────────────────
    print("  Running historical verification via Wayback Machine...")
    history = check_wayback_history(base_url, emails)
    results["history"] = history

    if history.get("emails_changed"):
        results["warnings"].append(f"Historical: {history['reason']}")
    elif history.get("snapshot_found"):
        print(f"  [HISTORY] {history['reason']}")

    # ── Overall Verdict ───────────────────────────────────────────
    nothing_found = not emails and not phones and not names

    if nothing_found:
        results["overall_verdict"] = "no_contacts_found"
    elif results["failures"]:
        results["overall_verdict"] = "fake_detected"
    elif results["warnings"]:
        results["overall_verdict"] = "suspicious"
    else:
        results["overall_verdict"] = "authentic"

    # ── Terminal Summary ──────────────────────────────────────────
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