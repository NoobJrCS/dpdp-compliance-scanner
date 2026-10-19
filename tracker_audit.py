# tracker_audit.py
# ---------------------------------------------------------------
# Passive pre-consent tracker + security-indicator auditor.
#
# WHAT IT DOES (all passive — equivalent to one visitor opening the
# homepage in a browser, with NO clicks and NO probing):
#   1. Loads the page in headless Chromium without interacting.
#   2. Logs every outgoing network request and flags third-party
#      requests that match a known tracker list.
#   3. Reads the cookie jar BEFORE any consent interaction.
#   4. Inspects main-document response headers (HSTS, CSP, etc.).
#   5. Inspects <form> elements for insecure submission targets.
#
# WHAT IT CANNOT PROVE:
#   - That personal data was actually transmitted (only that a
#     request to a tracker domain fired before any interaction).
#   - That a banner was ignored (the site may use a consent tool
#     that blocks scripts server-side or by region).
#   - Legal non-compliance. Findings are READINESS INDICATORS.
#
# Usage:
#   python tracker_audit.py example.com
#   python tracker_audit.py http://localhost:8000/tests/consent_test_page.html
#   python tracker_audit.py example.com --json
# ---------------------------------------------------------------

import sys
import json
import time
import argparse
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

try:
    from robots_check import is_scraping_allowed
except ImportError:           # lets the module run standalone
    def is_scraping_allowed(base_url, path="/"):
        return True


# ---------------------------------------------------------------
# TRACKER RULES
# (host_suffix, path_prefix_or_None, display_name, category)
# Path prefix is used where the host is also used for non-tracking
# purposes (e.g. facebook.com is also used for login widgets).
# ---------------------------------------------------------------
TRACKER_RULES = [
    # Google
    ("google-analytics.com",      None,   "Google Analytics",        "analytics"),
    ("analytics.google.com",      None,   "Google Analytics",        "analytics"),
    ("googletagmanager.com",      None,   "Google Tag Manager",      "tag_manager"),
    ("doubleclick.net",           None,   "Google DoubleClick",      "advertising"),
    ("googleadservices.com",      None,   "Google Ads",              "advertising"),
    ("googlesyndication.com",     None,   "Google AdSense",          "advertising"),
    # Meta
    ("connect.facebook.net",      None,   "Meta Pixel SDK",          "advertising"),
    ("facebook.com",              "/tr",  "Meta Pixel beacon",       "advertising"),
    # Microsoft
    ("clarity.ms",                None,   "Microsoft Clarity",       "session_replay"),
    ("bat.bing.com",              None,   "Microsoft Ads (Bing UET)","advertising"),
    # Session replay / heatmaps
    ("hotjar.com",                None,   "Hotjar",                  "session_replay"),
    ("hotjar.io",                 None,   "Hotjar",                  "session_replay"),
    ("fullstory.com",             None,   "FullStory",               "session_replay"),
    ("mouseflow.com",             None,   "Mouseflow",               "session_replay"),
    ("smartlook.com",             None,   "Smartlook",               "session_replay"),
    ("crazyegg.com",              None,   "Crazy Egg",               "session_replay"),
    # Product analytics
    ("mixpanel.com",              None,   "Mixpanel",                "analytics"),
    ("mxpnl.com",                 None,   "Mixpanel (CDN)",          "analytics"),
    ("segment.com",               None,   "Segment",                 "analytics"),
    ("segment.io",                None,   "Segment",                 "analytics"),
    ("amplitude.com",             None,   "Amplitude",               "analytics"),
    ("heap.io",                   None,   "Heap",                    "analytics"),
    # Marketing / engagement (common in Indian startups)
    ("clevertap.com",             None,   "CleverTap",               "analytics"),
    ("clevertap-prod.com",        None,   "CleverTap",               "analytics"),
    ("webengage.com",             None,   "WebEngage",               "analytics"),
    ("moengage.com",              None,   "MoEngage",                "analytics"),
    ("netcoresmartech.com",       None,   "Netcore",                 "analytics"),
    ("hs-analytics.net",          None,   "HubSpot Analytics",       "analytics"),
    ("hubspot.com",               "/__ptq.gif", "HubSpot tracking",  "analytics"),
    # Other ad networks / social pixels
    ("snap.licdn.com",            None,   "LinkedIn Insight Tag",    "advertising"),
    ("ads.linkedin.com",          None,   "LinkedIn Ads",            "advertising"),
    ("analytics.tiktok.com",      None,   "TikTok Pixel",            "advertising"),
    ("ads-twitter.com",           None,   "X/Twitter Ads Pixel",     "advertising"),
    ("ct.pinterest.com",          None,   "Pinterest Tag",           "advertising"),
    ("taboola.com",               None,   "Taboola",                 "advertising"),
    ("outbrain.com",              None,   "Outbrain",                "advertising"),
    ("appsflyer.com",             None,   "AppsFlyer",               "advertising"),
    ("branch.io",                 None,   "Branch",                  "advertising"),
    # Adobe Experience Cloud
    ("omtrdc.net",                None,   "Adobe Analytics",         "analytics"),
    ("demdex.net",                None,   "Adobe Audience Manager",  "analytics"),
    ("2o7.net",                   None,   "Adobe Analytics (legacy)","analytics"),
    ("everesttech.net",           None,   "Adobe Advertising Cloud", "advertising"),
    # APM & Real User Monitoring (RUM)
    ("newrelic.com",              None,   "New Relic",               "monitoring"),
    ("nr-data.net",               None,   "New Relic RUM",           "monitoring"),
    ("datadoghq-browser-agent.com", None, "Datadog RUM",             "monitoring"),
    ("datadoghq.com",             None,   "Datadog",                 "monitoring"),
    ("browser.sentry-cdn.com",    None,   "Sentry",                  "monitoring"),
    ("sentry.io",                 None,   "Sentry",                  "monitoring"),
]

# Cookie-name patterns that indicate tracking/analytics cookies
TRACKER_COOKIE_PATTERNS = [
    ("_ga",        "Google Analytics"),
    ("_gid",       "Google Analytics"),
    ("_gat",       "Google Analytics"),
    ("__utm",      "Google Analytics (legacy)"),
    ("_gcl_",      "Google Ads"),
    ("_fbp",       "Meta Pixel"),
    ("_fbc",       "Meta Pixel"),
    ("_clck",      "Microsoft Clarity"),
    ("_clsk",      "Microsoft Clarity"),
    ("_hjsession", "Hotjar"),
    ("_hjsessionuser", "Hotjar"),
    ("_hjid",      "Hotjar"),
    ("mp_",        "Mixpanel"),
    ("ajs_",       "Segment"),
    ("amplitude",  "Amplitude"),
    ("wzrk_",      "CleverTap"),
    ("_li_",       "LinkedIn"),
    ("_ttp",       "TikTok"),
    ("s_cc",       "Adobe Analytics"),
    ("s_sq",       "Adobe Analytics"),
    ("s_vi",       "Adobe Analytics"),
    ("s_fid",      "Adobe Analytics"),
    ("demdex",     "Adobe Audience Manager"),
    ("aam_",       "Adobe Audience Manager"),
    ("_dd_s",      "Datadog RUM"),
    ("nreum",      "New Relic"),
]

# Cookie names that look like session/auth cookies — only these are
# expected to carry HttpOnly (JS-set cookies cannot be HttpOnly, so
# flagging every cookie would create false positives).
SESSION_COOKIE_HINTS = ("sess", "sid", "token", "auth", "jwt", "login")

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS",
     "Browser is not told to always use HTTPS for this site."),
    ("content-security-policy",   "CSP",
     "No Content-Security-Policy to restrict which scripts can run."),
    ("x-content-type-options",    "X-Content-Type-Options",
     "MIME-sniffing protection header is absent."),
    ("referrer-policy",           "Referrer-Policy",
     "No policy limiting what URL data is sent to other sites."),
]

MULTI_PART_TLDS = (
    "co.in", "gov.in", "ac.in", "org.in", "net.in", "nic.in", "edu.in",
    "res.in", "co.uk", "com.au", "co.nz", "com.br",
)


# ---------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------

def base_domain(host: str) -> str:
    """Approximate registrable domain (handles common Indian TLDs)."""
    host = (host or "").lower().split(":")[0]
    if host in ("localhost", "127.0.0.1"):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_third_party(request_url: str, page_url: str) -> bool:
    req_host  = urlparse(request_url).hostname or ""
    page_host = urlparse(page_url).hostname or ""
    return base_domain(req_host) != base_domain(page_host)


def match_tracker(request_url: str):
    """Return (name, category) if the URL matches a tracker rule."""
    parsed = urlparse(request_url)
    host   = (parsed.hostname or "").lower()
    path   = parsed.path or "/"
    for suffix, path_prefix, name, category in TRACKER_RULES:
        if host == suffix or host.endswith("." + suffix):
            if path_prefix is None or path.startswith(path_prefix):
                return name, category
    return None


def normalise_url(target: str) -> str:
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


# ---------------------------------------------------------------
# CORE AUDIT
# ---------------------------------------------------------------

def audit_page(target: str, settle_ms: int = 4000, timeout_ms: int = 30000) -> dict:
    """
    Load `target` once, WITHOUT interacting, and collect evidence.
    Returns a structured result dict (see bottom of function).
    """
    url = normalise_url(target)

    result = {
        "url":              url,
        "audit_type":       "passive_pre_consent",
        "interaction":      "none (no clicks, no form input)",
        "scanned_at":       time.strftime("%Y-%m-%d %H:%M:%S"),
        "status":           "ok",          # ok | inconclusive | error
        "error":            None,
        "main_status":      None,          # HTTP status of main document
        "page_title":       "",
        "total_requests":   0,
        "tracker_requests": [],   # third-party requests matching tracker list
        "tracker_cookies":  [],   # cookies matching tracker patterns
        "cookie_issues":    [],   # missing Secure / SameSite / HttpOnly (session-like)
        "missing_headers":  [],
        "form_issues":      [],
        "all_third_party_hosts": [],
        "limitations": [
            "A request to a tracker domain proves the request fired, not that "
            "personal data was sent.",
            "Consent tools may block scripts by region (e.g. only for EU "
            "visitors); this scan reflects an Indian-visitor-style first load.",
            "Findings are readiness indicators, not legal conclusions. DPDP "
            "notice/consent obligations are enforceable from May 2027.",
        ],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            locale="en-IN",
            timezone_id="Asia/Kolkata",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        seen_requests = []   # (url, resource_type)
        page.on("request", lambda r: seen_requests.append((r.url, r.resource_type)))

        main_response = None
        try:
            main_response = page.goto(url, wait_until="load", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=settle_ms + 4000)
            except PlaywrightTimeout:
                pass                       # noisy sites never go idle — that's fine
            page.wait_for_timeout(settle_ms)   # let late-firing scripts run

            final_url = page.url
            result["main_status"]    = main_response.status if main_response else None
            result["page_title"]     = page.title()
            result["total_requests"] = len(seen_requests)

            # ── 1. Tracker requests (before any interaction) ───────────
            tracker_hits = {}
            third_party_hosts = set()
            for req_url, rtype in seen_requests:
                if not req_url.startswith(("http://", "https://")):
                    continue
                if is_third_party(req_url, final_url):
                    third_party_hosts.add(urlparse(req_url).hostname or "")
                    m = match_tracker(req_url)
                    if m:
                        name, category = m
                        entry = tracker_hits.setdefault(name, {
                            "name": name, "category": category,
                            "request_count": 0, "example_url": req_url[:200],
                        })
                        entry["request_count"] += 1

            result["tracker_requests"] = sorted(
                tracker_hits.values(), key=lambda e: (e["category"], e["name"])
            )
            result["all_third_party_hosts"] = sorted(h for h in third_party_hosts if h)

            # ── 2. Cookies set before any interaction ──────────────────
            cookies = context.cookies()
            page_is_https = final_url.startswith("https://")

            for c in cookies:
                name_l = c["name"].lower()

                for pattern, vendor in TRACKER_COOKIE_PATTERNS:
                    if name_l.startswith(pattern):
                        result["tracker_cookies"].append({
                            "name": c["name"], "vendor": vendor,
                            "domain": c["domain"],
                        })
                        break

                issues = []
                if page_is_https and not c.get("secure"):
                    issues.append("missing Secure flag")
                if c.get("sameSite") in (None, "None") and not c.get("secure"):
                    issues.append("SameSite not restricted")
                if any(h in name_l for h in SESSION_COOKIE_HINTS) and not c.get("httpOnly"):
                    issues.append("session-like cookie without HttpOnly")
                if issues:
                    result["cookie_issues"].append({
                        "name": c["name"], "domain": c["domain"], "issues": issues,
                    })

            # ── 3. Response headers on the main document ───────────────
            if main_response is not None:
                headers = {k.lower(): v for k, v in main_response.headers.items()}
                is_https_doc = final_url.startswith("https://")
                for header, label, why in SECURITY_HEADERS:
                    if header == "strict-transport-security" and not is_https_doc:
                        continue          # HSTS only meaningful on HTTPS
                    if header not in headers:
                        result["missing_headers"].append({"header": label, "why": why})
                # clickjacking: X-Frame-Options OR CSP frame-ancestors
                csp = headers.get("content-security-policy", "")
                if "x-frame-options" not in headers and "frame-ancestors" not in csp:
                    result["missing_headers"].append({
                        "header": "X-Frame-Options / frame-ancestors",
                        "why": "No clickjacking (framing) protection found.",
                    })

            # ── 4. Forms: insecure or third-party submission targets ────
            forms = page.eval_on_selector_all(
                "form",
                """els => els.map(f => ({
                    action: f.getAttribute('action') || '',
                    resolved: f.action || '',
                    has_password: !!f.querySelector('input[type=password]'),
                    has_pii: !!f.querySelector(
                        'input[type=email],input[type=tel],input[name*=phone i],' +
                        'input[name*=email i],input[name*=aadhaar i],input[name*=pan i]'),
                }))""",
            )
            for f in forms:
                resolved = f["resolved"] or final_url
                touches_data = f["has_password"] or f["has_pii"]
                if not touches_data:
                    continue
                if resolved.startswith("http://"):
                    result["form_issues"].append({
                        "type": "insecure_submission",
                        "detail": f"Form collecting "
                                  f"{'credentials' if f['has_password'] else 'personal data'} "
                                  f"submits over unencrypted HTTP ({resolved[:120]})",
                    })
                elif is_third_party(resolved, final_url):
                    result["form_issues"].append({
                        "type": "third_party_submission",
                        "detail": f"Form collecting personal data posts to a different "
                                  f"domain: {urlparse(resolved).hostname}",
                    })
                if f["has_password"] and not final_url.startswith("https://"):
                    result["form_issues"].append({
                        "type": "password_on_http_page",
                        "detail": "Password field served on a page loaded over HTTP.",
                    })

            # ── 5. Was the real page actually served? ──────────────────
            # If a bot-protection page was served instead of the homepage,
            # "0 trackers" would be a FALSE result. Mark it inconclusive.
            blocked_titles = (
                "access denied", "just a moment", "attention required",
                "pardon our interruption", "checking your browser",
                "are you a robot", "request blocked", "challenge validation",
                "security challenge", "human verification", "verify you are human",
                "security check", "bot verification",
            )
            bot_cookie_prefixes = (
                "ak_bmsc", "sec_cpt", "bm_sz", "_abck",
                "__cf_bm", "cf_clearance", "cf_chl",
                "datadome", "incap_ses", "visid_incap",
                "_px3", "_pxhd", "kpsdk", "aws-waf-token",
            )
            title_l = (result["page_title"] or "").lower()
            detected_bot_cookies = [
                c["name"] for c in cookies
                if any(c["name"].lower().startswith(p) for p in bot_cookie_prefixes)
            ]
            has_bot_cookie = bool(detected_bot_cookies)
            reasons = []
            if result["main_status"] in (401, 403, 429, 503):
                reasons.append(f"HTTP status {result['main_status']}")
            if any(t in title_l for t in blocked_titles):
                reasons.append(f"block-page title '{result['page_title']}'")

            explicit_challenge_cookies = [
                name for name in detected_bot_cookies
                if name.lower().startswith(("sec_cpt", "cf_chl"))
            ]
            if explicit_challenge_cookies:
                reasons.append(f"active challenge cookies ({', '.join(explicit_challenge_cookies)})")
            elif has_bot_cookie and any(w in title_l for w in ("challenge", "validation", "captcha", "verify", "robot")):
                reasons.append(f"bot-protection challenge detected ('{result['page_title']}' with {', '.join(detected_bot_cookies[:3])})")
            elif has_bot_cookie and result["total_requests"] <= 15:
                reasons.append("bot-protection cookies present and very few "
                               f"requests loaded ({result['total_requests']})")
            if reasons:
                result["status"] = "inconclusive"
                result["error"] = ("Site appears to have served a bot-protection page "
                                   "instead of the real homepage (" + "; ".join(reasons) +
                                   "). Results are NOT reliable.")

        except PlaywrightTimeout:
            result["status"] = "error"
            result["error"]  = "Page load timed out"
        except Exception as e:
            result["status"] = "error"
            result["error"]  = str(e)
        finally:
            browser.close()

    result["summary"] = summarise(result)
    return result


def summarise(result: dict) -> dict:
    tr_cnt = len(result["tracker_requests"])
    tc_cnt = len(result["tracker_cookies"])
    cf_cnt = len(result["cookie_issues"])
    mh_cnt = len(result["missing_headers"])
    fi_cnt = len(result["form_issues"])
    return {
        "trackers_before_interaction": tr_cnt,
        "tracker_cookies":             tc_cnt,
        "cookie_flag_issues":          cf_cnt,
        "missing_security_headers":    mh_cnt,
        "form_issues":                 fi_cnt,
        "trackers_count":              tr_cnt,
        "tracker_cookies_count":       tc_cnt,
        "cookie_issues_count":         cf_cnt,
        "missing_headers_count":       mh_cnt,
        "form_issues_count":           fi_cnt,
    }


# ---------------------------------------------------------------
# CLI OUTPUT
# ---------------------------------------------------------------

def print_report(r: dict):
    line = "=" * 64
    print(f"\n{line}\n  PASSIVE PRE-CONSENT AUDIT\n  Target : {r['url']}\n"
          f"  Mode   : {r['interaction']}\n{line}")

    if r["status"] == "error":
        print(f"\n  ✗ Scan failed: {r['error']}\n")
        return

    print(f"  Page   : HTTP {r['main_status']} | title: {r['page_title'][:50]!r} "
          f"| {r['total_requests']} requests seen")

    if r["status"] == "inconclusive":
        print(f"\n  [!] INCONCLUSIVE: {r['error']}")
        print("      Do NOT use these results in outreach.")
        print("      Verify manually in a normal browser (DevTools > Network).\n")
        return

    s = r["summary"]
    print(f"\n  Trackers firing before any interaction : {s['trackers_before_interaction']}")
    print(f"  Tracker cookies set before interaction : {s['tracker_cookies']}")
    print(f"  Cookie flag issues                     : {s['cookie_flag_issues']}")
    print(f"  Missing security headers               : {s['missing_security_headers']}")
    print(f"  Form issues                            : {s['form_issues']}")

    if r["tracker_requests"]:
        print("\n  TRACKER REQUESTS (fired before any click):")
        for t in r["tracker_requests"]:
            print(f"    • {t['name']:<26} [{t['category']}]  x{t['request_count']}")
    if r["tracker_cookies"]:
        print("\n  TRACKER COOKIES (present before any click):")
        for c in r["tracker_cookies"]:
            print(f"    • {c['name']:<20} {c['vendor']}")
    if r["cookie_issues"]:
        print("\n  COOKIE FLAG ISSUES:")
        for c in r["cookie_issues"]:
            print(f"    • {c['name']:<20} {', '.join(c['issues'])}")
    if r["missing_headers"]:
        print("\n  MISSING SECURITY HEADERS (indicators):")
        for h in r["missing_headers"]:
            print(f"    • {h['header']:<32} {h['why']}")
    if r["form_issues"]:
        print("\n  FORM ISSUES:")
        for f in r["form_issues"]:
            print(f"    • {f['detail']}")

    print("\n  LIMITATIONS:")
    for lim in r["limitations"]:
        print(f"    - {lim}")
    print(f"\n{line}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Passive pre-consent tracker & security-indicator audit")
    parser.add_argument("target", help="Domain or URL (e.g. example.com)")
    parser.add_argument("--json", action="store_true", help="Print raw JSON")
    parser.add_argument("--skip-robots", action="store_true",
                        help="Skip robots.txt check (use for your own test pages)")
    args = parser.parse_args()

    url = normalise_url(args.target)
    host = urlparse(url).hostname or ""
    if not args.skip_robots and host not in ("localhost", "127.0.0.1"):
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        if not is_scraping_allowed(origin, urlparse(url).path or "/"):
            print("✗ robots.txt disallows automated access to this URL. Skipping.")
            sys.exit(1)

    result = audit_page(args.target)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result)


if __name__ == "__main__":
    main()