# crawler.py
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import time
import urllib.parse
import urllib.request
import urllib.error
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from bs4 import BeautifulSoup
from robots_check import is_scraping_allowed, get_crawl_delay

# Keywords that suggest a page is relevant to DPDP compliance
# Avoid loose words like "policy" or "data" which falsely match insurance products or mobile data
COMPLIANCE_KEYWORDS = [
    "privacy", "terms", "grievance", "cookie", "legal",
    "user agreement", "disclaimer", "data protection"
]

BLOCKED_TITLES = (
    "access denied", "just a moment", "attention required",
    "pardon our interruption", "checking your browser",
    "are you a robot", "request blocked", "challenge validation",
    "security challenge", "human verification", "verify you are human",
    "security check", "bot verification"
)

BOT_COOKIE_PREFIXES = (
    "ak_bmsc", "sec_cpt", "bm_sz", "_abck",
    "__cf_bm", "cf_clearance", "cf_chl",
    "datadome", "incap_ses", "visid_incap",
    "_px3", "_pxhd", "kpsdk", "aws-waf-token"
)


def check_bot_block(page, html: str) -> tuple[bool, str]:
    """
    Checks if a Playwright page was served a bot challenge or block page.
    Returns (True, reason) or (False, '').
    """
    try:
        title = (page.title() or "").strip()
        title_l = title.lower()
    except Exception:
        title = ""
        title_l = ""

    for bt in BLOCKED_TITLES:
        if bt in title_l:
            return True, f"block-page title '{title}'"

    try:
        cookies = page.context.cookies()
    except Exception:
        cookies = []

    detected_bot_cookies = [
        c["name"] for c in cookies
        if any(c["name"].lower().startswith(p) for p in BOT_COOKIE_PREFIXES)
    ]
    explicit_challenge = [
        c for c in detected_bot_cookies
        if c.lower().startswith(("sec_cpt", "cf_chl"))
    ]
    if explicit_challenge:
        return True, f"active challenge token ({', '.join(explicit_challenge)})"

    if detected_bot_cookies and any(w in title_l for w in ("challenge", "validation", "captcha", "verify", "robot")):
        return True, f"bot challenge ('{title}')"

    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "header", "footer"]):
        tag.decompose()
    clean = soup.get_text(strip=True).lower()
    if len(clean) < 150:
        for bt in ("challenge validation", "access denied", "attention required", "security check", "are you a robot"):
            if bt in clean:
                return True, f"bot block text ('{bt}')"

    return False, ""


def normalize_url(domain: str) -> str:
    """
    Accepts a raw domain input and returns a clean,
    full URL with https:// prefix.

    EDGE CASE 1: Handles all input formats:
      - "flipkart.com"
      - "https://flipkart.com"
      - "http://flipkart.com"
      - "www.flipkart.com"
    Always defaults to https.
    """
    domain = domain.strip()

    # Remove any existing protocol
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain

    # Default to https
    return f"https://{domain}"


def fetch_page_http(url: str, timeout: int = 12) -> str | None:
    """
    Direct HTTP fallback using standard Python urllib.
    Used when Playwright Chromium encounters net::ERR_HTTP2_PROTOCOL_ERROR
    or stream resets on WAF/CDN protected sites.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                html = resp.read().decode("utf-8", errors="replace")
                soup = BeautifulSoup(html, "lxml")
                title = soup.title.string.strip() if soup.title and soup.title.string else ""
                title_l = title.lower()
                for bt in BLOCKED_TITLES:
                    if bt in title_l:
                        print(f"  [BLOCKED] Bot challenge detected in HTTP fallback ('{title}'): {url}")
                        return None
                return html
    except Exception as e:
        print(f"  [ERROR] Direct HTTP fetch failed for {url}: {e}")
        return None
    return None


def fetch_page(url: str, timeout_ms: int = 15000, retries: int = 2) -> str | None:
    """
    Uses Playwright (headless Chromium) to fetch a fully JS-rendered page.
    Falls back to direct HTTP (urllib) if Playwright encounters protocol errors
    (e.g. net::ERR_HTTP2_PROTOCOL_ERROR on WAFs).
    """
    for attempt in range(retries + 1):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            )

            page = context.new_page()

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

                # Brief pause to allow lazy-loaded footer content to appear
                time.sleep(2)

                # Capture final URL after all redirects
                final_url = page.url
                if final_url != url:
                    print(f"  [REDIRECT] {url}")
                    print(f"           -> {final_url}")

                html = page.content()
                is_blocked, block_reason = check_bot_block(page, html)
                if is_blocked:
                    print(f"  [BLOCKED] Bot protection challenge detected ({block_reason}): {final_url}")
                    return None

                return html

            except PlaywrightTimeout:
                wait = 2 ** attempt
                if attempt < retries:
                    print(f"  [TIMEOUT] Attempt {attempt + 1}/{retries + 1} failed. "
                          f"Retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    print(f"  [TIMEOUT] Playwright attempts failed: {url}")
                    print(f"  [FALLBACK] Attempting direct HTTP fallback for: {url}")
                    http_html = fetch_page_http(url)
                    if http_html:
                        print(f"  [OK] Successfully retrieved page via HTTP fallback: {url}")
                        return http_html
                    return None

            except Exception as e:
                err_str = str(e)
                print(f"  [ERROR] Playwright could not fetch {url}: {err_str}")
                # If network or HTTP2 protocol error or connection reset, try HTTP fallback
                if "ERR_HTTP2" in err_str or "ERR_CONNECTION" in err_str or "ERR_SSL" in err_str:
                    print(f"  [FALLBACK] Attempting direct HTTP fallback for: {url}")
                    http_html = fetch_page_http(url)
                    if http_html:
                        print(f"  [OK] Successfully retrieved page via HTTP fallback: {url}")
                        return http_html
                return None

            finally:
                browser.close()

    return None


def extract_compliance_links(html: str, base_url: str) -> dict:
    """
    Scans a page's HTML (especially the footer) for links whose
    text matches compliance keywords.

    Returns a dictionary: { "Privacy Policy": "https://...", ... }
    """
    soup = BeautifulSoup(html, "lxml")
    found_links = {}

    # Strategy 1: Look in the <footer> tag first
    footer = soup.find("footer")
    search_area = footer if footer else soup  # Fallback to entire page

    all_links = search_area.find_all("a", href=True)

    for link in all_links:
        link_text = link.get_text(strip=True).lower()
        href = link["href"].strip()

        # Skip empty, javascript, anchors, and non-web protocols
        if not href or href.startswith(("#", "javascript:", "tel:", "mailto:", "sms:")):
            continue

        # Skip long promotional/product cards (real compliance links are concise)
        if len(link_text) > 80:
            continue

        # Check if the link text contains any compliance keywords
        for keyword in COMPLIANCE_KEYWORDS:
            if keyword in link_text:
                full_url = urllib.parse.urljoin(base_url, href)
                if not full_url.startswith(("http://", "https://")):
                    continue

                label = link.get_text(strip=True)
                # Keep labels clean and reasonable in length
                label = " ".join(label.split())[:60]
                found_links[label] = full_url
                break

    # Strategy 2: Also try common known paths as fallback
    if not any("privacy" in label.lower() for label in found_links.keys()):
        common_paths = ["/privacy", "/privacy-policy", "/legal/privacy"]
        for path in common_paths:
            found_links["Privacy Policy (guessed)"] = base_url.rstrip("/") + path
            break

    return found_links


def extract_clean_text(html: str) -> str:
    """
    Strips all HTML tags and returns clean, readable plain text.
    Removes scripts, styles, and nav elements that add noise.

    EDGE CASE 4: Warns if the extracted text is suspiciously short.
                 A real privacy policy is typically 2,000+ characters.
                 Short text usually means infinite scroll or API-loaded content.
    """
    soup = BeautifulSoup(html, "lxml")

    # Remove tags that add noise
    for tag in soup(["script", "style", "nav", "header", "footer", "iframe", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator="\n")

    # Clean up excessive blank lines
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    clean_text = "\n".join(lines)

    # EDGE CASE 4: Short text warning
    if len(clean_text) < 1500:
        print(f"  [WARNING] Extracted text is very short ({len(clean_text)} chars).")
        print(f"            This page may use infinite scroll or load content via API.")
        print(f"            Audit results for this page may be incomplete.")

    return clean_text


def run_crawler(domain: str) -> dict:
    """
    Master function. Takes a domain, finds compliance pages,
    and returns their cleaned text.

    Returns:
    {
        "base_url": "https://flipkart.com",
        "pages_found": {
            "Privacy Policy": {
                "url": "https://flipkart.com/pages/privacypolicy",
                "text": "...raw cleaned text...",
                "char_count": 15000
            },
            ...
        },
        "errors": []
    }
    """
    base_url = normalize_url(domain)
    result = {
        "base_url": base_url,
        "pages_found": {},
        "errors": []
    }

    print(f"\n{'=' * 60}")
    print(f"  DPDP COMPLIANCE SCANNER")
    print(f"  Target: {base_url}")
    print(f"{'=' * 60}\n")

    # -----------------------------------------------------------------------
    # EDGE CASE 6: Check robots.txt and get crawl delay BEFORE anything else
    # -----------------------------------------------------------------------
    print(f"[0/3] Checking robots.txt...")
    homepage_allowed = is_scraping_allowed(base_url, "/")

    if not homepage_allowed:
        print(f"  [FAIL] robots.txt disallows crawling this domain. Skipping.")
        result["errors"].append("robots.txt disallows crawling this domain.")
        result["blocked"] = True
        result["blocked_reason"] = "robots.txt explicitly disallows automated crawlers for this domain (User-agent: *)."
        return result
    else:
        print(f"  [OK] robots.txt permits crawling.")

    # Get the crawl delay specified in robots.txt (defaults to 1.0s)
    crawl_delay = get_crawl_delay(base_url)
    print(f"  Crawl delay: {crawl_delay}s between requests\n")

    # -----------------------------------------------------------------------
    # STEP 1: Fetch the homepage
    # -----------------------------------------------------------------------
    print(f"[1/3] Fetching homepage...")
    homepage_html = fetch_page(base_url)

    if not homepage_html:
        result["errors"].append("Could not fetch homepage (blocked by bot protection or unreachable).")
        result["blocked"] = True
        result["blocked_reason"] = "Site appears to be protected by a bot-detection challenge (e.g. Akamai, Cloudflare, or WAF)."
        print("  [!] Crawl stopped: Homepage could not be retrieved.\n")
        return result

    print(f"  [OK] Homepage loaded successfully.\n")

    # -----------------------------------------------------------------------
    # STEP 2: Find compliance links
    # -----------------------------------------------------------------------
    print(f"[2/3] Scanning for compliance-related links...")
    links = extract_compliance_links(homepage_html, base_url)

    if not links:
        result["errors"].append("No compliance links found on homepage.")
        result["blocked"] = True
        result["blocked_reason"] = "No compliance links (Privacy Policy, Terms) could be found on the homepage."
        print(f"  [NOTE] No compliance links found.\n")
        return result

    print(f"  [OK] Found {len(links)} relevant link(s):")
    for label, url in links.items():
        print(f"     -> [{label}]: {url}")
    print()

    # -----------------------------------------------------------------------
    # STEP 3: Fetch and extract text from each compliance page
    # -----------------------------------------------------------------------
    print(f"[3/3] Fetching and extracting text from compliance pages...")

    # Parse base domain for third-party detection (Edge Case 2)
    parsed_base_netloc = urllib.parse.urlparse(base_url).netloc

    for label, url in links.items():
        print(f"  Fetching: {label}...")

        # EDGE CASE 6: Use crawl delay from robots.txt instead of hardcoded 1s
        time.sleep(crawl_delay)

        page_html = fetch_page(url)

        if page_html:
            # EDGE CASE 2: Detect if content is served from a third-party domain
            # e.g. OneTrust, Termly, or parent company domain
            parsed_final_netloc = urllib.parse.urlparse(url).netloc
            if parsed_base_netloc not in parsed_final_netloc:
                print(f"  [NOTE] Content served from third-party domain: {parsed_final_netloc}")
                print(f"         This is common for OneTrust/Termly-hosted policies.")

            clean_text = extract_clean_text(page_html)
            if len(clean_text) < 150:
                print(f"  [WARNING] Content for '{label}' is too short ({len(clean_text)} chars) — skipping.")
                result["errors"].append(f"Content for {label} was too short or empty ({len(clean_text)} chars).")
                continue

            result["pages_found"][label] = {
                "url": url,
                "text": clean_text,
                "char_count": len(clean_text)
            }
            print(f"  [OK] Extracted {len(clean_text):,} characters from '{label}'")
        else:
            result["errors"].append(f"Failed to fetch: {label} ({url})")
            print(f"  [FAIL] Failed to fetch '{label}'")

    if not result["pages_found"]:
        result["blocked"] = True
        result["blocked_reason"] = "No compliance pages could be accessed (blocked by bot protection or missing content)."

    print(f"\n{'=' * 60}")
    print(f"  CRAWL COMPLETE")
    print(f"  Pages extracted: {len(result['pages_found'])}")
    print(f"  Errors: {len(result['errors'])}")
    print(f"{'=' * 60}\n")

    return result