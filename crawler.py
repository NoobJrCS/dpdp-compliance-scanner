# crawler.py
import time
import urllib.parse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from bs4 import BeautifulSoup
from robots_check import is_scraping_allowed, get_crawl_delay

# Keywords that suggest a page is relevant to DPDP compliance
COMPLIANCE_KEYWORDS = [
    "privacy", "policy", "terms", "data", "legal",
    "grievance", "cookie", "consent", "personal data", "protection"
]


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


def fetch_page(url: str, timeout_ms: int = 15000, retries: int = 2) -> str | None:
    """
    Uses Playwright (headless Chromium) to fetch a fully JS-rendered page.
    Returns the full HTML string, or None if all attempts fail.

    EDGE CASE 1: Logs redirects so you can see when http → https or
                 www → non-www redirects happen.

    EDGE CASE 3: Retry logic with exponential backoff.
                 Waits 2s after first failure, 4s after second failure.
                 This handles 403 Forbidden and 429 Too Many Requests.

    timeout_ms : How long to wait for the page to load (default: 15 seconds)
    retries    : Number of additional attempts after first failure (default: 2)
    """
    for attempt in range(retries + 1):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # Create a browser context with a real-looking user agent
            # This reduces the chance of being blocked as a bot
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

                # EDGE CASE 1: Capture final URL after all redirects
                final_url = page.url
                if final_url != url:
                    print(f"  [REDIRECT] {url}")
                    print(f"           → {final_url}")

                html = page.content()
                return html

            except PlaywrightTimeout:
                # EDGE CASE 3: Exponential backoff — wait longer each retry
                wait = 2 ** attempt  # attempt 0 → 1s, attempt 1 → 2s, attempt 2 → 4s
                if attempt < retries:
                    print(f"  [TIMEOUT] Attempt {attempt + 1}/{retries + 1} failed. "
                          f"Retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    print(f"  [TIMEOUT] All {retries + 1} attempts failed: {url}")
                    return None

            except Exception as e:
                print(f"  [ERROR] Could not fetch {url}: {e}")
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

        # Skip empty, javascript:void, and anchor links
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue

        # Check if the link text contains any of our compliance keywords
        for keyword in COMPLIANCE_KEYWORDS:
            if keyword in link_text:
                # Build the full URL if it's a relative path (e.g., "/privacy")
                if href.startswith("http"):
                    full_url = href
                else:
                    full_url = base_url.rstrip("/") + "/" + href.lstrip("/")

                label = link.get_text(strip=True)
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
        print(f"  ✗ robots.txt disallows crawling this domain. Skipping.")
        result["errors"].append("robots.txt disallows crawling this domain.")
        return result
    else:
        print(f"  ✓ robots.txt permits crawling.")

    # Get the crawl delay specified in robots.txt (defaults to 1.0s)
    crawl_delay = get_crawl_delay(base_url)
    print(f"  Crawl delay: {crawl_delay}s between requests\n")

    # -----------------------------------------------------------------------
    # STEP 1: Fetch the homepage
    # -----------------------------------------------------------------------
    print(f"[1/3] Fetching homepage...")
    homepage_html = fetch_page(base_url)

    if not homepage_html:
        result["errors"].append("Could not fetch homepage.")
        return result

    print(f"  ✓ Homepage loaded successfully.\n")

    # -----------------------------------------------------------------------
    # STEP 2: Find compliance links
    # -----------------------------------------------------------------------
    print(f"[2/3] Scanning for compliance-related links...")
    links = extract_compliance_links(homepage_html, base_url)

    if not links:
        result["errors"].append("No compliance links found on homepage.")
        print(f"  ✗ No compliance links found.\n")
        return result

    print(f"  ✓ Found {len(links)} relevant link(s):")
    for label, url in links.items():
        print(f"     → [{label}]: {url}")
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
            result["pages_found"][label] = {
                "url": url,
                "text": clean_text,
                "char_count": len(clean_text)
            }
            print(f"  ✓ Extracted {len(clean_text):,} characters from '{label}'")
        else:
            result["errors"].append(f"Failed to fetch: {label} ({url})")
            print(f"  ✗ Failed to fetch '{label}'")

    print(f"\n{'=' * 60}")
    print(f"  CRAWL COMPLETE")
    print(f"  Pages extracted: {len(result['pages_found'])}")
    print(f"  Errors: {len(result['errors'])}")
    print(f"{'=' * 60}\n")

    return result