import urllib.robotparser
import urllib.request
import urllib.error

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def _get_robot_parser(base_url: str) -> urllib.robotparser.RobotFileParser:
    """
    Fetches robots.txt using a browser-like User-Agent.
    Standard urllib.robotparser uses 'Python-urllib', which triggers WAF 403
    blocks on Cloudflare/Akamai sites, causing false disallow-all results.
    """
    rp = urllib.robotparser.RobotFileParser()
    robots_url = base_url.rstrip("/") + "/robots.txt"
    req = urllib.request.Request(
        robots_url,
        headers={"User-Agent": BROWSER_UA, "Accept": "*/*"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                content = response.read().decode("utf-8", errors="replace")
                rp.parse(content.splitlines())
                return rp
            elif response.status in (401, 403, 404, 410):
                rp.allow_all = True
                return rp
    except (urllib.error.HTTPError, urllib.error.URLError, Exception):
        rp.allow_all = True
        return rp

    rp.allow_all = True
    return rp


def is_scraping_allowed(base_url: str, path: str = "/") -> bool:
    rp = _get_robot_parser(base_url)
    return rp.can_fetch("*", base_url.rstrip("/") + path)


def get_crawl_delay(base_url: str) -> float:
    rp = _get_robot_parser(base_url)
    try:
        delay = rp.crawl_delay("*")
        return float(delay) if delay else 1.0
    except Exception:
        return 1.0


def check_domain_robots(base_url: str, paths: list) -> dict:
    rp = _get_robot_parser(base_url)
    results = {}
    for path in paths:
        results[path] = rp.can_fetch("*", base_url.rstrip("/") + path)
    return results