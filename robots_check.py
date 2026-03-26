import urllib.robotparser


def is_scraping_allowed(base_url: str, path: str = "/") -> bool:
    rp = urllib.robotparser.RobotFileParser()
    robots_url = base_url.rstrip("/") + "/robots.txt"
    rp.set_url(robots_url)

    try:
        rp.read()
    except Exception:
        # If robots.txt can't be fetched, assume allowed
        # (many small Indian sites don't have one)
        return True

    allowed = rp.can_fetch("*", base_url.rstrip("/") + path)
    return allowed


def get_crawl_delay(base_url: str) -> float:
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(base_url.rstrip("/") + "/robots.txt")

    try:
        rp.read()
        delay = rp.crawl_delay("*")
        return float(delay) if delay else 1.0
    except Exception:
        return 1.0


def check_domain_robots(base_url: str, paths: list) -> dict:
    results = {}
    for path in paths:
        results[path] = is_scraping_allowed(base_url, path)
    return results