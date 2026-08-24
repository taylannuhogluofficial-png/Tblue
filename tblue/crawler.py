"""
Site crawler — discovers all pages on the target domain.
Stays strictly within the target domain.
Parses sitemap.xml and robots.txt for faster discovery.

Enhanced discovery (in addition to <a href> links):
  - <form action="..."> endpoints
  - JavaScript fetch() / XHR API call patterns
  - OpenAPI / Swagger spec paths at standard locations
"""

import re
from typing import Set, List
from collections import deque
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests import Session
from tblue.http import HTTPClient
from tblue.logger import get_logger, log_head
from tblue.constants import (
    DEFAULT_TIMEOUT, DEFAULT_DEPTH,
    DEFAULT_RETRIES, DEFAULT_BACKOFF, DEFAULT_RATE_LIMIT,
)

logger = get_logger(__name__)

# ── JS API endpoint extraction ─────────────────────────────────────────────────
# Matches: fetch('/api/users'), axios.get('/v1/items'), $.ajax({url: '/api/...'})
_JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|\.open)\s*\(\s*['"`](/[^'"`\s]{1,200})['"`]""",
    re.I,
)

# ── OpenAPI / Swagger standard paths ──────────────────────────────────────────
_OPENAPI_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/spec/swagger.json",
]

# Validators: response must contain these strings to count as a real spec
_OPENAPI_MARKERS = ('"openapi"', '"swagger"', 'openapi:', 'swagger:')


def crawl(
    base_url:   str,
    session:    Session,
    max_depth:  int   = DEFAULT_DEPTH,
    timeout:    int   = DEFAULT_TIMEOUT,
    retries:    int   = DEFAULT_RETRIES,
    backoff:    float = DEFAULT_BACKOFF,
    rate_limit: float = DEFAULT_RATE_LIMIT,
) -> Set[str]:
    """
    Crawl the target domain up to max_depth levels deep.
    Also discovers pages via sitemap.xml, robots.txt, form actions,
    JS API fetch() patterns, and OpenAPI specification files.
    Returns a set of unique URLs found on the target domain.
    """
    client  = HTTPClient(session, timeout, retries, backoff, rate_limit)
    visited: Set[str] = set()
    queue   = deque([(base_url, 0)])
    domain  = urlparse(base_url).netloc

    log_head(logger, f"Crawling {base_url} (max depth: {max_depth})")

    # seed from sitemap.xml
    sitemap_urls = _parse_sitemap(base_url, client, domain)
    if sitemap_urls:
        logger.info(f"Found {len(sitemap_urls)} URL(s) in sitemap.xml")
        for u in sitemap_urls:
            queue.append((u, 1))

    # seed from robots.txt
    robots_urls = _parse_robots(base_url, client, domain)
    if robots_urls:
        logger.info(f"Found {len(robots_urls)} path(s) in robots.txt")
        for u in robots_urls:
            queue.append((u, 1))

    # seed from OpenAPI / Swagger specs
    openapi_urls = _discover_openapi(base_url, client, domain)
    if openapi_urls:
        logger.info(f"Found {len(openapi_urls)} API endpoint(s) in OpenAPI spec(s)")
        for u in openapi_urls:
            queue.append((u, 1))

    # standard crawl
    while queue:
        url, depth = queue.popleft()

        if url in visited or depth > max_depth:
            continue

        visited.add(url)
        resp = client.get(url)
        if not resp:
            continue

        logger.info(f"Crawled [{depth}/{max_depth}]: {url}")

        if depth < max_depth:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")

                # <a href="..."> links
                for tag in soup.find_all("a", href=True):
                    _enqueue_url(url, tag["href"], domain, visited, queue, depth)

                # <form action="..."> endpoints
                for form in soup.find_all("form", action=True):
                    _enqueue_url(url, form["action"], domain, visited, queue, depth)

                # JS fetch() / XHR API endpoints in inline scripts
                for script in soup.find_all("script"):
                    if not script.get("src") and script.string:
                        for path in _JS_FETCH_RE.findall(script.string):
                            _enqueue_url(url, path, domain, visited, queue, depth)

            except Exception as e:
                logger.warning(f"Could not parse links on {url} — {e}")

    logger.info(f"Crawler done — {len(visited)} pages found.")
    return visited


def _enqueue_url(
    base_url: str,
    href: str,
    domain: str,
    visited: Set[str],
    queue: deque,
    depth: int,
) -> None:
    """Resolve href against base, validate same-origin, enqueue if unseen."""
    try:
        full   = urljoin(base_url, href)
        parsed = urlparse(full)
        if (
            parsed.netloc == domain
            and parsed.scheme in ("http", "https")
        ):
            clean = parsed._replace(fragment="").geturl()
            if clean not in visited:
                queue.append((clean, depth + 1))
    except Exception:
        pass


def _discover_openapi(base_url: str, client: HTTPClient, domain: str) -> List[str]:
    """
    Probe standard OpenAPI/Swagger spec paths and extract API endpoint paths.
    Returns list of same-origin URLs found in spec files.
    """
    urls: List[str] = []
    for path in _OPENAPI_PATHS:
        spec_url = urljoin(base_url, path)
        try:
            resp = client.get(spec_url)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not any(marker in body for marker in _OPENAPI_MARKERS):
                continue  # Not a real OpenAPI spec
            logger.info(f"OpenAPI spec found at {spec_url}")
            # Extract paths from spec (both JSON and YAML share "paths:" / '"paths"')
            path_re = re.compile(r'''["']?(/[a-zA-Z0-9_/{}.-]{1,200})["']?\s*:''')
            for api_path in path_re.findall(body):
                if api_path.startswith("/") and len(api_path) > 1:
                    full = urljoin(base_url, api_path.split("{")[0].rstrip("/") or "/")
                    if urlparse(full).netloc == domain:
                        urls.append(full)
        except Exception:
            continue
    return urls


def _parse_sitemap(base_url: str, client: HTTPClient, domain: str) -> List[str]:
    """
    Fetch and parse sitemap.xml to seed the crawler.
    Returns list of URLs found in the sitemap on the same domain.
    """
    urls = []
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    resp = client.get(sitemap_url)
    if not resp or resp.status_code != 200:
        return urls

    try:
        soup = BeautifulSoup(resp.text, "xml")
        for loc in soup.find_all("loc"):
            url = loc.text.strip()
            if urlparse(url).netloc == domain:
                urls.append(url)
    except Exception as e:
        logger.warning(f"Could not parse sitemap.xml — {e}")

    return urls


def _parse_robots(base_url: str, client: HTTPClient, domain: str) -> List[str]:
    """
    Fetch and parse robots.txt to discover allowed and disallowed paths.
    Returns list of full URLs for paths mentioned in robots.txt.
    """
    urls = []
    robots_url = urljoin(base_url, "/robots.txt")
    resp = client.get(robots_url)
    if not resp or resp.status_code != 200:
        return urls

    try:
        for line in resp.text.splitlines():
            line = line.strip()
            # extract paths from Allow and Disallow directives
            if line.lower().startswith(("allow:", "disallow:", "sitemap:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path.startswith("http"):
                        # full URL in sitemap directive
                        if urlparse(path).netloc == domain:
                            urls.append(path)
                    elif path and path != "/":
                        # relative path
                        full = urljoin(base_url, path)
                        if urlparse(full).netloc == domain:
                            urls.append(full)
    except Exception as e:
        logger.warning(f"Could not parse robots.txt — {e}")

    return urls
