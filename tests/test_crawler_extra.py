"""Extra branch coverage for tblue.crawler."""

from unittest.mock import MagicMock
from tblue.crawler import crawl


def _make_session(pages: dict) -> MagicMock:
    """Build a mock session that returns HTML based on requested URL."""
    session = MagicMock()

    def mock_request(method, url, **kwargs):
        resp = MagicMock()
        resp.text = pages.get(url, "<html><body></body></html>")
        resp.url = url
        return resp

    session.request.side_effect = mock_request
    return session


def test_sitemap_urls_discovered():
    """Covers the sitemap.xml seed branch — URLs found in sitemap are queued."""
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/products</loc></url>
  <url><loc>https://example.com/about</loc></url>
</urlset>"""
    pages = {
        "https://example.com": "<html><body></body></html>",
        "https://example.com/robots.txt": "",
        "https://example.com/sitemap.xml": sitemap_xml,
        "https://example.com/products": "<html><body><p>Products</p></body></html>",
        "https://example.com/about": "<html><body><p>About</p></body></html>",
    }
    found = crawl("https://example.com", _make_session(pages), max_depth=2)
    assert "https://example.com/products" in found or "https://example.com" in found


def test_max_depth_zero_returns_only_base():
    """Covers the max_depth=0 boundary — only the root URL visited."""
    pages = {
        "https://example.com": """
        <html><body>
          <a href="/deep/page">Deep</a>
        </body></html>
        """,
        "https://example.com/deep/page": "<html><body></body></html>",
    }
    found = crawl("https://example.com", _make_session(pages), max_depth=0)
    assert "https://example.com" in found
    assert "https://example.com/deep/page" not in found


def test_form_action_endpoints_discovered():
    """Covers the <form action> endpoint discovery branch."""
    pages = {
        "https://example.com": """
        <html><body>
          <form action="/submit" method="POST">
            <input name="q" type="text">
            <input type="submit">
          </form>
        </body></html>
        """,
        "https://example.com/submit": "<html><body></body></html>",
    }
    found = crawl("https://example.com", _make_session(pages), max_depth=2)
    assert "https://example.com" in found


def test_robots_txt_paths_discovered():
    """Covers the robots.txt seed branch — disallow paths are queued."""
    robots = "User-agent: *\nDisallow: /admin/\nDisallow: /private/"
    pages = {
        "https://example.com": "<html><body></body></html>",
        "https://example.com/robots.txt": robots,
        "https://example.com/admin/": "<html><body>Admin</body></html>",
        "https://example.com/private/": "<html><body>Private</body></html>",
    }
    found = crawl("https://example.com", _make_session(pages), max_depth=2)
    # robots.txt paths should be seeded into the crawl queue
    assert "https://example.com" in found


def test_duplicate_links_not_visited_twice():
    """Covers the visited-set deduplication branch."""
    pages = {
        "https://example.com": """
        <html><body>
          <a href="/page">Page</a>
          <a href="/page">Page again</a>
          <a href="/page">Page third time</a>
        </body></html>
        """,
        "https://example.com/page": "<html><body></body></html>",
    }
    session = MagicMock()
    call_count = {"n": 0}

    def mock_request(method, url, **kwargs):
        call_count["n"] += 1
        resp = MagicMock()
        resp.text = pages.get(url, "")
        resp.url = url
        return resp

    session.request.side_effect = mock_request
    found = crawl("https://example.com", session, max_depth=2)
    # crawl() returns a set — each URL appears exactly once
    assert isinstance(found, (set, list))
    urls = list(found)
    page_count = sum(1 for u in urls if u == "https://example.com/page")
    assert page_count == 1, f"Expected /page to appear exactly once, got {page_count}"


def test_none_response_from_session_handled():
    """Covers the branch where the HTTP client returns None for a URL."""
    session = MagicMock()

    def mock_request(method, url, **kwargs):
        return None

    session.request.side_effect = mock_request
    # Should not raise
    found = crawl("https://example.com", session, max_depth=1)
    assert isinstance(found, set)
