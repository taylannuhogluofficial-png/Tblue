"""
Tests for the site crawler — including edge cases.
"""

import pytest
from unittest.mock import MagicMock
from tblue.crawler import crawl


def make_session(pages: dict) -> MagicMock:
    """Build a mock session returning HTML based on requested URL."""
    session = MagicMock()

    def mock_request(method, url, **kwargs):
        resp      = MagicMock()
        resp.text = pages.get(url, "<html><body></body></html>")
        resp.url  = url
        return resp

    session.request.side_effect = mock_request
    return session


# ─── Basic crawling ───────────────────────────────────────────────────────────

def test_crawl_finds_linked_pages():
    pages = {
        "https://example.com": """
            <html><body>
              <a href="/about">About</a>
              <a href="/contact">Contact</a>
            </body></html>
        """,
        "https://example.com/about":   "<html><body><p>About</p></body></html>",
        "https://example.com/contact": "<html><body><p>Contact</p></body></html>",
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "https://example.com"         in found
    assert "https://example.com/about"   in found
    assert "https://example.com/contact" in found


def test_crawl_returns_base_url():
    pages = {"https://example.com": "<html><body></body></html>"}
    found = crawl("https://example.com", make_session(pages), max_depth=1)
    assert "https://example.com" in found


# ─── Domain boundaries ────────────────────────────────────────────────────────

def test_crawl_stays_on_same_domain():
    pages = {
        "https://example.com": """
            <html><body>
              <a href="https://external.com/page">External</a>
              <a href="/internal">Internal</a>
            </body></html>
        """,
        "https://example.com/internal": "<html><body></body></html>",
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "https://external.com/page"       not in found
    assert "https://example.com/internal"    in found


def test_crawl_ignores_mailto_links():
    pages = {
        "https://example.com": """
            <html><body>
              <a href="mailto:test@example.com">Email</a>
              <a href="/page">Page</a>
            </body></html>
        """,
        "https://example.com/page": "<html><body></body></html>",
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "mailto:test@example.com" not in found


def test_crawl_ignores_fragment_only_links():
    pages = {
        "https://example.com": """
            <html><body>
              <a href="#section">Jump</a>
              <a href="/page">Page</a>
            </body></html>
        """,
        "https://example.com/page": "<html><body></body></html>",
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    # fragment-only links resolve to base URL which is already visited
    page_calls = [str(c) for c in make_session(pages).request.call_args_list]
    assert "https://example.com#section" not in found


# ─── Depth limits ─────────────────────────────────────────────────────────────

def test_crawl_respects_max_depth():
    pages = {
        "https://example.com":        '<html><body><a href="/l1">L1</a></body></html>',
        "https://example.com/l1":     '<html><body><a href="/l2">L2</a></body></html>',
        "https://example.com/l2":     '<html><body><a href="/l3">L3</a></body></html>',
        "https://example.com/l3":     '<html><body></body></html>',
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "https://example.com/l3" not in found


def test_crawl_depth_zero_returns_only_base():
    pages = {
        "https://example.com": '<html><body><a href="/page">Page</a></body></html>',
        "https://example.com/page": "<html><body></body></html>",
    }
    found = crawl("https://example.com", make_session(pages), max_depth=0)
    assert "https://example.com" in found
    assert "https://example.com/page" not in found


# ─── Deduplication ───────────────────────────────────────────────────────────

def test_crawl_does_not_visit_same_url_twice():
    pages = {
        "https://example.com": """
            <html><body>
              <a href="/page">Page</a>
              <a href="/page">Page duplicate</a>
            </body></html>
        """,
        "https://example.com/page": "<html><body></body></html>",
    }
    session = make_session(pages)
    crawl("https://example.com", session, max_depth=2)
    page_urls = [
        call[0][1] for call in session.request.call_args_list
        if "/page" in call[0][1]
    ]
    assert len(page_urls) == 1


# ─── Error resilience ─────────────────────────────────────────────────────────

def test_crawl_handles_unreachable_page_gracefully():
    session = MagicMock()
    session.request.side_effect = Exception("Connection refused")
    found = crawl("https://example.com", session, max_depth=1, retries=1)
    assert isinstance(found, set)


def test_crawl_continues_after_single_page_error():
    call_count = 0

    def mock_request(method, url, **kwargs):
        nonlocal call_count
        call_count += 1
        if url == "https://example.com/broken":
            raise Exception("Broken")
        resp = MagicMock()
        resp.text = f'<html><body><a href="/broken">Broken</a><a href="/good">Good</a></body></html>'
        resp.url  = url
        return resp

    session = MagicMock()
    session.request.side_effect = mock_request
    found = crawl("https://example.com", session, max_depth=2, retries=1)
    assert "https://example.com" in found


def test_crawl_returns_set():
    pages = {"https://example.com": "<html><body></body></html>"}
    found = crawl("https://example.com", make_session(pages), max_depth=1)
    assert isinstance(found, set)


# ─── Phase 52: Form action discovery ─────────────────────────────────────────

def test_crawl_discovers_form_actions():
    pages = {
        "https://example.com": """
            <html><body>
              <form action="/login" method="post">
                <input type="submit" value="Login">
              </form>
            </body></html>
        """,
        "https://example.com/login": "<html><body><p>Login form</p></body></html>",
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "https://example.com/login" in found


def test_crawl_discovers_js_fetch_endpoints():
    pages = {
        "https://example.com": """
            <html><body>
              <script>
                fetch('/api/users').then(r => r.json());
              </script>
            </body></html>
        """,
        "https://example.com/api/users": '{"users": []}',
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "https://example.com/api/users" in found


def test_crawl_discovers_openapi_spec_paths():
    openapi_body = '{"openapi": "3.0.0", "paths": {"/users": {}, "/items": {}}}'

    def mock_request_openapi(method, url, **kwargs):
        resp = MagicMock()
        resp.url = url
        if url == "https://example.com/openapi.json":
            resp.text = openapi_body
            resp.status_code = 200
        elif url in ("https://example.com/users", "https://example.com/items"):
            resp.text = "<html></html>"
            resp.status_code = 200
        else:
            resp.text = "<html><body></body></html>"
            resp.status_code = 200
        return resp

    session = MagicMock()
    session.request.side_effect = mock_request_openapi
    found = crawl("https://example.com", session, max_depth=2)
    # OpenAPI spec should seed /users and /items
    assert "https://example.com/users" in found or "https://example.com/items" in found


def test_crawl_ignores_cross_origin_form_actions():
    pages = {
        "https://example.com": """
            <html><body>
              <form action="https://external.com/submit" method="post">
                <input type="submit">
              </form>
            </body></html>
        """,
    }
    found = crawl("https://example.com", make_session(pages), max_depth=2)
    assert "https://external.com/submit" not in found


def test_crawl_handles_openapi_not_found():
    """OpenAPI probe returning 404 → no crash, no extra URLs seeded."""
    def mock_request(method, url, **kwargs):
        resp = MagicMock()
        if "openapi" in url or "swagger" in url or "api-docs" in url:
            resp.text = "Not Found"
            resp.status_code = 404
        else:
            resp.text = "<html><body></body></html>"
            resp.status_code = 200
        resp.url = url
        return resp

    session = MagicMock()
    session.request.side_effect = mock_request
    found = crawl("https://example.com", session, max_depth=1)
    assert "https://example.com" in found
