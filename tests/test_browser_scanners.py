"""
Tests for browser-based scanners (browser_dom_xss, browser_spa_scan, browser_storage).
Playwright is mocked — no real browser launched during tests.
"""
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

URL = "https://example.com"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _mock_browser_page(
    content="<html></html>",
    title="Test Page",
    url=URL,
    local_storage=None,
    session_storage=None,
    cookies=None,
    responses=None,
    requests=None,
    evaluate_map=None,
):
    """Build a mock BrowserPage with configurable returns."""
    page = MagicMock()
    page.goto.return_value = True
    page.content.return_value = content
    page.title.return_value = title
    page.url.return_value = url
    page.local_storage.return_value = local_storage or {}
    page.session_storage.return_value = session_storage or {}
    page.cookies.return_value = cookies or []
    page.responses = responses or []
    page.requests = requests or []
    page.http_requests = [r for r in (requests or []) if r.get("url", "").startswith("http://")]
    page.wait_for_timeout.return_value = None
    page.add_script_tag.return_value = None
    page.get_spa_routes.return_value = []

    # evaluate: return from map or None
    if evaluate_map:
        def _eval(expr, *args, **kwargs):
            for key, val in evaluate_map.items():
                if key in expr:
                    return val
            return None
        page.evaluate.side_effect = _eval
    else:
        page.evaluate.return_value = None

    return page


def _mock_session(page):
    """Build a mock BrowserSession that returns the given page."""
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    session.new_page.return_value = page
    return session


# ── browser_dom_xss ────────────────────────────────────────────────────────────

class TestBrowserDOMXSS:
    def _scanner(self):
        from tblue.scanner.browser_dom_xss import BrowserDOMXSSScanner
        return BrowserDOMXSSScanner(MagicMock())

    def test_no_playwright_skips(self):
        """Returns empty results when Playwright not available."""
        s = self._scanner()
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=False):
            results = s.scan(URL)
        assert results == []

    def test_clean_page_passes(self):
        """No sinks hit → PASS."""
        from tblue.scanner.browser_dom_xss import BrowserDOMXSSScanner
        s = self._scanner()
        page = _mock_browser_page(
            evaluate_map={
                "__tbl_sinks": {"sinks": [], "fired": 0},
                "document.title": "Safe Page",
            }
        )
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL + "?q=hello")
        assert any(r["status"] == "PASS" for r in results)

    def test_fired_onerror_fails(self):
        """window.__tbl_fired=1 → FAIL (payload executed)."""
        s = self._scanner()
        page = _mock_browser_page(
            evaluate_map={
                "__tbl_sinks": {"sinks": [], "fired": 1},
                "document.title": "Normal",
            }
        )
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL + "?q=hello")
        fails = [r for r in results if r["status"] == "FAIL" and "EXECUTED" in r["type"]]
        assert fails

    def test_sink_hit_without_execution_warns(self):
        """Probe in sink but onerror not fired → WARN."""
        s = self._scanner()
        page = _mock_browser_page(
            evaluate_map={
                "__tbl_sinks": {"sinks": [{"sink": "innerHTML", "snippet": "TBLxss9z7<img"}], "fired": 0},
                "document.title": "Normal",
            }
        )
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL + "?q=hello")
        warns = [r for r in results if r["status"] == "WARN" and "sink" in r["type"].lower()]
        assert warns

    def test_probe_in_title_warns(self):
        """Probe in document.title → WARN."""
        from tblue.scanner.browser_dom_xss import _DOM_XSS_PROBE
        s = self._scanner()
        page = _mock_browser_page(
            evaluate_map={
                "__tbl_sinks": {"sinks": [], "fired": 0},
                "document.title": f"Search results for {_DOM_XSS_PROBE}",
            }
        )
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL + "?q=hello")
        warns = [r for r in results if r["status"] == "WARN" and "title" in r["type"].lower()]
        assert warns

    def test_http_subresouce_warns(self):
        """HTTP sub-resource loaded by HTTPS page → WARN."""
        s = self._scanner()
        page = _mock_browser_page(
            evaluate_map={
                "__tbl_sinks": {"sinks": [], "fired": 0},
                "document.title": "Normal",
            },
            requests=[{"url": "http://cdn.example.com/img.jpg", "method": "GET",
                        "resource_type": "image", "headers": {}}],
        )
        page.http_requests = [{"url": "http://cdn.example.com/img.jpg"}]
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL + "?q=hello")
        warns = [r for r in results if r["status"] == "WARN" and "HTTP sub-resource" in r["type"]]
        assert warns

    def test_no_params_probes_common_names(self):
        """URL without params probes common param names."""
        s = self._scanner()
        page = _mock_browser_page(
            evaluate_map={
                "__tbl_sinks": {"sinks": [], "fired": 0},
                "document.title": "Normal",
            }
        )
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL)  # no query string
        assert any(r["status"] == "PASS" for r in results)

    def test_navigation_failure_handled(self):
        """Failed page navigation is handled gracefully."""
        s = self._scanner()
        page = _mock_browser_page()
        page.goto.return_value = False
        session = _mock_session(page)
        with patch("tblue.scanner.browser_dom_xss.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_dom_xss.BrowserSession", return_value=session):
                results = s.scan(URL + "?q=test")
        # Should not raise; may return PASS or empty
        assert results is not None


# ── browser_spa_scan ───────────────────────────────────────────────────────────

class TestBrowserSPAScan:
    def _scanner(self):
        from tblue.scanner.browser_spa_scan import BrowserSPAScanner
        return BrowserSPAScanner(MagicMock())

    def test_no_playwright_skips(self):
        s = self._scanner()
        with patch("tblue.scanner.browser_spa_scan.playwright_available", return_value=False):
            results = s.scan(URL)
        assert results == []

    def test_no_routes_passes(self):
        """No routes found → PASS."""
        s = self._scanner()
        page = _mock_browser_page()
        page.get_spa_routes.return_value = []
        page.evaluate.return_value = []
        session = _mock_session(page)
        with patch("tblue.scanner.browser_spa_scan.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_spa_scan.BrowserSession", return_value=session):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_sensitive_route_accessible_fails(self):
        """Sensitive route accessible without redirect → FAIL."""
        s = self._scanner()

        # Root page returns /admin route
        root_page = _mock_browser_page()
        root_page.get_spa_routes.return_value = ["/admin"]
        root_page.evaluate.return_value = []

        # /admin page — stays on /admin (no auth redirect)
        admin_page = _mock_browser_page(url=URL + "/admin")
        admin_page.responses = [{"url": URL + "/admin", "status": 200, "headers": {}, "resource_type": "document"}]

        pages = [root_page, admin_page]
        call_count = [0]

        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)

        def new_page():
            idx = call_count[0]
            call_count[0] += 1
            return pages[idx] if idx < len(pages) else _mock_browser_page()

        session.new_page.side_effect = new_page

        with patch("tblue.scanner.browser_spa_scan.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_spa_scan.BrowserSession", return_value=session):
                results = s.scan(URL)

        fails = [r for r in results if r["status"] == "FAIL" and "sensitive" in r["type"].lower()]
        assert fails

    def test_sensitive_route_redirected_passes(self):
        """Sensitive route redirects to login → PASS."""
        s = self._scanner()

        root_page = _mock_browser_page()
        root_page.get_spa_routes.return_value = ["/admin"]
        root_page.evaluate.return_value = []

        # /admin redirects to /login
        login_page = _mock_browser_page(url=URL + "/login")
        login_page.responses = []

        pages = [root_page, login_page]
        call_count = [0]

        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)

        def new_page():
            idx = call_count[0]
            call_count[0] += 1
            return pages[idx] if idx < len(pages) else _mock_browser_page()

        session.new_page.side_effect = new_page

        with patch("tblue.scanner.browser_spa_scan.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_spa_scan.BrowserSession", return_value=session):
                results = s.scan(URL)

        passes = [r for r in results if r["status"] == "PASS" and "redirect" in r["type"].lower()]
        assert passes


# ── browser_storage ────────────────────────────────────────────────────────────

class TestBrowserStorage:
    def _scanner(self):
        from tblue.scanner.browser_storage import BrowserStorageScanner
        return BrowserStorageScanner(MagicMock())

    def test_no_playwright_skips(self):
        s = self._scanner()
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=False):
            results = s.scan(URL)
        assert results == []

    def test_empty_storage_passes(self):
        """No sensitive data in storage → PASS."""
        s = self._scanner()
        page = _mock_browser_page(local_storage={}, session_storage={}, cookies=[])
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_jwt_in_localstorage_fails(self):
        """JWT in localStorage → FAIL."""
        s = self._scanner()
        # Valid JWT structure: three base64url parts
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        page = _mock_browser_page(local_storage={"auth_token": fake_jwt})
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "JWT" in r["type"]]
        assert fails

    def test_sensitive_key_in_localstorage_warns(self):
        """Key named 'access_token' with non-JWT value → WARN."""
        s = self._scanner()
        page = _mock_browser_page(local_storage={"access_token": "some-opaque-value-here"})
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "localStorage" in r["type"]]
        assert warns

    def test_jwt_in_session_storage_warns(self):
        """JWT in sessionStorage → WARN (less severe than localStorage)."""
        s = self._scanner()
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        page = _mock_browser_page(session_storage={"session_token": fake_jwt})
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "sessionStorage" in r["type"]]
        assert warns

    def test_cookie_missing_httponly_warns(self):
        """Auth cookie without HttpOnly → WARN."""
        s = self._scanner()
        cookie = {"name": "auth_token", "value": "abc123", "httpOnly": False,
                   "secure": True, "sameSite": "Strict", "domain": "example.com"}
        page = _mock_browser_page(cookies=[cookie])
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "HttpOnly" in r["type"]]
        assert warns

    def test_cookie_missing_secure_on_https_warns(self):
        """Auth cookie without Secure on HTTPS → WARN."""
        s = self._scanner()
        cookie = {"name": "session_token", "value": "abc123", "httpOnly": True,
                   "secure": False, "sameSite": "Strict", "domain": "example.com"}
        page = _mock_browser_page(cookies=[cookie])
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "Secure" in r["type"]]
        assert warns

    def test_safe_cookie_no_warning(self):
        """Cookie with HttpOnly + Secure → no warning."""
        s = self._scanner()
        cookie = {"name": "session_token", "value": "abc123", "httpOnly": True,
                   "secure": True, "sameSite": "Strict", "domain": "example.com"}
        page = _mock_browser_page(cookies=[cookie])
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        cookie_warns = [r for r in results if "cookie" in r.get("type", "").lower() and r["status"] == "WARN"]
        assert not cookie_warns

    def test_navigation_failure_returns_empty(self):
        """Failed navigation returns empty results without crashing."""
        s = self._scanner()
        page = _mock_browser_page()
        page.goto.return_value = False
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        assert results == []

    def test_pii_in_localstorage_warns(self):
        """Email address in localStorage → WARN."""
        s = self._scanner()
        page = _mock_browser_page(local_storage={"userProfile": "user@example.com"})
        session = _mock_session(page)
        with patch("tblue.scanner.browser_storage.playwright_available", return_value=True):
            with patch("tblue.scanner.browser_storage.BrowserSession", return_value=session):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "PII" in r["type"]]
        assert warns
