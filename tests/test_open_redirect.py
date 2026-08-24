"""Tests for open redirect parameter detection."""

from unittest.mock import MagicMock
from tblue.scanner.open_redirect import OpenRedirectScanner


def _scanner(html="", base_url="https://example.com"):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html
        resp.headers = {}
        return resp

    session.request.side_effect = fake_request
    return OpenRedirectScanner(session)


_CLEAN_HTML = """
<html>
<body>
  <a href="/about">About</a>
  <a href="/contact">Contact</a>
  <form action="/submit">
    <input name="username">
  </form>
</body>
</html>
"""

_NEXT_HTML = """
<html>
<body>
  <a href="/login?next=/dashboard">Login</a>
</body>
</html>
"""

_REDIRECT_URL_HTML = """
<html>
<body>
  <a href="/logout?redirect_url=https://example.com">Logout</a>
</body>
</html>
"""

_RETURN_TO_HTML = """
<html>
<body>
  <form action="/auth?return_to=/home">
    <input name="email">
  </form>
</body>
</html>
"""

_MULTIPLE_HTML = """
<html>
<body>
  <a href="/sso?next=/app&callback=https://example.com">SSO</a>
</body>
</html>
"""


# ── Clean page → PASS ─────────────────────────────────────────────────────────

def test_clean_page_passes():
    scanner = _scanner(_CLEAN_HTML)
    results = scanner.scan("https://example.com")
    assert any("none detected" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── ?next= parameter → WARN ───────────────────────────────────────────────────

def test_next_param_detected():
    scanner = _scanner(_NEXT_HTML)
    results = scanner.scan("https://example.com")
    assert any("open redirect" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_next_param_type_mentions_param_name():
    scanner = _scanner(_NEXT_HTML)
    results = scanner.scan("https://example.com")
    warn = [r for r in results if r["status"] == "WARN"]
    assert warn
    assert "next" in warn[0]["type"].lower()


# ── ?redirect_url= → WARN ────────────────────────────────────────────────────

def test_redirect_url_param_detected():
    scanner = _scanner(_REDIRECT_URL_HTML)
    results = scanner.scan("https://example.com")
    assert any("open redirect" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── ?return_to= in form action → WARN ────────────────────────────────────────

def test_return_to_in_form_action():
    scanner = _scanner(_RETURN_TO_HTML)
    results = scanner.scan("https://example.com")
    assert any("open redirect" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Multiple params → deduped warnings ───────────────────────────────────────

def test_multiple_params_deduplicated():
    scanner = _scanner(_MULTIPLE_HTML)
    results = scanner.scan("https://example.com")
    warn = [r for r in results if r["status"] == "WARN"]
    # next and callback both found, but deduplicated by param name
    param_names = [r["type"] for r in warn]
    assert len(param_names) == len(set(param_names))


# ── URL itself has redirect param → WARN ─────────────────────────────────────

def test_redirect_param_in_target_url():
    scanner = _scanner("")
    results = scanner.scan("https://example.com/login?next=/dashboard")
    assert any("open redirect" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Network error → empty ─────────────────────────────────────────────────────

def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = OpenRedirectScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Detail mentions whitelist ─────────────────────────────────────────────────

def test_detail_mentions_whitelist():
    scanner = _scanner(_NEXT_HTML)
    results = scanner.scan("https://example.com")
    warn = [r for r in results if r["status"] == "WARN"]
    assert warn
    assert "whitelist" in warn[0]["detail"].lower() or "allowlist" in warn[0]["detail"].lower()
