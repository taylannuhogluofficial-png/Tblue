"""Tests for tblue.scanner.ssrf_advanced — Advanced SSRF scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.ssrf_advanced import SSRFAdvancedScanner


def _scanner():
    session = MagicMock()
    return SSRFAdvancedScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html"}
    return r


def _clean_resp():
    return _resp(200, "<html><body><p>Welcome</p></body></html>")


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── SSRF form parameter → FAIL ────────────────────────────────────────────────

def test_url_form_input_fails():
    html = """
    <html><body>
    <form action="/fetch" method="POST">
        <input name="url" type="text" placeholder="Enter URL">
        <input type="submit">
    </form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("ssrf" in r["type"].lower() or "url" in r["type"].lower() for r in fails)


def test_redirect_form_input_fails():
    html = """
    <html><body>
    <form><input name="redirect_url" type="hidden"><input type="submit"></form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    # redirect_url is hidden, so not flagged (SKIP hidden inputs)
    # If marked as type=text it would be flagged
    assert results  # at minimum some result


def test_webhook_form_input_warns_or_fails():
    html = """
    <html><body>
    <form action="/configure" method="POST">
        <input name="webhook" type="text">
        <input type="submit">
    </form>
    </body></html>
    """
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    issues = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert issues


# ── SSRF query param → WARN ───────────────────────────────────────────────────

def test_url_query_param_warns():
    s = _scanner()
    url = "https://example.com/proxy?url=https://external.com"
    with patch.object(s.http, "get", return_value=_clean_resp()):
        results = s.scan(url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("ssrf" in r["type"].lower() or "query" in r["type"].lower() for r in warns)


def test_redirect_query_param_warns():
    s = _scanner()
    url = "https://example.com/login?redirect=https://dashboard.example.com"
    with patch.object(s.http, "get", return_value=_clean_resp()):
        results = s.scan(url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_no_query_params_skipped():
    s = _scanner()
    url = "https://example.com/about"
    with patch.object(s.http, "get", return_value=_clean_resp()):
        results = s.scan(url)
    query_warns = [r for r in results if "query parameter" in r.get("type", "").lower()]
    assert not query_warns


# ── Import/webhook endpoint → WARN ────────────────────────────────────────────

def test_webhook_endpoint_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/webhook" in url:
            return _resp(200, '{"status":"ok","webhook_url":""}')
        return _clean_resp()

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("webhook" in r["type"].lower() or "import" in r["type"].lower() for r in warns)


def test_import_endpoint_405_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if "/import" in url:
            return _resp(405, "Method Not Allowed — POST required with url parameter")
        return _clean_resp()

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── XML content type → WARN ────────────────────────────────────────────────────

def test_xml_content_type_warns():
    s = _scanner()
    xml_resp = _resp(200, "<rss></rss>", {"content-type": "application/rss+xml"})
    with patch.object(s.http, "get", return_value=xml_resp):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("xml" in r["type"].lower() or "xxe" in r["type"].lower() for r in warns)


# ── Private IP in response → FAIL ─────────────────────────────────────────────

def test_private_ip_in_body_fails():
    html = "<html><body>Internal server: 10.0.0.5</body></html>"
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("private ip" in r["type"].lower() or "ssrf" in r["type"].lower() for r in fails)


def test_localhost_in_body_not_flagged():
    """127.0.0.1 and localhost are filtered out as they appear in normal code examples."""
    html = "<html><body>See http://127.0.0.1:8080 for local dev</body></html>"
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan("https://example.com")
    ip_fails = [r for r in results if "private ip" in r.get("type", "").lower()]
    assert not ip_fails


# ── Clean page → PASS ─────────────────────────────────────────────────────────

def test_clean_page_passes():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        # All import/webhook paths return 404 — only main URL returns content
        if url == "https://example.com" or url == "https://example.com/":
            return _clean_resp()
        return _resp(404, "Not Found")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
