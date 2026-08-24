"""Extra coverage for cloud_metadata — lines 163-164 (JS bundle metadata), 202-203 (SSRF FAIL)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cloud_metadata import CloudMetadataScanner

URL = "https://example.com"


def _make_scanner():
    return CloudMetadataScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html"}
    r.cookies = {}
    r.__bool__ = lambda self: self.status_code < 400
    return r


# ── Metadata IP in JS bundle (lines 163-164) ─────────────────────────────────

def test_metadata_ip_in_js_bundle_warns():
    """169.254.169.254 found in a loaded JS file produces WARN (lines 163-164)."""
    s = _make_scanner()
    html_page = (
        '<html><head>'
        '<script src="/static/config.js"></script>'
        '</head><body><p>App</p></body></html>'
    )
    js_with_metadata = (
        "const META_URL = 'http://169.254.169.254/latest/meta-data/';\n"
        "// Used for cloud configuration bootstrap\n"
        "fetch(META_URL).then(r => r.json()).then(console.log);"
    )

    def se(url, **kw):
        if "config.js" in url:
            return _resp(200, js_with_metadata, {"content-type": "application/javascript"})
        return _resp(200, html_page)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    warn_results = [r for r in results if r["status"] == "WARN" and "js bundle" in r.get("type", "").lower()]
    assert warn_results, f"Expected WARN for metadata IP in JS bundle: {results}"


def test_metadata_ip_in_external_js_warns():
    """Metadata address in external JS file produces WARN."""
    s = _make_scanner()
    html_page = (
        '<html><head>'
        '<script src="https://cdn.example.com/app.js"></script>'
        '</head><body></body></html>'
    )
    js_with_metadata = (
        "// Emergency fallback\n"
        "var FALLBACK = '169.254.169.254';\n"
        "module.exports = { fallback: FALLBACK };"
    )

    def se(url, **kw):
        if "app.js" in url:
            return _resp(200, js_with_metadata, {"content-type": "application/javascript"})
        return _resp(200, html_page)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    warn_results = [r for r in results if r["status"] == "WARN"]
    assert warn_results, f"Expected WARN for metadata address in external JS: {results}"


# ── SSRF to metadata endpoint succeeds (lines 202-203) ───────────────────────

def test_ssrf_to_cloud_metadata_via_proxy_fails():
    """SSRF probe to /proxy?url=... returns IMDS credentials → FAIL (lines 202-203 SSRF path)."""
    s = _make_scanner()
    # Page body with 169.254.169.254 reference (triggers cloud_indicators = True)
    html_with_metadata_ref = (
        "<html><body>"
        "<p>Config server: 169.254.169.254/latest/meta-data/</p>"
        "</body></html>"
    )
    # AWS IMDS credential response
    imds_creds = (
        '{"Code":"Success","LastUpdated":"2024-01-01T00:00:00Z",'
        '"Type":"AWS-HMAC","AccessKeyId":"ASIAIOSFODNN7EXAMPLE",'
        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
        '"Token":"AQoXnyc4lcK4w...","Expiration":"2024-01-01T06:00:00Z"}'
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, html_with_metadata_ref)
        if "proxy" in url and "169.254.169.254" in url:
            # SSRF via /proxy?url=... succeeds and returns IMDS credentials
            return _resp(200, imds_creds, {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert fail_results, f"Expected FAIL results for page with metadata reference: {results}"


def test_js_probe_exception_is_caught():
    """Exception probing a JS file for metadata refs is caught and skipped (lines 163-164)."""
    s = _make_scanner()
    html_with_script = (
        "<html><head><script src='/static/app.js'></script></head><body></body></html>"
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, html_with_script)
        if "app.js" in url:
            raise ConnectionError("timeout fetching JS")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # Exception is caught → scan continues normally
    assert isinstance(results, list)


def test_ssrf_probe_exception_is_caught():
    """Exception during SSRF probe is caught (lines 202-203 except path)."""
    s = _make_scanner()
    # Trigger cloud_indicators with metadata IP in page
    html_with_ref = "<html><body>Endpoint: http://169.254.169.254/latest</body></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html_with_ref)
        if "proxy" in url:
            raise ConnectionError("unreachable")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # Exception in SSRF probe caught → scan completes normally
    assert isinstance(results, list)
