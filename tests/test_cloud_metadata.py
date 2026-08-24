"""Tests for tblue.scanner.cloud_metadata — Cloud metadata SSRF scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.cloud_metadata import CloudMetadataScanner


def _scanner():
    session = MagicMock()
    return CloudMetadataScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html"}
    r.cookies = {}
    return r


def _404():
    return _resp(status=404)


def test_no_metadata_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_metadata_ip_in_page_fail():
    s = _scanner()
    body = '<html>Internal URL: http://169.254.169.254/latest/meta-data/</html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("169.254.169.254" in r["type"] for r in fails)


def test_gcp_metadata_hostname_in_page():
    s = _scanner()
    body = '<script>const meta = "http://metadata.google.internal/computeMetadata/v1/";</script>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("metadata.google.internal" in r["type"] for r in fails)


def test_k8s_service_account_path_fail():
    s = _scanner()
    body = '<pre>Error: /var/run/secrets/kubernetes.io/serviceaccount/token not found</pre>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("Kubernetes" in r["type"] for r in fails)


def test_k8s_env_variable_in_response():
    s = _scanner()
    body = "<html>KUBERNETES_SERVICE_HOST=10.0.0.1</html>"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_no_response_empty_results():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_js_metadata_reference_warn():
    s = _scanner()
    html_body = '<script src="/static/app.js"></script>'

    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, html_body)
        if url == "https://example.com/static/app.js":
            return _resp(200, "const metaUrl = 'http://169.254.169.254/latest';")
        return _404()

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("169.254.169.254" in r["type"] for r in warns)


def test_alibaba_cloud_metadata():
    s = _scanner()
    body = "Metadata endpoint: http://100.100.100.200/latest/meta-data/"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_js_get_returns_none_no_crash():
    """JS fetch returning None on the JS URL → no crash (covers line 150)."""
    s = _scanner()
    html_body = '<script src="/static/app.js"></script>'

    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, html_body)
        return None  # JS fetch returns None

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert isinstance(results, list)


def test_ssrf_to_metadata_via_proxy_fails():
    """SSRF proxy to 169.254.169.254 succeeds → FAIL (covers lines 188-202)."""
    s = _scanner()
    # Cloud header triggers SSRF probe
    html_body = '<html><a href="http://169.254.169.254/latest/">metadata</a></html>'
    imds_body = "ami-id\ninstance-id\niam/security-credentials"

    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, html_body, {"x-aws-request-id": "abc-123"})
        if "proxy?url=" in url and "169.254.169.254" in url:
            return _resp(200, imds_body)
        return _404()

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    # Metadata IP in page → FAIL; SSRF probe may also FAIL
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_cloud_header_triggers_ssrf_check():
    """AWS request-id header triggers SSRF probe even without IP in body."""
    s = _scanner()
    html_body = "<html><p>Normal page</p></html>"

    def side_effect(url, **kw):
        if url == "https://example.com":
            return _resp(200, html_body, {"x-amz-request-id": "req-abc-123"})
        return _404()

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    # Should run without error; SSRF probes return 404 so no FAIL from probe
    assert isinstance(results, list)
