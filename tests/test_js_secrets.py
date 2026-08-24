"""Tests for hardcoded secrets in JavaScript scanner."""

from unittest.mock import MagicMock
from tblue.scanner.js_secrets import JSSecretsScanner, _is_likely_fp

# Real-looking test keys that don't trigger false-positive filters
_AWS_KEY      = "AKIAIOSFODNN7ABCDEFG"          # AKIA + 16 uppercase/digit chars, no banned words
_GITHUB_PAT   = "ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrR"  # ghp_ + 36 chars
_STRIPE_KEY   = "sk_live_aAbBcCdDeEfFgGhHiIjJkKlL"           # sk_live_ + 24 chars
_SLACK_WH     = "https://hooks.slack.com/services/T0123456789/B0123456789/aAbBcCdDeEfFgGhHiIjJ"
_GOOGLE_KEY   = "AIzaSyDaAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpq"    # AIza + 35 chars


def _scanner(html=""):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html
        resp.url = url
        return resp

    session.request.side_effect = fake_request
    return JSSecretsScanner(session)


def test_aws_key_detected():
    html = f'<script>var key = "{_AWS_KEY}";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("aws" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_github_pat_detected():
    html = f'<script>const tok = "{_GITHUB_PAT}";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("github" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_stripe_live_key_detected():
    html = f'<script>stripe("{_STRIPE_KEY}");</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("stripe" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_slack_webhook_detected():
    html = f'<script>var wh = "{_SLACK_WH}";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("slack" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_google_api_key_detected():
    html = f'<script>var k = "{_GOOGLE_KEY}";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("google" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_rsa_private_key_detected():
    html = '<script>var key = "-----BEGIN RSA PRIVATE KEY-----";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("rsa private key" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_clean_page_passes():
    scanner = _scanner(html='<html><body><h1>Hello World</h1></body></html>')
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_placeholder_filtered():
    # Keys with "example", "placeholder", "your-key" etc. are false positives
    html = '<script>var key = "your-key-placeholder-123456789012";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert not any(r["status"] == "FAIL" for r in results)


def test_env_var_not_flagged():
    html = '<script>var key = process.env.SECRET_KEY;</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert not any(r["status"] == "FAIL" for r in results)


def test_is_likely_fp_changeme():
    assert _is_likely_fp("changeme") is True


def test_is_likely_fp_placeholder():
    assert _is_likely_fp("sk_live_placeholder12345678901234") is True


def test_is_likely_fp_real_key():
    # A realistic-looking key with no banned words should NOT be flagged as FP
    assert _is_likely_fp(_AWS_KEY) is False


def test_is_likely_fp_eight_xs():
    assert _is_likely_fp("sk_live_xxxxxxxxxxxxxxxxxxxxxxxx") is True


def test_deduplication():
    # Same key appears twice — should only produce one FAIL
    html = f'<script>var a="{_AWS_KEY}"; var b="{_AWS_KEY}";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    aws_fails = [r for r in results if "aws" in r["type"].lower() and r["status"] == "FAIL"]
    assert len(aws_fails) == 1


# ── External script scanning ──────────────────────────────────────────────────

def _scanner_multi(page_html, script_bodies: dict = None):
    """Serve page_html on all page URLs; script_bodies: {path: content}."""
    session = MagicMock()
    script_bodies = script_bodies or {}

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.url = url
        for path, body in script_bodies.items():
            if path in url:
                resp.text = body
                return resp
        resp.text = page_html
        return resp

    session.request.side_effect = fake_request
    return JSSecretsScanner(session)


def test_secret_in_external_script_detected():
    page = '<script src="/app.js"></script>'
    scanner = _scanner_multi(page, {"/app.js": f'var k="{_AWS_KEY}";'})
    results = scanner.scan("https://example.com")
    assert any("aws" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_clean_external_script_passes():
    page = '<script src="/app.js"></script>'
    scanner = _scanner_multi(page, {"/app.js": "var x = 1 + 2;"})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_data_uri_script_skipped():
    page = '<script src="data:text/javascript,var x=1;"></script>'
    scanner = _scanner_multi(page)
    results = scanner.scan("https://example.com")
    # Should not crash and still produce PASS (page itself is clean)
    assert isinstance(results, list)


def test_large_script_truncated_does_not_crash():
    huge_js = "A" * 600_000
    page = '<script src="/big.js"></script>'
    scanner = _scanner_multi(page, {"/big.js": huge_js})
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_external_script_fetch_failure_continues():
    page = '<script src="/bad.js"></script>'
    session = MagicMock()

    call_count = [0]
    def fake_request(method, url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:  # page itself
            resp = MagicMock()
            resp.status_code = 200
            resp.text = page
            resp.url = url
            return resp
        return None  # script fetch fails

    session.request.side_effect = fake_request
    scanner = JSSecretsScanner(session)
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_none_response_returns_empty():
    session = MagicMock()
    session.request.return_value = None
    scanner = JSSecretsScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


def test_secret_result_has_mitre_field():
    html = f'<script>var key = "{_AWS_KEY}";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    for r in fails:
        assert "mitre" in r
