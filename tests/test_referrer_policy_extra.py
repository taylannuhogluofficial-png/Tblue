"""Extra edge-case tests for ReferrerPolicyScanner."""
from unittest.mock import MagicMock, patch

from tblue.scanner.referrer_policy import (
    ReferrerPolicyScanner,
    _POLICY_SAFE,
    _POLICY_ACCEPTABLE,
    _POLICY_UNSAFE,
)

URL = "https://example.com"


def _scanner():
    return ReferrerPolicyScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── Multiple policy values (comma-separated) ──────────────────────────────────

def test_comma_separated_fallback_to_last_known():
    """Browser uses last recognized value in comma-separated list."""
    s = _scanner()
    # "unknown, no-referrer" — last recognized is "no-referrer" → PASS
    with patch.object(s.http, "get", return_value=_resp(
        "<html></html>", headers={"Referrer-Policy": "unknown-value, no-referrer"}
    )):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS" and "safe" in r["type"].lower()]
    assert passes


def test_comma_separated_last_is_unsafe_url_fails():
    """Last value is unsafe-url → FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        "<html></html>", headers={"Referrer-Policy": "no-referrer, unsafe-url"}
    )):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


# ── Meta tag alternative attribute order ──────────────────────────────────────

def test_meta_content_before_name_extracted():
    """<meta content='...' name='referrer'> (reversed attr order) still parsed."""
    s = _scanner()
    html = "<html><head><meta content='no-referrer' name='referrer'></head></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── Case insensitivity ────────────────────────────────────────────────────────

def test_header_value_case_insensitive():
    """Policy values are matched case-insensitively."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        "<html></html>", headers={"Referrer-Policy": "STRICT-ORIGIN"}
    )):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── All safe policies produce PASS ───────────────────────────────────────────

def test_all_safe_policies_produce_pass():
    for policy in _POLICY_SAFE:
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": policy}
        )):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails, f"Safe policy '{policy}' should not FAIL"
        passes = [r for r in results if r["status"] == "PASS"]
        assert passes, f"Safe policy '{policy}' should produce PASS"


# ── Inconsistency: safe header + unsafe meta ──────────────────────────────────

def test_safe_header_unsafe_meta_warns_inconsistency():
    s = _scanner()
    html = "<html><head><meta name='referrer' content='no-referrer-when-downgrade'></head></html>"
    with patch.object(s.http, "get", return_value=_resp(
        html, headers={"Referrer-Policy": "strict-origin"}
    )):
        results = s.scan(URL)
    inconsistent = [r for r in results if "inconsistent" in r.get("type", "")]
    assert inconsistent


# ── Extract meta from malformed HTML ─────────────────────────────────────────

def test_malformed_html_meta_extraction_does_not_crash():
    s = _scanner()
    html = "<html><head><meta name='referrer' content='strict-origin"  # unclosed
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert results  # Should not raise


# ── BeautifulSoup exception path and regex fallback ──────────────────────────

def test_meta_extraction_regex_fallback():
    """When BeautifulSoup raises, regex fallback extracts meta referrer."""
    s = _scanner()
    html = "<html><head><meta name='referrer' content='strict-origin'></head></html>"

    with patch("tblue.scanner.referrer_policy.BeautifulSoup", side_effect=Exception("parse error")):
        policy = s._extract_meta_policy(html)
    assert policy == "strict-origin"


def test_meta_extraction_regex_fallback_reversed_attrs():
    """Regex fallback also handles reversed attribute order."""
    s = _scanner()
    html = "<html><head><meta content='no-referrer' name='referrer'></head></html>"

    with patch("tblue.scanner.referrer_policy.BeautifulSoup", side_effect=Exception("err")):
        policy = s._extract_meta_policy(html)
    assert policy == "no-referrer"


def test_meta_extraction_no_match_returns_none():
    """No meta referrer tag → returns None."""
    s = _scanner()
    html = "<html><head></head></html>"
    with patch("tblue.scanner.referrer_policy.BeautifulSoup", side_effect=Exception("err")):
        policy = s._extract_meta_policy(html)
    assert policy is None


# ── Empty body ────────────────────────────────────────────────────────────────

def test_empty_body_with_header():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        "", headers={"Referrer-Policy": "same-origin"}
    )):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_empty_body_no_header_warns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
