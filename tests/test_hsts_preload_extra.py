"""Extra edge-case tests for HSTSPreloadScanner."""
from unittest.mock import MagicMock, patch

from tblue.scanner.hsts_preload import HSTSPreloadScanner, _PRELOAD_MIN_MAX_AGE

URL = "https://example.com/page"


def _scanner():
    return HSTSPreloadScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


def _good_hsts():
    return f"max-age={_PRELOAD_MIN_MAX_AGE}; includeSubDomains; preload"


# ── max-age parsing ───────────────────────────────────────────────────────────

def test_parse_max_age_normal():
    s = _scanner()
    assert s._parse_max_age("max-age=31536000; includeSubDomains") == 31536000


def test_parse_max_age_with_spaces():
    s = _scanner()
    assert s._parse_max_age("max-age = 7776000") == 7776000


def test_parse_max_age_missing_returns_none():
    s = _scanner()
    assert s._parse_max_age("includeSubDomains; preload") is None


def test_parse_max_age_zero():
    s = _scanner()
    assert s._parse_max_age("max-age=0") == 0


# ── HTTP-origin URL (no https:// prefix available) ───────────────────────────

def test_http_only_url_still_checks():
    """Scanning an http:// URL still checks HTTPS version."""
    s = _scanner()
    http_url = "http://example.com"

    def get_side(url, **kw):
        if url.startswith("https://"):
            return _resp("", 200, headers={"Strict-Transport-Security": _good_hsts()})
        return _resp("", 301, headers={"Location": "https://example.com"})

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(http_url)
    assert results
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── Exact min max-age boundary ────────────────────────────────────────────────

def test_exactly_min_max_age_passes():
    """max-age exactly equal to minimum should pass."""
    s = _scanner()
    hsts = f"max-age={_PRELOAD_MIN_MAX_AGE}; includeSubDomains; preload"

    def get_side(url, **kw):
        if url.startswith("http://"):
            return _resp("", 301, headers={"Location": "https://example.com"})
        return _resp("", headers={"Strict-Transport-Security": hsts})

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS" and "preload-eligible" in r["type"]]
    assert passes


def test_one_below_min_max_age_warns():
    """max-age = min-1 should warn about short max-age."""
    s = _scanner()
    short_age = _PRELOAD_MIN_MAX_AGE - 1
    hsts = f"max-age={short_age}; includeSubDomains; preload"
    with patch.object(s.http, "get", return_value=_resp("", headers={"Strict-Transport-Security": hsts})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "short" in r["type"]]
    assert warns


# ── Case insensitivity in directives ─────────────────────────────────────────

def test_includesubdomains_case_insensitive():
    """IncludeSubDomains with mixed case is recognized."""
    s = _scanner()
    hsts = f"max-age={_PRELOAD_MIN_MAX_AGE}; IncludeSubDomains; preload"
    with patch.object(s.http, "get", return_value=_resp("", headers={"Strict-Transport-Security": hsts})):
        results = s.scan(URL)
    sub_warns = [r for r in results if "includeSubDomains" in r.get("type", "")]
    assert not sub_warns


def test_preload_case_insensitive():
    """PRELOAD with uppercase is recognized."""
    s = _scanner()
    hsts = f"max-age={_PRELOAD_MIN_MAX_AGE}; includeSubDomains; PRELOAD"
    with patch.object(s.http, "get", return_value=_resp("", headers={"Strict-Transport-Security": hsts})):
        results = s.scan(URL)
    preload_warns = [r for r in results if "preload" in r.get("type", "").lower() and "missing" in r.get("type", "").lower()]
    assert not preload_warns


# ── 307 redirect ─────────────────────────────────────────────────────────────

def test_307_redirect_to_https_passes():
    """307 Temporary Redirect to HTTPS is accepted."""
    s = _scanner()

    def get_side(url, **kw):
        if url.startswith("http://"):
            return _resp("", 307, headers={"Location": "https://example.com"})
        return _resp("", headers={"Strict-Transport-Security": _good_hsts()})

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    redirect_passes = [r for r in results if r["status"] == "PASS" and "redirect" in r["type"].lower()]
    assert redirect_passes
