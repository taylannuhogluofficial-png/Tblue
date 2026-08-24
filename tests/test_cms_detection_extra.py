"""Extra branch coverage for tblue.scanner.cms_detection."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.cms_detection import CMSDetectionScanner


def _scanner():
    session = MagicMock()
    return CMSDetectionScanner(session)


# ─── Exception in scan() ─────────────────────────────────────────────────────

def test_scan_exception_returns_empty():
    s = _scanner()
    s.http.get = MagicMock(side_effect=RuntimeError("connection refused"))
    results = s.scan("https://example.com")
    assert results == []


# ─── _check_osv: no eco or pkg ───────────────────────────────────────────────

def test_check_osv_no_ecosystem_returns_empty():
    s = _scanner()
    # sig without ecosystem/osv_package
    result = s._check_osv({"name": "WordPress"}, "5.9.3")
    assert result == []


def test_check_osv_no_package_returns_empty():
    s = _scanner()
    result = s._check_osv({"ecosystem": "npm"}, "1.0.0")
    assert result == []


def test_check_osv_exception_returns_empty():
    s = _scanner()
    s.http.session = MagicMock()
    s.http.session.post = MagicMock(side_effect=Exception("network error"))
    result = s._check_osv(
        {"ecosystem": "npm", "osv_package": "express"},
        "4.17.1"
    )
    assert result == []


def test_check_osv_returns_vulns():
    s = _scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulns": [{"id": "CVE-2023-1234"}]}
    s.http.session = MagicMock()
    s.http.session.post = MagicMock(return_value=mock_resp)
    result = s._check_osv(
        {"ecosystem": "npm", "osv_package": "express"},
        "4.17.1"
    )
    assert result == [{"id": "CVE-2023-1234"}]


# ─── _extract_version: no regex match ────────────────────────────────────────

def test_extract_version_no_match():
    s = _scanner()
    import re
    sig = {"version_regex": re.compile(r"v(\d+\.\d+\.\d+)")}
    result = s._extract_version(sig, "<html>no version here</html>", "https://x.com")
    assert result is None


def test_extract_version_match_with_group():
    s = _scanner()
    import re
    sig = {"version_regex": re.compile(r"Version v(\d+\.\d+\.\d+)")}
    result = s._extract_version(sig, "Version v5.9.3", "https://x.com")
    assert result == "5.9.3"


def test_extract_version_no_sig_regex():
    s = _scanner()
    result = s._extract_version({}, "<html>anything</html>", "https://x.com")
    assert result is None


# ─── _result with extra dict ─────────────────────────────────────────────────

def test_result_extra_merged():
    s = _scanner()
    r = s._result("https://x.com", "CMS — WordPress", "WARN",
                  detail="found", extra={"osv_vulns": ["CVE-2023-1"]})
    assert r["osv_vulns"] == ["CVE-2023-1"]
    assert r["status"] == "WARN"


def test_result_no_extra():
    s = _scanner()
    r = s._result("https://x.com", "CMS — Joomla", "PASS")
    assert "osv_vulns" not in r
