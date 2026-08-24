"""Tests for Version CVE Correlation scanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.version_cve import VersionCVEScanner


def _make_scanner():
    session = MagicMock()
    return VersionCVEScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


# 1 — Unreachable target → PASS
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


# 2 — No version banners at all → PASS
def test_no_version_banners_pass():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Content-Type": "text/html"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 3 — Vulnerable Apache version → FAIL + version disclosure WARN
def test_apache_vulnerable_fail():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Server": "Apache/2.4.49"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Should have: (1) banner exposure WARN, (2) CVE finding FAIL
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert any("apache" in r["type"].lower() or "cve" in r["type"].lower()
               for r in fail_results)
    # CVE-2021-41773 should be mentioned
    assert any("CVE-2021-41773" in r["detail"] for r in results)


# 4 — Vulnerable PHP version → FAIL
def test_php_vulnerable_fail():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"X-Powered-By": "PHP/7.4.10"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    assert any("php" in r["type"].lower() for r in fail_results)


# 5 — Current PHP version (not vulnerable) → only banner WARN, no CVE FAIL
def test_php_current_version_no_cve():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"X-Powered-By": "PHP/8.3.0"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Banner disclosure should still warn, but no CVE FAIL
    statuses = [r["status"] for r in results]
    assert "FAIL" not in statuses
    assert "WARN" in statuses  # banner exposure


# 6 — nginx vulnerable version → FAIL
def test_nginx_vulnerable_fail():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Server": "nginx/1.22.0"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    assert any("nginx" in r["type"].lower() for r in fail_results)


# 7 — WordPress via meta generator → FAIL for vulnerable version
def test_wordpress_vulnerable_via_meta():
    s = _make_scanner()
    html = '<html><head><meta name="generator" content="WordPress 5.8"></head></html>'

    def fake_get(url, **kw):
        return _resp(html, headers={"Content-Type": "text/html"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    assert any("wordpress" in r["type"].lower() for r in fail_results)


# 8 — Multiple vulnerable versions in different headers
def test_multiple_vulnerable_versions():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp(
            "<html></html>",
            headers={
                "Server": "Apache/2.4.50",
                "X-Powered-By": "PHP/7.4.10",
            }
        )

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 2  # one per vulnerable product


# 9 — OpenSSL version in Server header
def test_openssl_in_server_header():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp(
            "<html></html>",
            headers={"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1p"}
        )

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Should detect both Apache and OpenSSL versions and check CVEs
    types = " ".join(r["type"].lower() for r in results)
    assert "apache" in types or "openssl" in types


# 10 — Version banner present but not in CVE DB → only banner WARN
def test_version_banner_not_in_cve_db():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp(
            "<html></html>",
            headers={"Server": "MyCustomServer/1.0.0"}
        )

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # No CVE finding but no crash either
    assert len(results) >= 1


# 11 — Joomla vulnerable version via meta generator
def test_joomla_vulnerable():
    s = _make_scanner()
    html = '<html><head><meta name="generator" content="Joomla! 4.1.0"></head></html>'

    def fake_get(url, **kw):
        return _resp(html, headers={"Content-Type": "text/html"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    assert any("joomla" in r["type"].lower() for r in fail_results)
    # CVE-2023-23752 should be mentioned
    assert any("CVE-2023-23752" in r["detail"] for r in results)


# 12 — Apache current version → only banner WARN
def test_apache_current_version_no_cve():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Server": "Apache/2.4.60"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) == 0
    assert any("banner" in r["type"].lower() or "version" in r["type"].lower()
               for r in results if r["status"] == "WARN")


# 13 — IIS version in Server header → CVE for old version
def test_iis_vulnerable():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Server": "Microsoft-IIS/8.5"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    assert any("iis" in r["type"].lower() for r in fail_results)


# 14 — Drupal vulnerable version via meta generator
def test_drupal_vulnerable():
    s = _make_scanner()
    html = '<html><head><meta name="generator" content="Drupal 9.4.0 (https://www.drupal.org)"></head></html>'

    def fake_get(url, **kw):
        return _resp(html)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    assert any("drupal" in r["type"].lower() for r in fail_results)


# 16 — _ver() handles non-numeric version component gracefully (line 44-45)
def test_malformed_version_string_no_crash():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp(
            "<html></html>",
            headers={"Server": "Apache/abc.def.xyz"}
        )

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Should not crash — just a banner warning
    assert len(results) >= 1


# 17 — Product with > 8 CVEs triggers truncation string (line 262)
def test_many_cves_truncation():
    from tblue.scanner.version_cve import VersionCVEScanner as VCVE, _CVE_DB
    # Patch the DB to have many CVEs for a single product
    import unittest.mock as mock

    big_db_entry = [
        ("apache", "2.4.99", ["CVE-2021-41773", "CVE-2021-42013", "CVE-2023-25690",
                               "CVE-2023-43622", "CVE-2023-45802", "CVE-2022-22720",
                               "CVE-2022-22719", "CVE-2022-22721", "CVE-2022-23943"],
         "CRITICAL", "Multiple Apache vulnerabilities."),
    ]
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Server": "Apache/2.4.10"})

    with mock.patch("tblue.scanner.version_cve._CVE_DB", big_db_entry):
        with patch.object(s.http, "get", side_effect=fake_get):
            results = s.scan("https://example.com")

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
    # Should include truncation indicator
    assert any("more" in r["detail"] for r in fail_results)


# 15 — Version string with pre-release suffix (Apache/2.4.49-beta) → still detected
def test_version_with_suffix_detected():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={"Server": "Apache/2.4.49-beta"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # Should still detect the 2.4.49 version and report CVE-2021-41773
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) >= 1
