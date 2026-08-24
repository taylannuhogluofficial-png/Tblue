"""Tests for Software Composition Analysis scanner."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.sca import (
    SCAScanner, _parse_package_json, _parse_requirements_txt,
    _parse_gemfile_lock, _osv_severity, _highest_severity,
)


def make_scanner():
    return SCAScanner(MagicMock())


# ── Parsers ───────────────────────────────────────────────────────────────────

def test_parse_package_json():
    content = json.dumps({
        "dependencies": {"express": "4.18.2", "lodash": "4.17.20"},
        "devDependencies": {"jest": "29.0.0"}
    })
    deps = _parse_package_json(content)
    names = [d[0] for d in deps]
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names


def test_parse_requirements_txt():
    content = "Django==4.2.0\nrequests>=2.28.0\nflask==2.3.0\n# comment\n"
    deps = _parse_requirements_txt(content)
    names = [d[0] for d in deps]
    assert "Django" in names
    assert "requests" in names
    assert "flask" in names


def test_parse_gemfile_lock():
    content = """GEM
  specs:
    rails (7.0.4)
    devise (4.9.0)

BUNDLED WITH
   2.3.0
"""
    deps = _parse_gemfile_lock(content)
    names = [d[0] for d in deps]
    assert "rails" in names
    assert "devise" in names


def test_parse_package_json_invalid():
    deps = _parse_package_json("not json")
    assert deps == []


# ── Severity helpers ──────────────────────────────────────────────────────────

def test_osv_severity_critical():
    adv = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert _osv_severity(adv) == "CRITICAL"


def test_osv_severity_high():
    adv = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert _osv_severity(adv) == "HIGH"


def test_osv_severity_medium():
    adv = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
    assert _osv_severity(adv) == "MEDIUM"


def test_osv_severity_no_score():
    adv = {}
    assert _osv_severity(adv) == "MEDIUM"  # default


def test_highest_severity():
    assert _highest_severity(["LOW", "CRITICAL", "HIGH"]) == "CRITICAL"
    assert _highest_severity(["MEDIUM", "LOW"]) == "MEDIUM"
    assert _highest_severity([]) == "LOW"


# ── Scanner integration ───────────────────────────────────────────────────────

def test_vulnerable_dep_fails():
    scanner = make_scanner()
    # Mock OSV batch response
    osv_resp = MagicMock()
    osv_resp.status_code = 200
    osv_resp.json.return_value = {
        "results": [
            {"vulns": [{"id": "GHSA-1234-5678-9abc", "summary": "RCE vulnerability",
                        "severity": [{"type": "CVSS_V3", "score": "9.8"}]}]},
            {"vulns": []},
        ]
    }
    scanner.http.session = MagicMock()
    scanner.http.session.post.return_value = osv_resp
    scanner._analyse_manifest("package.json",
                              json.dumps({"dependencies": {"lodash": "4.17.10", "express": "4.0.0"}}),
                              "https://example.com/package.json")
    assert any("vulnerable" in r["type"].lower() and r["status"] in ("FAIL", "WARN")
               for r in scanner.results)


def test_no_vulns_passes():
    scanner = make_scanner()
    osv_resp = MagicMock()
    osv_resp.status_code = 200
    osv_resp.json.return_value = {"results": [{"vulns": []}, {"vulns": []}]}
    scanner.http.session = MagicMock()
    scanner.http.session.post.return_value = osv_resp
    scanner._analyse_manifest("package.json",
                              json.dumps({"dependencies": {"lodash": "4.17.21"}}),
                              "https://example.com/package.json")
    assert any("no known vulnerabilities" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


# ── scan() method ─────────────────────────────────────────────────────────────

def _make_manifest_scanner(manifest_content, status=200):
    """Scanner where http.get returns a mock with manifest content."""
    session = MagicMock()
    scanner = SCAScanner(session)
    resp_mock = MagicMock()
    resp_mock.status_code = status
    resp_mock.text = manifest_content
    scanner.http.get = MagicMock(return_value=resp_mock)
    scanner.http.session = MagicMock()
    return scanner


def test_scan_with_valid_manifest_no_vulns():
    scanner = _make_manifest_scanner(
        json.dumps({"dependencies": {"lodash": "4.17.21"}})
    )
    scanner.http.session.post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"results": [{"vulns": []}]}
    )
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_scan_none_response_skips():
    scanner = SCAScanner(MagicMock())
    scanner.http.get = MagicMock(return_value=None)
    results = scanner.scan("https://example.com")
    assert results == []


def test_scan_non_200_response_skips():
    scanner = _make_manifest_scanner("Not Found", status=404)
    results = scanner.scan("https://example.com")
    assert results == []


def test_scan_html_false_positive_skipped():
    scanner = _make_manifest_scanner("<html><body>Not found</body></html>")
    results = scanner.scan("https://example.com")
    assert results == []


def test_scan_short_content_skipped():
    scanner = _make_manifest_scanner("{}")
    results = scanner.scan("https://example.com")
    assert results == []


def test_scan_http_get_exception_continues():
    scanner = SCAScanner(MagicMock())
    scanner.http.get = MagicMock(side_effect=Exception("connection reset"))
    results = scanner.scan("https://example.com")
    assert results == []


# ── scan_manifest() external call ─────────────────────────────────────────────

def test_scan_manifest_external():
    scanner = make_scanner()
    scanner.http.session = MagicMock()
    scanner.http.session.post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"results": [{"vulns": []}]}
    )
    results = scanner.scan_manifest(
        "requirements.txt",
        "Django==4.2.0\n",
        "https://example.com/requirements.txt"
    )
    assert isinstance(results, list)


# ── _analyse_manifest edge cases ──────────────────────────────────────────────

def test_analyse_unknown_filename_skips():
    scanner = make_scanner()
    scanner._analyse_manifest("unknown.xyz", "some content", "https://x.com/unknown.xyz")
    assert scanner.results == []


def test_analyse_empty_deps_skips():
    scanner = make_scanner()
    # requirements.txt with no parseable deps
    scanner._analyse_manifest("requirements.txt", "# only comments\n", "https://x.com/req")
    assert scanner.results == []


# ── _query_osv_batch edge cases ───────────────────────────────────────────────

def test_osv_batch_none_response_returns_empty():
    scanner = make_scanner()
    scanner.http.session = MagicMock()
    scanner.http.session.post.return_value = None
    result = scanner._query_osv_batch([("django", "2.2.0")], "PyPI")
    assert result == []


def test_osv_batch_non_200_returns_empty():
    scanner = make_scanner()
    scanner.http.session = MagicMock()
    scanner.http.session.post.return_value = MagicMock(status_code=500)
    result = scanner._query_osv_batch([("django", "2.2.0")], "PyPI")
    assert result == []


def test_osv_batch_exception_returns_empty():
    scanner = make_scanner()
    scanner.http.session = MagicMock()
    scanner.http.session.post.side_effect = Exception("timeout")
    result = scanner._query_osv_batch([("django", "2.2.0")], "PyPI")
    assert result == []


# ── Parser edge cases ─────────────────────────────────────────────────────────

def test_parse_package_json_version_with_no_digits():
    # Version like "*" → re.sub removes everything → empty string → skipped
    content = json.dumps({"dependencies": {"some-pkg": "*", "lodash": "4.17.0"}})
    deps = _parse_package_json(content)
    names = [d[0] for d in deps]
    assert "some-pkg" not in names
    assert "lodash" in names


def test_parse_requirements_txt_skips_no_match_lines():
    content = "Django==4.2.0\n   \n-r other.txt\nsome-package-no-version\n"
    deps = _parse_requirements_txt(content)
    names = [d[0] for d in deps]
    assert "Django" in names
    assert "some-package-no-version" not in names


def test_parse_gemfile_lock_empty_line_exits_specs():
    content = """GEM
  specs:
    rails (7.0.4)

  PLATFORMS
    x86_64-linux
"""
    deps = _parse_gemfile_lock(content)
    names = [d[0] for d in deps]
    assert "rails" in names


# ── Severity LOW branch ────────────────────────────────────────────────────────

def test_osv_severity_low():
    adv = {"severity": [{"type": "CVSS_V3", "score": "2.1"}]}
    assert _osv_severity(adv) == "LOW"


def test_osv_severity_invalid_score_falls_through():
    adv = {"severity": [{"type": "CVSS_V3", "score": "not-a-number"}]}
    assert _osv_severity(adv) == "MEDIUM"  # falls through to default


def test_highest_severity_with_info():
    # No standard severities, just INFO-like or empty
    assert _highest_severity([]) == "LOW"
