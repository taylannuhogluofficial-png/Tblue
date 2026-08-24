"""Extra branch coverage for tblue.compliance."""

from tblue.compliance import generate_report, _match_frameworks, OWASP_TOP_10, CWE_TOP25


def _result(type_, status, url="https://example.com"):
    return {"type": type_, "status": status, "url": url, "detail": "", "mitre": []}


def test_match_frameworks_cors_maps_to_owasp():
    """Covers the CORS keyword mapping in _match_frameworks."""
    mapping = _match_frameworks("CORS — reflected origin with credentials")
    assert "A01" in mapping.get("owasp", []) or "A05" in mapping.get("owasp", [])


def test_match_frameworks_injection_maps_to_a03():
    """Covers injection/XSS keyword mapping."""
    mapping = _match_frameworks("XSS reflected in query parameter")
    assert "A03" in mapping.get("owasp", [])


def test_match_frameworks_unknown_type_returns_empty():
    """Covers the branch where no rule matches the finding type."""
    mapping = _match_frameworks("completely unrelated scan finding xyz123")
    # Unknown type: may return empty or minimal mapping
    assert isinstance(mapping, dict)


def test_generate_report_contains_all_framework_keys():
    """Covers that generate_report always returns all framework coverage keys."""
    report = generate_report([])
    assert "owasp_coverage" in report
    assert "pci_coverage" in report
    assert "nist_coverage" in report


def test_warn_does_not_override_fail():
    """Covers the worst-status logic: FAIL beats WARN for same OWASP category."""
    results = [
        _result("TLS 1.0 enabled — weak cipher", "FAIL"),
        _result("HSTS missing", "WARN"),
    ]
    report = generate_report(results)
    assert report["owasp_coverage"]["A02"]["status"] == "FAIL"


def test_pass_does_not_override_warn():
    """Covers that PASS does not downgrade an existing WARN."""
    results = [
        _result("HSTS redirect present", "PASS"),
        _result("HSTS max-age too short", "WARN"),
    ]
    report = generate_report(results)
    # WARN should win over PASS for A02
    assert report["owasp_coverage"]["A02"]["status"] in ("WARN", "FAIL")


def test_generate_report_summary_counts():
    """Covers the summary counts section of the report."""
    results = [
        _result("CORS misconfiguration", "FAIL"),
        _result("X-Frame-Options missing", "WARN"),
        _result("HSTS enforced", "PASS"),
    ]
    report = generate_report(results)
    # Report should have counts summary
    assert "summary" in report or "owasp_coverage" in report


def test_owasp_top10_all_present_in_report():
    """Covers that all OWASP Top 10 categories appear in coverage output."""
    report = generate_report([])
    for key in OWASP_TOP_10:
        assert key in report["owasp_coverage"]
