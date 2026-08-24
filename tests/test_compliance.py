"""Tests for compliance report generator."""

from tblue.compliance import generate_report, OWASP_TOP_10, PCI_DSS_4, NIST_CSF


def _result(type_, status, url="https://example.com"):
    return {"type": type_, "status": status, "url": url, "detail": "", "mitre": []}


# ── Empty results ─────────────────────────────────────────────────────────────

def test_empty_results_all_unchecked():
    report = generate_report([])
    for cat, info in report["owasp_coverage"].items():
        assert info["status"] == "UNCHECKED"
    for req, info in report["pci_coverage"].items():
        assert info["status"] == "UNCHECKED"
    for func, info in report["nist_coverage"].items():
        assert info["status"] == "UNCHECKED"


# ── OWASP mapping ─────────────────────────────────────────────────────────────

def test_hsts_missing_maps_to_a02():
    report = generate_report([_result("HSTS missing", "FAIL")])
    assert report["owasp_coverage"]["A02"]["status"] == "FAIL"


def test_xss_maps_to_a03():
    report = generate_report([_result("XSS reflected in input", "FAIL")])
    assert report["owasp_coverage"]["A03"]["status"] == "FAIL"


def test_admin_exposed_maps_to_a01_and_a05():
    report = generate_report([_result("Admin panel exposed — /admin", "FAIL")])
    assert report["owasp_coverage"]["A01"]["status"] == "FAIL"
    assert report["owasp_coverage"]["A05"]["status"] == "FAIL"


def test_outdated_lib_maps_to_a06():
    report = generate_report([_result("SCA CVE — jQuery 1.11 (CVE-2019-11358)", "FAIL")])
    assert report["owasp_coverage"]["A06"]["status"] == "FAIL"


def test_jwt_alg_none_maps_to_a07():
    report = generate_report([_result("JWT alg:none accepted", "FAIL")])
    assert report["owasp_coverage"]["A07"]["status"] == "FAIL"


def test_supply_chain_maps_to_a08():
    report = generate_report([_result("SRI missing — external scripts without subresource integrity", "WARN")])
    assert report["owasp_coverage"]["A08"]["status"] == "WARN"


def test_pass_result_maps_to_pass():
    report = generate_report([_result("HSTS enforced — redirect present", "PASS")])
    # PASS on an A02 finding → A02 should be PASS
    assert report["owasp_coverage"]["A02"]["status"] == "PASS"


# ── Worst-status wins ─────────────────────────────────────────────────────────

def test_fail_beats_warn_for_same_category():
    results = [
        _result("HSTS missing — no redirect", "WARN"),
        _result("TLS 1.0 enabled — weak cipher", "FAIL"),
    ]
    report = generate_report(results)
    assert report["owasp_coverage"]["A02"]["status"] == "FAIL"


def test_fail_beats_pass():
    results = [
        _result("HSTS present", "PASS"),
        _result("HSTS missing", "FAIL"),
    ]
    report = generate_report(results)
    assert report["owasp_coverage"]["A02"]["status"] == "FAIL"


# ── PCI DSS mapping ──────────────────────────────────────────────────────────

def test_tls_maps_to_pci_4_2_1():
    report = generate_report([_result("TLS 1.0 enabled", "FAIL")])
    assert report["pci_coverage"]["4.2.1"]["status"] == "FAIL"


def test_waf_maps_to_pci_6_4_1():
    report = generate_report([_result("WAF not detected", "WARN")])
    assert report["pci_coverage"]["6.4.1"]["status"] == "WARN"


def test_xss_maps_to_pci_6_2_4():
    report = generate_report([_result("XSS reflected in search", "FAIL")])
    assert report["pci_coverage"]["6.2.4"]["status"] == "FAIL"


def test_sca_maps_to_pci_6_3_2():
    report = generate_report([_result("SCA CVE found in outdated component", "FAIL")])
    assert report["pci_coverage"]["6.3.2"]["status"] == "FAIL"


def test_supply_chain_maps_to_pci_6_4_3():
    report = generate_report([_result("SRI missing — third-party script without integrity", "WARN")])
    assert report["pci_coverage"]["6.4.3"]["status"] == "WARN"


# ── NIST CSF mapping ─────────────────────────────────────────────────────────

def test_ssl_maps_to_protect():
    report = generate_report([_result("SSL / HTTPS — no HTTPS redirect", "FAIL")])
    assert report["nist_coverage"]["PR"]["status"] == "FAIL"


def test_admin_exposed_maps_to_detect():
    report = generate_report([_result("Admin panel exposed — /phpMyAdmin", "FAIL")])
    assert report["nist_coverage"]["DE"]["status"] == "FAIL"


def test_security_txt_maps_to_respond():
    report = generate_report([_result("security.txt — file not found", "WARN")])
    assert report["nist_coverage"]["RS"]["status"] == "WARN"


def test_dns_maps_to_identify():
    report = generate_report([_result("DNS security — DNSSEC not enabled", "WARN")])
    assert report["nist_coverage"]["ID"]["status"] == "WARN"


# ── Findings grouped under OWASP ──────────────────────────────────────────────

def test_fail_findings_grouped_under_owasp():
    results = [
        _result("Admin panel exposed", "FAIL"),
        _result("CORS wildcard origin", "FAIL"),
    ]
    report = generate_report(results)
    a01_findings = report["owasp_coverage"]["A01"]["findings"]
    assert len(a01_findings) >= 1


def test_pass_findings_not_in_owasp_list():
    results = [_result("Admin panel — not found", "PASS")]
    report = generate_report(results)
    a01_findings = report["owasp_coverage"]["A01"]["findings"]
    # PASS results are not included in findings list
    assert not any(f["status"] == "PASS" for f in a01_findings)


# ── Report structure ──────────────────────────────────────────────────────────

def test_report_has_all_owasp_categories():
    report = generate_report([])
    for cat in OWASP_TOP_10:
        assert cat in report["owasp_coverage"]


def test_report_has_all_pci_requirements():
    report = generate_report([])
    for req in PCI_DSS_4:
        assert req in report["pci_coverage"]


def test_report_has_all_nist_functions():
    report = generate_report([])
    for func in NIST_CSF:
        assert func in report["nist_coverage"]


def test_summary_counts_present():
    report = generate_report([_result("HSTS missing", "FAIL")])
    summary = report["summary"]
    assert "owasp" in summary
    assert "pci" in summary
    assert "nist" in summary


def test_owasp_entries_have_label_and_findings():
    report = generate_report([])
    for cat, info in report["owasp_coverage"].items():
        assert "label" in info
        assert "status" in info
        assert "findings" in info
        assert info["label"] == OWASP_TOP_10[cat]
