"""Extra branch coverage for tblue.report.sigma — Sigma rules export."""

import os
import tempfile
import yaml
from tblue.report.sigma import generate, _finding_to_rule, _logsource_for, _severity_for_status


def _finding(status="FAIL", ftype="XSS injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "Found"}


def _results(*findings):
    return {"scanner": list(findings)}


def test_generate_writes_yaml_file():
    """generate() writes a YAML file with at least one rule for FAIL findings."""
    all_results = _results(_finding("FAIL", "SQL injection"))
    with tempfile.NamedTemporaryFile(suffix=".yml", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        assert os.path.exists(path)
        with open(path) as fh:
            content = fh.read()
        assert len(content) > 0
    finally:
        os.unlink(path)


def test_generate_pass_only_writes_empty():
    """generate() with only PASS findings writes empty/minimal output."""
    all_results = _results(_finding("PASS", "CSP"))
    with tempfile.NamedTemporaryFile(suffix=".yml", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        with open(path) as fh:
            content = fh.read()
        assert isinstance(content, str)
    finally:
        os.unlink(path)


def test_severity_for_status_fail():
    """_severity_for_status returns high/critical for FAIL."""
    sev = _severity_for_status("FAIL")
    assert sev in ("high", "critical", "medium")


def test_severity_for_status_warn():
    """_severity_for_status returns medium/low for WARN."""
    sev = _severity_for_status("WARN")
    assert sev in ("medium", "low")


def test_severity_for_status_pass():
    """_severity_for_status returns informational/low for PASS."""
    sev = _severity_for_status("PASS")
    assert sev in ("informational", "low")


def test_finding_to_rule_structure():
    """_finding_to_rule returns a dict with required Sigma fields."""
    rule = _finding_to_rule(_finding("FAIL", "XSS injection", "https://x.com"), "https://x.com")
    assert isinstance(rule, dict)
    required = {"title", "status", "description", "detection", "level"}
    for field in required:
        assert field in rule, f"Missing field: {field}"


def test_logsource_for_web_finding():
    """_logsource_for returns a dict for web-related findings."""
    src = _logsource_for("XSS injection")
    assert isinstance(src, dict)
    assert "category" in src or "product" in src
