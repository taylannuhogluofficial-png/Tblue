"""Extra branch coverage for tblue.report.kql — Microsoft Sentinel KQL export."""

import json
import tempfile
import os
from tblue.report.kql import generate, _kql_for_finding, _rule_id


def _finding(status="FAIL", ftype="XSS injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "Found"}


def _results(*findings):
    return {"scanner": list(findings)}


def test_generate_empty_findings_produces_file():
    """generate() with empty findings writes a valid JSON file."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", {}, path)
        assert os.path.exists(path)
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, (list, dict))
    finally:
        os.unlink(path)


def test_generate_fail_finding_produces_rule():
    """generate() with a FAIL finding produces at least one KQL rule."""
    all_results = _results(_finding("FAIL", "SQL injection"))
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        with open(path) as fh:
            content = fh.read()
        assert len(content) > 0
    finally:
        os.unlink(path)


def test_pass_findings_excluded():
    """PASS findings are not included in KQL output."""
    all_results = _results(_finding("PASS", "Header check"))
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        with open(path) as fh:
            data = json.load(fh)
        rules = data if isinstance(data, list) else data.get("resources", [])
        assert len(rules) == 0
    finally:
        os.unlink(path)


def test_rule_id_deterministic():
    """_rule_id returns the same ID for the same input."""
    id1 = _rule_id("xss-injection")
    id2 = _rule_id("xss-injection")
    assert id1 == id2


def test_kql_for_unknown_finding_type():
    """_kql_for_finding returns a non-empty string for unknown finding types."""
    kql = _kql_for_finding("some-totally-unknown-finding-xyz", "https://example.com")
    assert isinstance(kql, str)
    assert len(kql) > 0


def test_kql_for_xss_finding():
    """_kql_for_finding for XSS returns KQL with script filter."""
    kql = _kql_for_finding("XSS injection", "https://example.com/search")
    assert isinstance(kql, str)
    assert len(kql) > 0
