"""Tests for SARIF 2.1.0 report generator."""

import json
import tempfile
from pathlib import Path
from tblue.report.sarif import generate
from tblue.scoring import score_results


def _results(status="FAIL"):
    return {"ssl": [{"type": "SSL / HTTPS", "status": status, "url": "https://example.com",
                     "detail": "HTTP redirect missing."}]}


def _write_sarif(all_results, scan_score=None):
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
        path = f.name
    generate("https://example.com", all_results, path, scan_score=scan_score)
    return json.loads(Path(path).read_text())


def test_sarif_schema_field():
    sarif = _write_sarif(_results())
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"


def test_sarif_version():
    sarif = _write_sarif(_results())
    assert sarif["version"] == "2.1.0"


def test_sarif_has_one_run():
    sarif = _write_sarif(_results())
    assert len(sarif["runs"]) == 1


def test_sarif_tool_name():
    sarif = _write_sarif(_results())
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Tblue"


def test_fail_produces_result():
    sarif = _write_sarif(_results("FAIL"))
    assert len(sarif["runs"][0]["results"]) >= 1


def test_warn_produces_result():
    sarif = _write_sarif(_results("WARN"))
    assert len(sarif["runs"][0]["results"]) >= 1


def test_pass_produces_no_result():
    sarif = _write_sarif(_results("PASS"))
    assert sarif["runs"][0]["results"] == []


def test_result_has_rule_id():
    sarif   = _write_sarif(_results("FAIL"))
    results = sarif["runs"][0]["results"]
    assert all("ruleId" in r for r in results)


def test_result_has_message():
    sarif   = _write_sarif(_results("FAIL"))
    result  = sarif["runs"][0]["results"][0]
    assert "message" in result and "text" in result["message"]


def test_result_has_location():
    sarif  = _write_sarif(_results("FAIL"))
    result = sarif["runs"][0]["results"][0]
    assert "locations" in result and len(result["locations"]) > 0


def test_rules_registered():
    sarif = _write_sarif(_results("FAIL"))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    assert all("id" in r and "shortDescription" in r for r in rules)


def test_score_in_properties():
    results    = _results("PASS")
    scan_score = score_results(results)
    sarif      = _write_sarif(results, scan_score=scan_score)
    props      = sarif["runs"][0].get("properties", {})
    assert "score" in props


def test_critical_finding_has_error_level():
    results = {"info": [{"type": "API keys in page source", "status": "FAIL",
                          "url": "https://example.com", "detail": "Key found."}]}
    sarif   = _write_sarif(results)
    r       = sarif["runs"][0]["results"]
    assert any(x["level"] == "error" for x in r)


def test_low_finding_has_note_level():
    results = {"info": [{"type": "HTML comments", "status": "FAIL",
                          "url": "https://example.com", "detail": "Comments."}]}
    sarif   = _write_sarif(results)
    r       = sarif["runs"][0]["results"]
    assert any(x["level"] == "note" for x in r)
