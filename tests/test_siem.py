"""Tests for SIEM-native export formats (CEF, LEEF, Elastic NDJSON, Sentinel)."""

import json
import os
import tempfile
import pytest
from unittest.mock import MagicMock

from tblue.report.siem import generate, _flatten, _to_cef, _to_leef, _to_elastic_ndjson, _to_sentinel_json


# ── Fixtures ──────────────────────────────────────────────────────────────────

_SAMPLE_RESULTS = {
    "headers": [
        {
            "type":   "Security headers — Content-Security-Policy",
            "status": "FAIL",
            "url":    "https://example.com",
            "detail": "CSP header missing. Fix: add Content-Security-Policy.",
        },
        {
            "type":   "Security headers — X-Frame-Options",
            "status": "WARN",
            "url":    "https://example.com",
            "detail": "X-Frame-Options not set.",
        },
        {
            "type":   "Security headers — HSTS",
            "status": "PASS",
            "url":    "https://example.com",
            "detail": "HSTS configured correctly.",
        },
    ],
    "cookies": [
        {
            "type":   "Cookie — missing HttpOnly",
            "status": "FAIL",
            "url":    "https://example.com",
            "detail": "session cookie lacks HttpOnly flag.",
        },
    ],
}

_EMPTY_RESULTS: dict = {"headers": [], "cookies": []}

_MOCK_SCORE = MagicMock()
_MOCK_SCORE.score = 72
_MOCK_SCORE.grade = "C"


def _flat():
    return _flatten("https://example.com", _SAMPLE_RESULTS)


# ── _flatten ──────────────────────────────────────────────────────────────────

def test_flatten_excludes_pass():
    flat = _flat()
    assert all(f["status"] != "PASS" for f in flat)


def test_flatten_includes_fail_and_warn():
    flat = _flat()
    statuses = {f["status"] for f in flat}
    assert "FAIL" in statuses
    assert "WARN" in statuses


def test_flatten_injects_severity():
    flat = _flat()
    assert all("severity" in f for f in flat)
    assert all(f["severity"] in ("critical", "high", "medium", "low", "info")
               for f in flat)


def test_flatten_empty_results_returns_empty():
    assert _flatten("https://example.com", _EMPTY_RESULTS) == []


# ── CEF ──────────────────────────────────────────────────────────────────────

def test_cef_starts_with_cef_header():
    output = _to_cef(_flat())
    for line in output.strip().splitlines():
        assert line.startswith("CEF:0|Tblue|Tblue|")


def test_cef_contains_url():
    output = _to_cef(_flat())
    assert "example.com" in output


def test_cef_contains_status():
    output = _to_cef(_flat())
    assert "FAIL" in output
    assert "WARN" in output


def test_cef_severity_is_integer():
    output = _to_cef(_flat())
    for line in output.strip().splitlines():
        parts = line.split("|")
        # Severity is the 7th pipe-delimited field (index 6)
        assert parts[6].isdigit()


def test_cef_empty_findings_returns_empty():
    assert _to_cef([]) == ""


def test_cef_escapes_pipe_in_detail():
    flat = [{
        "module": "test", "type": "Test|Finding", "status": "FAIL",
        "severity": "high", "url": "https://x.com", "detail": "pipe|in|detail",
    }]
    output = _to_cef(flat)
    # Pipes in detail are escaped as \|
    assert "\\|" in output


# ── LEEF ─────────────────────────────────────────────────────────────────────

def test_leef_starts_with_leef_header():
    output = _to_leef(_flat())
    for line in output.strip().splitlines():
        assert line.startswith("LEEF:1.0|Tblue|Tblue|")


def test_leef_contains_tab_separated_attrs():
    output = _to_leef(_flat())
    for line in output.strip().splitlines():
        # Extension section (after 5th pipe) must have tabs
        ext = line.split("|", 5)[5]
        assert "\t" in ext


def test_leef_contains_required_fields():
    output = _to_leef(_flat())
    assert "devTime=" in output
    assert "dstURL=" in output
    assert "severity=" in output
    assert "status=" in output
    assert "msg=" in output


def test_leef_empty_findings_returns_empty():
    assert _to_leef([]) == ""


# ── Elastic NDJSON (ECS) ─────────────────────────────────────────────────────

def test_elastic_is_valid_ndjson():
    output = _to_elastic_ndjson(_flat(), None)
    for line in output.strip().splitlines():
        doc = json.loads(line)  # must not raise
        assert isinstance(doc, dict)


def test_elastic_has_required_ecs_fields():
    output = _to_elastic_ndjson(_flat(), None)
    first = json.loads(output.splitlines()[0])
    assert "@timestamp" in first
    assert "event" in first
    assert "rule" in first
    assert "url" in first
    assert "message" in first
    assert "observer" in first


def test_elastic_event_kind_is_alert():
    output = _to_elastic_ndjson(_flat(), None)
    first = json.loads(output.splitlines()[0])
    assert first["event"]["kind"] == "alert"


def test_elastic_observer_vendor():
    output = _to_elastic_ndjson(_flat(), None)
    first = json.loads(output.splitlines()[0])
    assert first["observer"]["vendor"] == "Tblue"
    assert first["observer"]["product"] == "Tblue"


def test_elastic_includes_score_when_provided():
    output = _to_elastic_ndjson(_flat(), _MOCK_SCORE)
    first = json.loads(output.splitlines()[0])
    assert first["labels"]["security_score"] == "72"
    assert first["labels"]["security_grade"] == "C"


def test_elastic_empty_findings_returns_empty():
    assert _to_elastic_ndjson([], None) == ""


# ── Microsoft Sentinel ────────────────────────────────────────────────────────

def test_sentinel_is_valid_json_array():
    output = _to_sentinel_json(_flat(), None)
    records = json.loads(output)
    assert isinstance(records, list)
    assert len(records) == 3  # 2 FAIL + 1 WARN, no PASS


def test_sentinel_has_required_fields():
    output = _to_sentinel_json(_flat(), None)
    rec = json.loads(output)[0]
    assert "TimeGenerated" in rec
    assert "URL" in rec
    assert "RuleName" in rec
    assert "Status" in rec
    assert "Severity" in rec
    assert "Detail" in rec
    assert "SourceSystem" in rec


def test_sentinel_includes_score_when_provided():
    output = _to_sentinel_json(_flat(), _MOCK_SCORE)
    rec = json.loads(output)[0]
    assert rec["SecurityScore"] == 72
    assert rec["SecurityGrade"] == "C"


def test_sentinel_severity_is_uppercase():
    output = _to_sentinel_json(_flat(), None)
    for rec in json.loads(output):
        assert rec["Severity"] == rec["Severity"].upper()


def test_sentinel_empty_findings_returns_empty_array():
    output = _to_sentinel_json([], None)
    assert json.loads(output) == []


# ── generate() — file output ──────────────────────────────────────────────────

@pytest.mark.parametrize("fmt,expected_content", [
    ("cef",      "CEF:0|Tblue"),
    ("leef",     "LEEF:1.0|Tblue"),
    ("elastic",  "@timestamp"),
    ("sentinel", "TimeGenerated"),
])
def test_generate_writes_file(fmt, expected_content, tmp_path):
    out = str(tmp_path / f"report.{fmt}")
    generate("https://example.com", _SAMPLE_RESULTS, out, fmt=fmt, scan_score=_MOCK_SCORE)
    assert os.path.exists(out)
    content = open(out).read()
    assert expected_content in content


def test_generate_unknown_format_raises():
    with pytest.raises(ValueError, match="Unknown SIEM format"):
        generate("https://example.com", _SAMPLE_RESULTS, "/tmp/x.txt", fmt="splunk")


def test_generate_empty_results_writes_file(tmp_path):
    out = str(tmp_path / "empty.ndjson")
    generate("https://example.com", _EMPTY_RESULTS, out, fmt="elastic")
    assert os.path.exists(out)


def test_generate_cef_no_pass_findings(tmp_path):
    out = str(tmp_path / "report.cef")
    generate("https://example.com", _SAMPLE_RESULTS, out, fmt="cef")
    content = open(out).read()
    # PASS findings should not appear
    assert "HSTS" not in content or "PASS" not in content
