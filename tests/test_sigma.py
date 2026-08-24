"""Tests for tblue.report.sigma — Sigma rules export."""

import os
import tempfile
import pytest
import yaml
from tblue.report.sigma import generate, _finding_to_rule, _logsource_for, _severity_for_status


def _finding(status="FAIL", ftype="XSS — reflected script injection", url="https://x.com/search"):
    return {"status": status, "type": ftype, "url": url, "detail": "XSS found in search param"}


# ── _severity_for_status ──────────────────────────────────────────────────────

def test_severity_fail_is_high():
    assert _severity_for_status("FAIL") == "high"

def test_severity_warn_is_medium():
    assert _severity_for_status("WARN") == "medium"

def test_severity_pass_is_informational():
    assert _severity_for_status("PASS") == "informational"


# ── _logsource_for ────────────────────────────────────────────────────────────

def test_logsource_xss_is_webserver():
    ls = _logsource_for("XSS reflected injection")
    assert ls["category"] == "webserver"

def test_logsource_auth_is_authentication():
    ls = _logsource_for("JWT algorithm none — weak signature")
    assert ls["category"] == "authentication"

def test_logsource_cloud_is_cloud():
    ls = _logsource_for("Cloud metadata SSRF exposure")
    assert ls["category"] == "cloud"

def test_logsource_default_fallback():
    ls = _logsource_for("some unknown finding type XYZ")
    assert "category" in ls


# ── _finding_to_rule ──────────────────────────────────────────────────────────

def test_finding_to_rule_structure():
    rule = _finding_to_rule(_finding(), "https://x.com")
    assert rule is not None
    assert "title" in rule
    assert "detection" in rule
    assert "level" in rule
    assert rule["level"] == "high"

def test_finding_to_rule_skips_pass():
    rule = _finding_to_rule(_finding(status="PASS"), "https://x.com")
    assert rule is None

def test_finding_to_rule_warn_is_medium():
    rule = _finding_to_rule(_finding(status="WARN"), "https://x.com")
    assert rule is not None
    assert rule["level"] == "medium"

def test_finding_to_rule_title_contains_finding_type():
    rule = _finding_to_rule(_finding(ftype="CORS wildcard origin"), "https://x.com")
    assert "CORS" in rule["title"] or "cors" in rule["title"].lower()


# ── generate ─────────────────────────────────────────────────────────────────

def test_generate_creates_file():
    findings = {"xss": [_finding()], "cors": [_finding(ftype="CORS — wildcard", status="WARN")]}
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Tblue" in content
    finally:
        os.unlink(path)

def test_generate_valid_yaml():
    findings = {"xss": [_finding()]}
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            content = f.read()
        # Should be parseable YAML (multi-doc with ---)
        docs = list(yaml.safe_load_all(content))
        assert len(docs) >= 1
        assert docs[0]["title"].startswith("Tblue:")
    finally:
        os.unlink(path)

def test_generate_skips_pass_findings():
    findings = {"ssl": [_finding(status="PASS", ftype="SSL — certificate valid")]}
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            content = f.read()
        assert content.strip() == "" or "title" not in content
    finally:
        os.unlink(path)

def test_generate_deduplicates_rules():
    # Same finding type at different URLs — should deduplicate by id
    findings = {
        "xss1": [_finding(url="https://x.com/a")],
        "xss2": [_finding(url="https://x.com/b")],  # different URL = different id
    }
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        assert os.path.exists(path)
    finally:
        os.unlink(path)
