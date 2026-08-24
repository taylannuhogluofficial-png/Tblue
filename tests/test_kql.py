"""Tests for tblue.report.kql — Microsoft Sentinel KQL export."""

import os
import json
import tempfile
import pytest
from tblue.report.kql import generate, _kql_for_finding, _rule_id


def _finding(status="FAIL", ftype="XSS injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "Found XSS"}


def test_kql_for_xss():
    kql = _kql_for_finding("XSS reflected injection", "https://x.com")
    assert "script" in kql.lower() or "W3C" in kql

def test_kql_for_ssrf():
    kql = _kql_for_finding("SSRF cloud metadata", "https://x.com")
    assert "169.254" in kql or "metadata" in kql.lower()

def test_kql_fallback():
    kql = _kql_for_finding("unknown xyz finding", "https://x.com/api")
    assert "W3CIISLog" in kql or "where" in kql

def test_rule_id_is_uuid_like():
    rid = _rule_id("XSS reflected")
    parts = rid.split("-")
    assert len(parts) == 5

def test_generate_creates_valid_json():
    findings = {"xss": [_finding()]}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            data = json.load(f)
        assert data["schema"] == "tblue-sentinel-rules-v1"
        assert len(data["rules"]) >= 1
    finally:
        os.unlink(path)

def test_generate_rule_fields():
    findings = {"xss": [_finding()]}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            data = json.load(f)
        rule = data["rules"][0]
        assert "id" in rule
        assert "name" in rule
        assert "severity" in rule
        assert "query" in rule
        assert rule["severity"] == "High"  # FAIL → High
    finally:
        os.unlink(path)

def test_generate_skips_pass():
    findings = {"ssl": [_finding(status="PASS", ftype="SSL valid")]}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            data = json.load(f)
        assert data["rule_count"] == 0
    finally:
        os.unlink(path)

def test_generate_warn_is_medium_severity():
    findings = {"csp": [_finding(status="WARN", ftype="CSP missing")]}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            data = json.load(f)
        rule = data["rules"][0]
        assert rule["severity"] == "Medium"
    finally:
        os.unlink(path)

def test_generate_deduplicates():
    findings = {
        "a": [_finding(ftype="XSS reflected")],
        "b": [_finding(ftype="XSS reflected")],
    }
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        with open(path) as f:
            data = json.load(f)
        assert data["rule_count"] == 1
    finally:
        os.unlink(path)
