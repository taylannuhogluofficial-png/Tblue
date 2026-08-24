"""Tests for tblue.report.splunk_spl — Splunk SPL export."""

import os
import tempfile
import pytest
from tblue.report.splunk_spl import generate, _spl_for_finding


def _finding(status="FAIL", ftype="XSS — reflected injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "XSS found"}


def test_spl_for_xss():
    spl = _spl_for_finding("XSS reflected injection", "https://x.com/search")
    assert "uri" in spl.lower() or "script" in spl.lower()

def test_spl_for_nosql():
    spl = _spl_for_finding("NoSQL injection MongoDB error", "https://x.com")
    assert "Mongo" in spl or "nosql" in spl.lower()

def test_spl_for_ssrf():
    spl = _spl_for_finding("SSRF — cloud metadata endpoint", "https://x.com")
    assert "169.254" in spl or "metadata" in spl.lower()

def test_spl_fallback_default():
    spl = _spl_for_finding("something completely unknown XYZ", "https://x.com/path")
    assert "index=" in spl or "W3CIISLog" in spl or "uri" in spl.lower()

def test_generate_creates_file():
    findings = {"xss": [_finding()]}
    with tempfile.NamedTemporaryFile(suffix=".spl", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        assert os.path.exists(path)
        content = open(path).read()
        assert "Tblue" in content
    finally:
        os.unlink(path)

def test_generate_skips_pass():
    findings = {"ssl": [_finding(status="PASS", ftype="SSL valid")]}
    with tempfile.NamedTemporaryFile(suffix=".spl", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        content = open(path).read()
        assert "no correlation rules" in content.lower() or "Rule 1" not in content
    finally:
        os.unlink(path)

def test_generate_deduplicates():
    findings = {
        "a": [_finding(ftype="XSS reflected")],
        "b": [_finding(ftype="XSS reflected")],  # duplicate
    }
    with tempfile.NamedTemporaryFile(suffix=".spl", delete=False) as f:
        path = f.name
    try:
        generate("https://x.com", findings, path)
        content = open(path).read()
        # Should have rule 1 but not rule 2 (deduplicated)
        assert "Rule 2:" not in content
    finally:
        os.unlink(path)
