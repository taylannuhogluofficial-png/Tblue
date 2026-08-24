"""Extra branch coverage for tblue.report.splunk_spl — Splunk SPL export."""

import os
import tempfile
from tblue.report.splunk_spl import generate, _spl_for_finding


def _finding(status="FAIL", ftype="XSS injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "Found"}


def _results(*findings):
    return {"scanner": list(findings)}


def test_generate_writes_file():
    """generate() writes a non-empty SPL file for FAIL findings."""
    all_results = _results(_finding("FAIL", "SQL injection"), _finding("WARN", "Missing CSP"))
    with tempfile.NamedTemporaryFile(suffix=".spl", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        assert os.path.exists(path)
        with open(path) as fh:
            content = fh.read()
        assert len(content) > 0
    finally:
        os.unlink(path)


def test_generate_empty_produces_file():
    """generate() with no FAIL/WARN findings still writes a valid file."""
    all_results = _results(_finding("PASS", "CSP"))
    with tempfile.NamedTemporaryFile(suffix=".spl", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        assert os.path.exists(path)
    finally:
        os.unlink(path)


def test_spl_for_xss_returns_string():
    """_spl_for_finding for XSS returns a non-empty string."""
    spl = _spl_for_finding("XSS injection", "https://example.com/search")
    assert isinstance(spl, str)
    assert len(spl) > 0


def test_spl_for_unknown_finding_type():
    """_spl_for_finding returns fallback SPL for unknown finding types."""
    spl = _spl_for_finding("totally-unknown-finding-xyz-99999", "https://example.com")
    assert isinstance(spl, str)
    assert len(spl) > 0


def test_generate_multiple_findings():
    """generate() handles multiple distinct finding types."""
    all_results = _results(
        _finding("FAIL", "XSS injection"),
        _finding("FAIL", "SQL injection"),
        _finding("WARN", "Open redirect"),
        _finding("FAIL", "SSRF detection"),
    )
    with tempfile.NamedTemporaryFile(suffix=".spl", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path)
        with open(path) as fh:
            content = fh.read()
        assert len(content) > 0
    finally:
        os.unlink(path)
