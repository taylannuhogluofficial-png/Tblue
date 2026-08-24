"""Extra branch coverage for tblue.report.siem — SIEM-native export formats."""

import json
import os
import tempfile
from tblue.report.siem import generate, _flatten, _to_cef, _to_leef


def _finding(status="FAIL", ftype="XSS injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "Found"}


def _results(*findings):
    return {"scanner": list(findings)}


def test_generate_cef_produces_file():
    """generate() with fmt='cef' writes a non-empty CEF file."""
    all_results = _results(_finding("FAIL", "XSS injection"), _finding("WARN", "Missing CSP"))
    with tempfile.NamedTemporaryFile(suffix=".cef", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path, fmt="cef")
        assert os.path.exists(path)
        with open(path) as fh:
            content = fh.read()
        assert "CEF:" in content
    finally:
        os.unlink(path)


def test_generate_leef_produces_file():
    """generate() with fmt='leef' writes a non-empty LEEF file."""
    all_results = _results(_finding("FAIL", "SQL injection"))
    with tempfile.NamedTemporaryFile(suffix=".leef", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path, fmt="leef")
        assert os.path.exists(path)
        with open(path) as fh:
            content = fh.read()
        assert "LEEF:" in content
    finally:
        os.unlink(path)


def test_generate_elastic_produces_ndjson():
    """generate() with fmt='elastic' writes valid NDJSON."""
    all_results = _results(_finding("FAIL", "Open redirect"), _finding("PASS", "CSP"))
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", all_results, path, fmt="elastic")
        with open(path) as fh:
            lines = [l.strip() for l in fh if l.strip()]
        for line in lines:
            json.loads(line)
    finally:
        os.unlink(path)


def test_flatten_returns_list():
    """_flatten returns a list of flattened findings."""
    all_results = _results(_finding("FAIL", "XSS"), _finding("PASS", "CSP"))
    flat = _flatten("https://example.com", all_results)
    assert isinstance(flat, list)


def test_flatten_excludes_pass():
    """_flatten excludes PASS findings."""
    all_results = _results(_finding("FAIL", "XSS"), _finding("PASS", "CSP"))
    flat = _flatten("https://example.com", all_results)
    assert all(f.get("status") != "PASS" for f in flat)


def test_to_cef_structure():
    """_to_cef returns string starting with CEF: for non-empty flat list."""
    all_results = _results(_finding("FAIL", "SQL injection", "https://example.com/q?id=1"))
    flat = _flatten("https://example.com", all_results)
    cef = _to_cef(flat)
    assert "CEF:" in cef


def test_generate_empty_results():
    """generate() with empty all_results writes valid empty output."""
    with tempfile.NamedTemporaryFile(suffix=".cef", delete=False) as f:
        path = f.name
    try:
        generate("https://example.com", {}, path, fmt="cef")
        assert os.path.exists(path)
    finally:
        os.unlink(path)
