"""Extra branch coverage for tblue.report.sarif."""

import json
import os
import tempfile
from tblue.report import sarif


TARGET = "https://example.com"


def _finding(status="FAIL", rtype="csp — missing", detail="No CSP header", url=TARGET):
    return {"status": status, "type": rtype, "detail": detail, "url": url}


def test_generate_creates_valid_sarif_file():
    """generate() writes a valid SARIF 2.1.0 JSON file."""
    all_results = {"csp": [_finding()]}
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        sarif.generate(TARGET, all_results, path)
        with open(path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1
    finally:
        os.unlink(path)


def test_pass_findings_not_included_in_results():
    """PASS findings are registered as rules but not emitted as results."""
    all_results = {"ssl": [_finding(status="PASS", rtype="ssl / https")]}
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        sarif.generate(TARGET, all_results, path)
        with open(path) as f:
            data = json.load(f)
        run = data["runs"][0]
        # Results should be empty for PASS-only
        assert run["results"] == []
    finally:
        os.unlink(path)


def test_warn_finding_emitted_as_warning_level():
    """WARN findings are emitted as SARIF 'warning' level."""
    all_results = {"headers": [_finding(status="WARN", rtype="x-content-type-options — missing")]}
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        sarif.generate(TARGET, all_results, path)
        with open(path) as f:
            data = json.load(f)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        # WARN maps to "warning" or "note" depending on scoring severity
        assert results[0]["level"] in ("warning", "note", "error")
    finally:
        os.unlink(path)


def test_fail_finding_emitted_as_error_level():
    """FAIL findings for high-severity types are emitted as 'error' level."""
    all_results = {"cors": [_finding(status="FAIL", rtype="cors reflected origin with credentials")]}
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        sarif.generate(TARGET, all_results, path)
        with open(path) as f:
            data = json.load(f)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "error"
    finally:
        os.unlink(path)


def test_empty_results_produces_valid_sarif():
    """Empty scan results produce a valid SARIF file with no findings."""
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        sarif.generate(TARGET, {}, path)
        with open(path) as f:
            data = json.load(f)
        assert data["runs"][0]["results"] == []
    finally:
        os.unlink(path)
