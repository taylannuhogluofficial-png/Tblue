"""Tests for tblue.remediation — Remediation playbook generator."""

import pytest
from tblue.remediation import generate_playbooks, format_terminal, format_markdown


def _finding(status="FAIL", ftype="XSS — reflected injection", url="https://x.com"):
    return {"status": status, "type": ftype, "url": url, "detail": "XSS found"}


# ── generate_playbooks ────────────────────────────────────────────────────────

def test_no_findings_empty_playbooks():
    result = generate_playbooks({"ssl": [_finding(status="PASS")]})
    assert result == []

def test_fail_generates_playbook():
    results = generate_playbooks({"xss": [_finding(status="FAIL", ftype="XSS — reflected injection")]})
    assert len(results) >= 1
    assert results[0]["status"] == "FAIL"

def test_warn_generates_playbook():
    results = generate_playbooks({"csp": [_finding(status="WARN", ftype="CSP missing header")]})
    assert len(results) >= 1
    assert results[0]["status"] == "WARN"

def test_playbook_has_required_fields():
    results = generate_playbooks({"auth": [_finding(status="FAIL", ftype="JWT algorithm none detected")]})
    assert results
    pb = results[0]
    assert "title" in pb
    assert "steps" in pb
    assert "severity" in pb
    assert "time_to_fix" in pb
    assert "verification" in pb
    assert "references" in pb

def test_fail_sorted_before_warn():
    all_results = {
        "warn1": [_finding(status="WARN", ftype="CSP missing", url="https://x.com/a")],
        "fail1": [_finding(status="FAIL", ftype="XSS reflected", url="https://x.com/b")],
    }
    results = generate_playbooks(all_results)
    statuses = [pb["status"] for pb in results]
    fail_idx = next((i for i, s in enumerate(statuses) if s == "FAIL"), None)
    warn_idx = next((i for i, s in enumerate(statuses) if s == "WARN"), None)
    if fail_idx is not None and warn_idx is not None:
        assert fail_idx <= warn_idx

def test_known_pattern_jwt():
    results = generate_playbooks({"jwt": [_finding(status="FAIL", ftype="JWT algorithm none — no signature")]})
    assert results
    assert any("JWT" in pb["title"] for pb in results)

def test_known_pattern_cors():
    results = generate_playbooks({"cors": [_finding(status="FAIL", ftype="CORS wildcard origin * detected")]})
    assert results
    assert any("CORS" in pb["title"] for pb in results)

def test_known_pattern_nosql():
    results = generate_playbooks({"nosql": [_finding(status="FAIL", ftype="NoSQL injection — MongoDB error exposed")]})
    assert results
    assert any("NoSQL" in pb["title"] or "nosql" in pb["title"].lower() for pb in results)

def test_generic_playbook_for_unknown():
    results = generate_playbooks({"misc": [_finding(status="FAIL", ftype="Some unknown thing XYZ 12345")]})
    assert results  # Generic playbook fallback
    assert results[0]["steps"]

def test_deduplication():
    # Same pattern found in two modules → single playbook entry
    all_results = {
        "cors1": [_finding(status="FAIL", ftype="CORS wildcard origin *", url="https://x.com/a")],
        "cors2": [_finding(status="FAIL", ftype="CORS wildcard origin * on API", url="https://x.com/b")],
    }
    results = generate_playbooks(all_results)
    cors_playbooks = [pb for pb in results if "CORS" in pb["title"]]
    assert len(cors_playbooks) == 1  # deduplicated by title


# ── format_terminal ───────────────────────────────────────────────────────────

def test_terminal_no_findings():
    output = format_terminal([])
    assert "No remediation needed" in output

def test_terminal_shows_title():
    results = generate_playbooks({"xss": [_finding(status="FAIL", ftype="XSS reflected injection")]})
    output = format_terminal(results)
    assert "XSS" in output or "Remediate" in output

def test_terminal_contains_steps():
    results = generate_playbooks({"jwt": [_finding(status="FAIL", ftype="JWT algorithm none")]})
    output = format_terminal(results)
    assert "1." in output  # First step must appear


# ── format_markdown ───────────────────────────────────────────────────────────

def test_markdown_no_findings():
    output = format_markdown([], "https://x.com")
    assert "No findings" in output

def test_markdown_has_header():
    results = generate_playbooks({"xss": [_finding(status="FAIL", ftype="XSS reflected injection")]})
    output = format_markdown(results, "https://x.com")
    assert "# Tblue" in output

def test_markdown_has_table():
    results = generate_playbooks({"xss": [_finding(status="FAIL", ftype="XSS reflected injection")]})
    output = format_markdown(results, "https://x.com")
    assert "|" in output  # Table separator

def test_markdown_has_references():
    results = generate_playbooks({"jwt": [_finding(status="FAIL", ftype="JWT algorithm none")]})
    output = format_markdown(results, "https://x.com")
    assert "owasp.org" in output or "cwe.mitre.org" in output or "cheatsheetseries" in output
