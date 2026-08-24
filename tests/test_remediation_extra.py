"""Extra branch coverage for tblue.remediation."""

from tblue.remediation import generate_playbooks, format_terminal, format_markdown


def _finding(status="FAIL", rtype="jwt — algorithm none", url="https://example.com", detail="bad jwt"):
    return {"status": status, "type": rtype, "url": url, "detail": detail}


def test_empty_results_returns_empty_playbooks():
    """No findings → no playbooks generated."""
    playbooks = generate_playbooks({})
    assert playbooks == []


def test_pass_only_findings_ignored():
    """PASS-only findings produce no playbooks."""
    all_results = {"module": [_finding(status="PASS", rtype="ssl / https")]}
    playbooks = generate_playbooks(all_results)
    assert playbooks == []


def test_fail_finding_generates_playbook():
    """A FAIL finding with a known pattern generates a matching playbook."""
    all_results = {"jwt_security": [_finding(status="FAIL", rtype="jwt — algorithm none")]}
    playbooks = generate_playbooks(all_results)
    assert len(playbooks) >= 1
    assert "steps" in playbooks[0]
    assert isinstance(playbooks[0]["steps"], list)


def test_warn_finding_generates_playbook():
    """A WARN finding also generates a playbook."""
    all_results = {"ssti": [_finding(status="WARN", rtype="ssti — template injection detected")]}
    playbooks = generate_playbooks(all_results)
    assert len(playbooks) >= 1


def test_unmatched_finding_uses_generic_playbook():
    """Finding type with no matching pattern uses the generic playbook."""
    # Use a type with no substring matching any playbook pattern
    all_results = {"custom": [_finding(status="FAIL", rtype="zz-nonexistent-finding-xyz-99999")]}
    playbooks = generate_playbooks(all_results)
    assert len(playbooks) == 1
    assert "Remediate:" in playbooks[0]["title"]


def test_duplicate_findings_deduplicated():
    """Two findings with same matched playbook title are deduplicated."""
    finding = _finding(status="FAIL", rtype="jwt — algorithm none")
    all_results = {"mod_a": [finding], "mod_b": [finding]}
    playbooks = generate_playbooks(all_results)
    # Should produce only one JWT playbook, not two
    jwt_pbs = [p for p in playbooks if "JWT" in p["title"]]
    assert len(jwt_pbs) == 1


def test_format_terminal_returns_string():
    """format_terminal produces non-empty string output."""
    all_results = {"jwt_security": [_finding(status="FAIL", rtype="jwt — algorithm none")]}
    playbooks = generate_playbooks(all_results)
    output = format_terminal(playbooks)
    assert isinstance(output, str)
    assert len(output) > 0


def test_format_markdown_returns_string():
    """format_markdown produces valid markdown output."""
    all_results = {"jwt_security": [_finding(status="FAIL", rtype="jwt — algorithm none")]}
    playbooks = generate_playbooks(all_results)
    output = format_markdown(playbooks, target="https://example.com")
    assert isinstance(output, str)
    assert "#" in output
