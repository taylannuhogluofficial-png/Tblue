"""Extra branch coverage for tblue.scanner.dev_artifact."""

from unittest.mock import MagicMock, patch
from tblue.scanner.dev_artifact import DevArtifactScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return DevArtifactScanner(session)


def test_none_initial_response_returns_pass():
    """Branch: initial get returns None — PASS and early return."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_all_probes_404_returns_pass():
    """Branch: all artifact probes return 404 — PASS (nothing exposed)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert all(r["status"] not in ("FAIL", "WARN") for r in results)


def test_ssh_private_key_exposed_fails():
    """Branch: probe returns SSH private key content — FAIL."""
    s = _scanner()
    ssh_body = "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64encodedstuff\n-----END OPENSSH PRIVATE KEY-----\n"
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html>homepage</html>")
        if "id_rsa" in url or "id_ed25519" in url or "ssh" in url.lower():
            return _resp(200, ssh_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_terraform_state_exposed_warns_or_fails():
    """Branch: terraform.tfstate with valid content — FAIL or WARN."""
    s = _scanner()
    tf_body = '{"version":4,"terraform_version":"1.5.0","serial":1,"resources":[]}'
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html>ok</html>")
        if "terraform.tfstate" in url or "tfstate" in url:
            return _resp(200, tf_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_empty_body_probe_is_skipped():
    """Branch: probe returns 200 but body < 5 chars — skip (not validated)."""
    s = _scanner()
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html>ok</html>")
        return _resp(200, "")  # too short

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    # No artifact findings since body too short
    assert any(r["status"] == "PASS" for r in results)


def test_npmrc_auth_token_exposed_fails():
    """Branch: .npmrc with _authToken — FAIL."""
    s = _scanner()
    npmrc_body = "//registry.npmjs.org/:_authToken=npm_abc123xyz456"
    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html>ok</html>")
        if ".npmrc" in url:
            return _resp(200, npmrc_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
