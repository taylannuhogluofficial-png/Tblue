"""Tests for tblue.scanner.http_verb_tampering."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.http_verb_tampering import HTTPVerbTamperingScanner


def _scanner():
    session = MagicMock()
    return HTTPVerbTamperingScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── TRACE in Allow header → FAIL ─────────────────────────────────────────────

def test_trace_in_allow_header_fails():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options",
                      return_value=_resp(200, "", {"Allow": "GET, POST, HEAD, TRACE"})), \
         patch.object(s.http, "post", return_value=_resp(405, "")):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("trace" in r["type"].lower() for r in fails)


# ── DEBUG in Allow header → FAIL ─────────────────────────────────────────────

def test_debug_in_allow_header_fails():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options",
                      return_value=_resp(200, "", {"Allow": "GET, POST, DEBUG"})), \
         patch.object(s.http, "post", return_value=_resp(405, "")):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("debug" in r["type"].lower() for r in fails)


# ── X-HTTP-Method-Override: DELETE accepted → WARN ───────────────────────────

def test_method_override_header_warns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", return_value=_resp(200, "")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("override" in r["type"].lower() or "x-http" in r["type"].lower()
               for r in warns)


# ── _method=DELETE POST param accepted → WARN ────────────────────────────────

def test_method_override_param_warns():
    s = _scanner()

    def post_side_effect(url, data=None, headers=None, **kwargs):
        # Only _method=DELETE triggers 200
        if data and data.get("_method") == "DELETE":
            return _resp(200, "Deleted")
        # X-HTTP-Method-Override override requests → 405
        if headers and any("Method-Override" in h for h in headers):
            return _resp(405, "")
        return _resp(405, "")

    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("_method" in r["type"].lower() or "override" in r["type"].lower()
               for r in warns)


# ── Clean server → PASS ───────────────────────────────────────────────────────

def test_clean_server_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", return_value=_resp(405, "Method Not Allowed")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── OPTIONS returns None → graceful ──────────────────────────────────────────

def test_options_none_graceful():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=None), \
         patch.object(s.http, "post", return_value=_resp(405, "")):
        results = s.scan("https://example.com")
    assert isinstance(results, list)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_method_override_header_post_returns_none():
    """http.post() returns None in _check_method_override_headers → continue line 116."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan("https://example.com")
    # All POST attempts returned None → no override WARN, likely PASS
    assert isinstance(results, list)
    assert not any("override" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_method_override_param_post_returns_none():
    """http.post() returns None in _check_method_override_params → continue line 140."""
    s = _scanner()

    def post_side_effect(url, data=None, headers=None, **kwargs):
        # Override-header calls → 405 (no WARN for that check)
        # Override-param calls (data is set) → None
        if data is not None:
            return None
        return _resp(405, "")

    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    assert not any("_method" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_arbitrary_method_accepted_warns():
    """_check_arbitrary_method: session.request() returns 200 → WARN lines 166-181."""
    s = _scanner()
    mock_session = MagicMock()
    mock_req_resp = MagicMock()
    mock_req_resp.status_code = 200
    mock_session.request.return_value = mock_req_resp
    s.http._session = mock_session  # inject _session so the dead-code path becomes live

    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", return_value=_resp(405, "")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("arbitrary" in r["type"].lower() or "method" in r["type"].lower() for r in warns)


def test_arbitrary_method_exception_continues():
    """session.request() raises → except → continue line 182."""
    s = _scanner()
    mock_session = MagicMock()
    mock_session.request.side_effect = Exception("connection error")
    s.http._session = mock_session

    with patch.object(s.http, "get", return_value=_resp(200, "")), \
         patch.object(s.http, "options", return_value=_resp(200, "", {"Allow": "GET, POST"})), \
         patch.object(s.http, "post", return_value=_resp(405, "")):
        results = s.scan("https://example.com")
    assert isinstance(results, list)
