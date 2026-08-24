"""Extra coverage for deserialization — lines 95-96 (_is_java_serialized_b64 except), 114-116 (Java body FAIL)."""

import base64
from unittest.mock import MagicMock, patch
from tblue.scanner.deserialization import DeserializationScanner, _is_java_serialized_b64

URL = "https://example.com"


def _make_scanner():
    return DeserializationScanner(MagicMock())


def _resp(status=200, body="", content_type="text/html", cookies=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": content_type}
    r.cookies = cookies or {}
    r.__bool__ = lambda self: self.status_code < 400
    return r


# ── _is_java_serialized_b64 ───────────────────────────────────────────────────

def test_is_java_serialized_b64_exception_returns_false():
    """Exception in base64 decode returns False (lines 95-96 — except path)."""
    # Passing garbage that causes b64decode to raise or return wrong bytes
    result = _is_java_serialized_b64("!!not-base64-!!")
    assert result is False


def test_is_java_serialized_b64_valid_java_magic():
    """Valid Java serialized magic bytes (0xACED0005) returns True."""
    java_magic = b"\xac\xed\x00\x05" + b"\x00" * 10
    encoded = base64.b64encode(java_magic).decode()
    result = _is_java_serialized_b64(encoded)
    assert result is True


def test_is_java_serialized_b64_non_java_bytes():
    """Valid base64 but not Java magic — returns False."""
    result = _is_java_serialized_b64(base64.b64encode(b"ABCDEFGH").decode())
    assert result is False


# ── Java serialized in response body (lines 114-116) ─────────────────────────

def test_java_serialized_magic_hex_in_response_body():
    """Java serialized hex magic in response body triggers FAIL (lines 114-116)."""
    s = _make_scanner()
    # Body with Java serialized hex marker "aced0005" — must use application/octet-stream
    # so both _JAVA_CONTENT_TYPE_RE matches AND "octet-stream" in content_type is True
    java_body = "aced0005sr\x00\x13com.example.UserSession\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01"

    with patch.object(s.http, "get", return_value=_resp(
        body=java_body,
        content_type="application/octet-stream",
    )):
        results = s.scan(URL)

    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails, f"Expected FAIL for Java serialized body, got: {results}"
    assert any("java" in r["type"].lower() or "deserializ" in r["type"].lower()
               for r in fails), f"FAIL type should mention Java/deserialization: {fails}"


def test_java_serialized_b64_in_response_body():
    """Base64-encoded Java magic bytes in response body triggers FAIL."""
    s = _make_scanner()
    java_magic = b"\xac\xed\x00\x05" + b"\x73\x72" + b"com.example.Session" + b"\x00" * 20
    b64_body = base64.b64encode(java_magic).decode()

    with patch.object(s.http, "get", return_value=_resp(
        body=b64_body,
        content_type="application/octet-stream",
    )):
        results = s.scan(URL)

    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails, f"Expected FAIL for b64-encoded Java magic bytes, got: {results}"
