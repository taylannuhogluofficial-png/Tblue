"""Extra branch coverage for tblue.scanner.security_txt."""

from unittest.mock import MagicMock
from tblue.scanner.security_txt import SecurityTxtScanner

URL = "https://example.com"


def _scanner(well_known_status=404, security_txt_status=404, body=""):
    session = MagicMock()
    s = SecurityTxtScanner(session)

    def fake_get(url, **kw):
        resp = MagicMock()
        if "/.well-known/security.txt" in url:
            resp.status_code = well_known_status
            resp.text = body
            resp.headers = {"content-type": "text/plain"}
        else:
            resp.status_code = security_txt_status
            resp.text = body
            resp.headers = {"content-type": "text/plain"}
        return resp

    s.http.get = MagicMock(side_effect=fake_get)
    return s


_VALID_BODY = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\n"
_FULL_BODY = _VALID_BODY + "Policy: https://example.com/security-policy\nEncryption: https://example.com/pgp.asc\nAcknowledgments: https://example.com/thanks\n"


def test_missing_security_txt_warns():
    """Both paths returning 404 → WARN about missing security.txt."""
    results = _scanner().scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "missing" in r["type"].lower()]
    assert warns


def test_well_known_path_found_passes():
    """Valid security.txt at /.well-known/security.txt → PASS."""
    results = _scanner(well_known_status=200, body=_VALID_BODY).scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_fallback_security_txt_path_used():
    """When well-known returns 404 but /security.txt exists → PASS."""
    results = _scanner(well_known_status=404, security_txt_status=200, body=_VALID_BODY).scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_missing_contact_field_warns():
    """security.txt without Contact field → WARN about incomplete."""
    body = "Expires: 2027-01-01T00:00:00.000Z\n"
    results = _scanner(well_known_status=200, body=body).scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_full_security_txt_all_fields_passes():
    """security.txt with all required and recommended fields → PASS."""
    results = _scanner(well_known_status=200, body=_FULL_BODY).scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
