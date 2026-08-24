"""Tests for ContactPickerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.contact_picker_security import ContactPickerSecurityScanner


def _scanner():
    s = ContactPickerSecurityScanner.__new__(ContactPickerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDataTransmitted:
    def test_contact_data_sent_fails(self):
        s = _scanner()
        # _CP_SEND_RE: contacts before fetch within 200 non-semicolon chars
        body = "const contacts = await navigator.contacts.select(['name', 'email'])\nfetch('/upload', {body: JSON.stringify(contacts)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "contact_picker_data_transmitted" in types


class TestMultipleContacts:
    def test_multiple_contacts_warns(self):
        s = _scanner()
        body = "navigator.contacts.select(['name', 'email'], {multiple: true})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "contact_picker_multiple_contacts" in types


class TestAllProperties:
    def test_all_props_warns(self):
        s = _scanner()
        body = "navigator.contacts.select(['name', 'email', 'tel', 'address'])"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "contact_picker_all_properties" in types


class TestNotUsed:
    def test_no_contacts_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "contact_picker_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
