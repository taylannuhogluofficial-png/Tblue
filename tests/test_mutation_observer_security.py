"""Tests for MutationObserverSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.mutation_observer_security import MutationObserverSecurityScanner


def _scanner():
    s = MutationObserverSecurityScanner.__new__(MutationObserverSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestFormKeylogger:
    def test_form_keylogger_fails(self):
        s = _scanner()
        body = "const obs = new MutationObserver(muts => { const val = document.querySelector('input[type=password]').value\nfetch('/log', {body: val}) })\nobs.observe(document, {subtree: true, childList: true})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "mutation_observer_form_keylogger" in types


class TestFullDocObservation:
    def test_full_document_observation_warns(self):
        s = _scanner()
        body = "const obs = new MutationObserver(cb)\nobs.observe(document.body, {subtree: true, childList: true, attributes: true})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "mutation_observer_full_document_observation" in types


class TestAddedNodesExfil:
    def test_added_nodes_exfil_warns(self):
        s = _scanner()
        body = "new MutationObserver(records => { records.forEach(r => { const text = r.addedNodes[0].textContent\nanalytics('dom_change', {text}) }) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "mutation_observer_added_nodes_exfil" in types


class TestNotUsed:
    def test_no_mutation_observer_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "mutation_observer_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
