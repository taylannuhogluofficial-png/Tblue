"""Tests for BeforeInstallPromptSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.before_install_prompt_security import BeforeInstallPromptSecurityScanner


def _scanner():
    s = BeforeInstallPromptSecurityScanner.__new__(BeforeInstallPromptSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoPrompt:
    def test_prompt_on_load_warns(self):
        s = _scanner()
        # _BIP_AUTO_PROMPT_RE: DOMContentLoaded ... .prompt()
        body = "window.addEventListener('DOMContentLoaded', () => deferredPrompt.prompt())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "install_prompt_shown_on_load" in types


class TestChoiceExfil:
    def test_choice_exfiltrated_warns(self):
        s = _scanner()
        # _BIP_CHOICE_EXFIL_RE: userChoice ... outcome ... analytics
        body = "deferredPrompt.userChoice.then(c => { const outcome = c.outcome\nanalytics('install', {outcome}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "install_choice_exfiltrated" in types


class TestDeceptiveContext:
    def test_deceptive_context_warns(self):
        s = _scanner()
        # _BIP_DECEPTIVE_CONTEXT_RE: deferredPrompt ... download
        body = "window.addEventListener('beforeinstallprompt', e => { deferredPrompt = e\nshowButton('Click to download security update') })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "install_prompt_deceptive_context" in types


class TestNotUsed:
    def test_no_install_prompt_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "before_install_prompt_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
