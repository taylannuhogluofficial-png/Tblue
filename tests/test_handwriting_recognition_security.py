"""Tests for HandwritingRecognitionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.handwriting_recognition_security import HandwritingRecognitionSecurityScanner


def _scanner():
    s = HandwritingRecognitionSecurityScanner.__new__(HandwritingRecognitionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_handwriting_recognition_data_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const recognizer = await navigator.createHandwritingRecognizer({languages: ['en']})\n"
        "const drawing = recognizer.startDrawing()\n"
        "sendBeacon('/ink', JSON.stringify({strokes: drawing.getStrokes()}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "handwriting_recognition_data_exfil" in types


def test_handwriting_recognition_param_controlled():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.createHandwritingRecognizer({languages: [searchParams.get('lang')]})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "handwriting_recognition_param_controlled" in types


def test_handwriting_recognition_language_fingerprint():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const recognizer = await navigator.createHandwritingRecognizer({languages: ['en']})\n"
        "const hints = recognizer.hints\n"
        "fetch('/analytics', {body: JSON.stringify({recognitionType: hints})})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "handwriting_recognition_language_fingerprint" in types


def test_handwriting_recognition_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No ink or stylus input API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "handwriting_recognition_not_used"
    assert results[0]["status"] == "PASS"


def test_handwriting_recognition_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "handwriting_recognition_not_used"
