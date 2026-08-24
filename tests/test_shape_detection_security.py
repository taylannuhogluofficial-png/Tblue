"""Tests for ShapeDetectionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.shape_detection_security import ShapeDetectionSecurityScanner


def _scanner():
    s = ShapeDetectionSecurityScanner.__new__(ShapeDetectionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestFaceExfil:
    def test_face_data_exfiltrated_fails(self):
        s = _scanner()
        # _SD_FACE_EXFIL_RE: FaceDetector ... boundingBox ... sendBeacon
        body = "const det = new FaceDetector()\ndet.detect(img).then(faces => { const bb = faces[0].boundingBox\nsendBeacon('/face', JSON.stringify(bb)) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shape_detection_face_data_exfiltrated" in types


class TestBarcodeExfil:
    def test_barcode_exfiltrated_warns(self):
        s = _scanner()
        # _SD_BARCODE_EXFIL_RE: BarcodeDetector ... rawValue ... fetch
        body = "const det = new BarcodeDetector()\ndet.detect(img).then(codes => { const val = codes[0].rawValue\nfetch('/scan', {body: val}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shape_detection_barcode_exfiltrated" in types


class TestContinuousScan:
    def test_continuous_scan_warns(self):
        s = _scanner()
        # _SD_CONTINUOUS_SCAN_RE: BarcodeDetector ... requestAnimationFrame
        body = "const det = new BarcodeDetector()\nfunction scan() { det.detect(video).then(c => console.log(c))\nrequestAnimationFrame(scan) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shape_detection_continuous_scan" in types


class TestNotUsed:
    def test_no_shape_detection_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "shape_detection_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
