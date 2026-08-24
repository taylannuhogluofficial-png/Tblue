"""Shape Detection API security scanner — barcode scanning, face detection, biometric exfiltration."""
import re
from .base import BaseScanner

_SD_ANY_RE = re.compile(
    r'(?:BarcodeDetector\b|FaceDetector\b|TextDetector\b|new\s+BarcodeDetector|new\s+FaceDetector)',
    re.I
)

# Detected barcode/QR content transmitted to remote server
_SD_BARCODE_EXFIL_RE = re.compile(
    r'BarcodeDetector[^;]{0,400}(?:rawValue|format)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Face detection data transmitted — biometric data exfiltration
_SD_FACE_EXFIL_RE = re.compile(
    r'FaceDetector[^;]{0,400}(?:boundingBox|landmarks|score)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# OCR/text detected from camera stream and transmitted
_SD_TEXT_EXFIL_RE = re.compile(
    r'TextDetector[^;]{0,400}(?:rawValue|boundingBox)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S
)

# Detection run on user media stream (camera) — real-time surveillance
_SD_CAMERA_DETECT_RE = re.compile(
    r'(?:BarcodeDetector|FaceDetector|TextDetector)[^;]{0,400}(?:getUserMedia|MediaStream|videoTrack)',
    re.I | re.S
)

# Continuous detection loop — ongoing scanning without user awareness
_SD_CONTINUOUS_SCAN_RE = re.compile(
    r'(?:BarcodeDetector|FaceDetector|TextDetector)[^;]{0,400}(?:setInterval|requestAnimationFrame)',
    re.I | re.S
)


class ShapeDetectionSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "shape_detection_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SD_ANY_RE.search(body):
            return [self._result(url, "shape_detection_not_used", "INFO",
                                 detail="Shape Detection API not detected")]

        results = []

        if _SD_FACE_EXFIL_RE.search(body):
            results.append(self._result(url, "shape_detection_face_data_exfiltrated", "FAIL",
                                        detail="Face detection bounding boxes/landmarks transmitted to remote — biometric facial data exfiltrated"))

        if _SD_BARCODE_EXFIL_RE.search(body):
            results.append(self._result(url, "shape_detection_barcode_exfiltrated", "WARN",
                                        detail="Detected barcode/QR code rawValue transmitted to remote — scanned content (may be sensitive) sent to server"))

        if _SD_TEXT_EXFIL_RE.search(body):
            results.append(self._result(url, "shape_detection_text_exfiltrated", "WARN",
                                        detail="OCR-detected text content transmitted to remote — text from images or camera stream sent to server"))

        if _SD_CAMERA_DETECT_RE.search(body):
            results.append(self._result(url, "shape_detection_on_camera_stream", "WARN",
                                        detail="Shape/face detection running on live camera MediaStream — real-time video surveillance without clear user consent"))

        if _SD_CONTINUOUS_SCAN_RE.search(body):
            results.append(self._result(url, "shape_detection_continuous_scan", "WARN",
                                        detail="Detection runs in setInterval or requestAnimationFrame loop — continuous scanning without user-initiated trigger"))

        if not results:
            results.append(self._result(url, "shape_detection_found_no_issues", "PASS",
                                        detail="Shape Detection API usage appears safe"))

        return results
