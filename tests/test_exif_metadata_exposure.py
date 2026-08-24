"""Tests for EXIFMetadataExposureScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.exif_metadata_exposure import (
    EXIFMetadataExposureScanner, _has_exif_data,
    _JPEG_SOI, _APP1_MARKER, _EXIF_HEADER, _GPS_IFD_TAG,
)

URL = "https://example.com"


def _make_jpeg_with_exif(fields: bytes = b"") -> bytes:
    """Minimal JPEG with APP1 EXIF segment."""
    payload = _EXIF_HEADER + fields
    length = len(payload) + 2
    app1 = _APP1_MARKER + length.to_bytes(2, "big") + payload
    return _JPEG_SOI + app1 + b"\xff\xd9"


class TestEXIFMetadataExposure:
    def _scanner(self):
        return EXIFMetadataExposureScanner(MagicMock())

    def _resp(self, content=b"", status=200, ct="image/jpeg"):
        r = MagicMock()
        r.status_code = status
        r.text = content.decode("latin-1", errors="replace") if isinstance(content, bytes) else content
        r.content = content if isinstance(content, bytes) else content.encode("latin-1", errors="replace")
        r.headers = {"content-type": ct}
        return r

    def test_no_images_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(b"Not Found", status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_has_exif_data_detects_gps(self):
        jpeg = _make_jpeg_with_exif(_GPS_IFD_TAG + b"\x00" * 10)
        exif = _has_exif_data(jpeg)
        assert exif.get("gps")

    def test_has_exif_data_clean_jpeg(self):
        jpeg = _JPEG_SOI + b"\xff\xd9"
        exif = _has_exif_data(jpeg)
        assert exif == {}

    def test_non_jpeg_returns_empty(self):
        exif = _has_exif_data(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
        assert exif == {}

    def test_image_with_gps_exif_fails(self):
        jpeg = _make_jpeg_with_exif(_GPS_IFD_TAG + b"\x00" * 20)
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(jpeg)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("exif" in r["type"] for r in fails)

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(b"", status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
