"""EXIF metadata exposure — images served with EXIF data containing GPS, author, software info."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_IMAGE_PATHS = [
    "/favicon.ico", "/logo.png", "/logo.jpg", "/logo.svg",
    "/images/logo.png", "/img/logo.png",
    "/static/img/logo.png", "/assets/logo.png",
    "/images/banner.jpg", "/img/hero.jpg",
    "/profile.jpg", "/avatar.jpg", "/uploads/image.jpg",
]

_JPEG_SOI = b"\xff\xd8"
_APP1_MARKER = b"\xff\xe1"
_EXIF_HEADER = b"Exif\x00\x00"

_GPS_IFD_TAG = b"\x88\x25"  # 0x8825 — GPS IFD pointer
_ARTIST_TAG = b"\x01\x3b"   # 0x013b — Artist
_MAKE_TAG = b"\x01\x0f"     # 0x010f — Make
_MODEL_TAG = b"\x01\x10"    # 0x0110 — Model
_SOFTWARE_TAG = b"\x01\x31" # 0x0131 — Software

_GPS_GPS_LATITUDE = b"\x00\x02"  # GPS Latitude tag

_CONTENT_TYPE_IMAGE_RE = re.compile(r'image/(?:jpeg|jpg|png|gif|webp|tiff)', re.I)


def _has_exif_data(content: bytes) -> dict:
    """Return dict of detected EXIF info or empty dict if none."""
    if not content or len(content) < 12:
        return {}
    if not content.startswith(_JPEG_SOI):
        return {}

    pos = 2
    while pos + 4 <= len(content):
        marker = content[pos:pos+2]
        if marker == _APP1_MARKER:
            length = int.from_bytes(content[pos+2:pos+4], "big")
            segment = content[pos+4:pos+4+length-2]
            if segment[:6] == _EXIF_HEADER:
                findings = {}
                segment_lower = segment.lower()
                if _GPS_IFD_TAG in segment or b"\x00\x02" in segment[6:]:
                    findings["gps"] = True
                if _SOFTWARE_TAG in segment:
                    findings["software"] = True
                if _MAKE_TAG in segment or _MODEL_TAG in segment:
                    findings["camera"] = True
                if _ARTIST_TAG in segment:
                    findings["artist"] = True
                return findings
            break
        if marker[0:1] != b"\xff":
            break
        if len(content) <= pos + 4:
            break
        length = int.from_bytes(content[pos+2:pos+4], "big")
        pos += 2 + length
    return {}


class EXIFMetadataExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        found_image = False
        for path in _IMAGE_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp is None or resp.status_code != 200:
                    continue
                ct = ""
                if hasattr(resp.headers, "get"):
                    ct = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
                elif isinstance(resp.headers, dict):
                    ct = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
                if not _CONTENT_TYPE_IMAGE_RE.search(ct or ""):
                    if not path.endswith((".jpg", ".jpeg", ".png")):
                        continue

                found_image = True
                content = getattr(resp, "content", None)
                if content is None:
                    content = (resp.text or "").encode("latin-1", errors="replace")

                exif = _has_exif_data(content)
                if exif:
                    fields = []
                    if exif.get("gps"):
                        fields.append("GPS coordinates")
                    if exif.get("camera"):
                        fields.append("camera make/model")
                    if exif.get("software"):
                        fields.append("software version")
                    if exif.get("artist"):
                        fields.append("artist/author")
                    detail = (f"EXIF metadata detected in {path}: {', '.join(fields)} — "
                              f"strip metadata before serving user images to prevent information leakage")
                    sev = "FAIL" if exif.get("gps") else "WARN"
                    results.append(self._result(origin + path, "exif_metadata_exposed", sev,
                                                detail=detail))
            except Exception:
                continue

        if not results:
            if found_image:
                results.append(self._result(url, "exif_metadata_clean", "PASS",
                                            detail="Images found but no EXIF metadata detected"))
            else:
                results.append(self._result(url, "exif_no_images_probed", "PASS",
                                            detail="No image endpoints found at common paths"))
        return results
