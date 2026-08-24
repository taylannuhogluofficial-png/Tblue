"""Tests for public cloud storage bucket detector."""

from unittest.mock import MagicMock
from tblue.scanner.cloud_storage import CloudStorageScanner, _name_variants


def _scanner(url_responses: dict = None):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        if url_responses:
            for pattern, (code, body) in url_responses.items():
                if pattern in url:
                    resp.status_code = code
                    resp.text = body
                    break
        return resp

    session.request.side_effect = fake_request
    return CloudStorageScanner(session)


# ── Name variant generation ───────────────────────────────────────────────────

def test_name_variants_not_empty():
    variants = _name_variants("example.com")
    assert len(variants) > 5


def test_name_variants_includes_base():
    variants = _name_variants("example.com")
    assert "example" in variants


def test_name_variants_includes_assets():
    variants = _name_variants("example.com")
    assert any("assets" in v for v in variants)


def test_name_variants_includes_backup():
    variants = _name_variants("example.com")
    assert any("backup" in v for v in variants)


# ── S3 detection ──────────────────────────────────────────────────────────────

def test_public_s3_bucket_fails():
    body = '<?xml version="1.0"?><ListBucketResult><Name>example</Name></ListBucketResult>'
    scanner = _scanner({".s3.amazonaws.com": (200, body)})
    results = scanner.scan("https://example.com")
    assert any("s3" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_private_s3_bucket_not_flagged():
    scanner = _scanner({".s3.amazonaws.com": (403, "AccessDenied")})
    results = scanner.scan("https://example.com")
    assert not any("s3" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_nonexistent_s3_bucket_not_flagged():
    scanner = _scanner()
    results = scanner.scan("https://example.com")
    assert not any("s3" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Azure Blob detection ───────────────────────────────────────────────────────

def test_public_azure_blob_fails():
    body = '<?xml version="1.0"?><EnumerationResults><Blobs/></EnumerationResults>'
    scanner = _scanner({".blob.core.windows.net": (200, body)})
    results = scanner.scan("https://example.com")
    assert any("azure" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_private_azure_blob_not_flagged():
    scanner = _scanner({".blob.core.windows.net": (403, "ResourceNotFound")})
    results = scanner.scan("https://example.com")
    assert not any("azure" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── GCS detection ─────────────────────────────────────────────────────────────

def test_public_gcs_bucket_fails():
    body = '{"kind": "storage#objects", "items": []}'
    scanner = _scanner({"storage.googleapis.com": (200, body)})
    results = scanner.scan("https://example.com")
    assert any("gcs" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_private_gcs_bucket_not_flagged():
    scanner = _scanner({"storage.googleapis.com": (403, '{"error": "forbidden"}')})
    results = scanner.scan("https://example.com")
    assert not any("gcs" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Clean scan ────────────────────────────────────────────────────────────────

def test_no_public_buckets_passes():
    scanner = _scanner()
    results = scanner.scan("https://example.com")
    assert any("no public buckets" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_network_error_skipped_gracefully():
    session = MagicMock()
    session.request.side_effect = Exception("Connection refused")
    scanner = CloudStorageScanner(session)
    results = scanner.scan("https://example.com")
    # Should still return a PASS (no buckets found)
    assert any(r["status"] == "PASS" for r in results)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_empty_domain_returns_early():
    """URL with no hostname → not domain → return self.results at line 71."""
    scanner = CloudStorageScanner(MagicMock())
    results = scanner.scan("https:///no-host")
    assert results == []


def test_probe_s3_get_raises_returns_none():
    """http.get raises in _probe_s3 → except Exception: pass at lines 122-123."""
    from unittest.mock import patch
    scanner = CloudStorageScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        result = scanner._probe_s3("https://example.s3.amazonaws.com/", "example")
    assert result is None


def test_probe_azure_get_raises_returns_none():
    """http.get raises in _probe_azure → except Exception: pass at lines 141-142."""
    from unittest.mock import patch
    scanner = CloudStorageScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        result = scanner._probe_azure("https://example.blob.core.windows.net/", "example")
    assert result is None


def test_probe_gcs_get_raises_returns_none():
    """http.get raises in _probe_gcs → except Exception: pass at lines 159-160."""
    from unittest.mock import patch
    scanner = CloudStorageScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        result = scanner._probe_gcs("https://storage.googleapis.com/example/", "example")
    assert result is None
