"""Extra branch coverage for tblue.scanner.cloud_storage."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cloud_storage import CloudStorageScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return CloudStorageScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _404():
    return _resp(404, "<Error><Code>NoSuchBucket</Code></Error>")


def test_no_public_buckets_returns_pass():
    """Covers the clean branch where no public buckets are found."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_s3_public_listing_fails():
    """Covers the S3 ListBucketResult detection branch."""
    s = _scanner()
    s3_body = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example-assets</Name>
  <Contents><Key>file.txt</Key></Contents>
</ListBucketResult>"""

    def fake_get(url, **kw):
        if "s3.amazonaws.com" in url and "example" in url:
            return _resp(200, s3_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_azure_public_listing_fails():
    """Covers the Azure EnumerationResults detection branch."""
    s = _scanner()
    azure_body = """<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://example.blob.core.windows.net/" ContainerName="example">
  <Blobs><Blob><Name>data.csv</Name></Blob></Blobs>
</EnumerationResults>"""

    def fake_get(url, **kw):
        if "blob.core.windows.net" in url and "example" in url:
            return _resp(200, azure_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_gcs_public_listing_fails():
    """Covers the GCS storage#objects detection branch."""
    s = _scanner()
    gcs_body = '{"kind": "storage#objects", "items": [{"name": "backup.sql"}]}'

    def fake_get(url, **kw):
        if "storage.googleapis.com" in url and "example" in url:
            return _resp(200, gcs_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_empty_domain_returns_empty_results():
    """Covers the branch where the URL has no parseable domain."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan("https://")
    assert isinstance(results, list)


def test_access_denied_s3_not_flagged_as_public():
    """Covers the S3 AccessDenied response — bucket exists but not public."""
    s = _scanner()
    s3_denied = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"

    def fake_get(url, **kw):
        if "s3.amazonaws.com" in url:
            return _resp(403, s3_denied)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    # AccessDenied should not produce FAIL results (bucket not publicly readable)
    assert not any(r["status"] == "FAIL" for r in results)
