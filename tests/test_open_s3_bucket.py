"""Tests for Open S3 Bucket scanner."""
from unittest.mock import MagicMock, patch

URL = "https://myapp.example.com"


class TestOpenS3BucketScanner:
    def _scanner(self):
        from tblue.scanner.open_s3_bucket import OpenS3BucketScanner
        return OpenS3BucketScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_open_s3_bucket_fails(self):
        s = self._scanner()
        s3_body = (
            "<?xml version='1.0'?><ListBucketResult>"
            "<Name>myapp</Name><Contents><Key>secret.txt</Key></Contents>"
            "</ListBucketResult>"
        )

        def get_side(url, **kwargs):
            if "s3.amazonaws.com" in url:
                return self._resp(s3_body, 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("s3" in r["type"] for r in fails)

    def test_open_gcs_bucket_fails(self):
        s = self._scanner()
        gcs_body = (
            '<?xml version="1.0"?><ListBucketResult>'
            "<item><name>file.txt</name></item></ListBucketResult>"
        )

        def get_side(url, **kwargs):
            if "storage.googleapis.com" in url:
                return self._resp(gcs_body, 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("gcs" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_bucket_candidates(self):
        from tblue.scanner.open_s3_bucket import _bucket_candidates
        candidates = _bucket_candidates("myapp.example.com")
        assert "myapp" in candidates
        assert "myapp-assets" in candidates

    def test_bucket_candidates_subdomain(self):
        from tblue.scanner.open_s3_bucket import _bucket_candidates
        candidates = _bucket_candidates("api.company.io")
        assert "api" in candidates
