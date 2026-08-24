"""Tests for Credential Exposure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCredentialExposureScanner:
    def _scanner(self):
        from tblue.scanner.credential_exposure import CredentialExposureScanner
        return CredentialExposureScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_all_404_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_env_file_exposed_fails(self):
        s = self._scanner()
        env_body = "DB_PASSWORD=supersecret\nAPI_KEY=abc123\n"

        def get_side(url, **kwargs):
            if "/.env" in url and "local" not in url and "prod" not in url and "dev" not in url and "bak" not in url:
                return self._resp(env_body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("env" in r["type"] for r in fails)

    def test_git_config_exposed_fails(self):
        s = self._scanner()
        git_config = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/user/repo\n"

        def get_side(url, **kwargs):
            if "/.git/config" in url:
                return self._resp(git_config, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("git" in r["type"] for r in fails)

    def test_phpinfo_exposed_fails(self):
        s = self._scanner()
        phpinfo_body = "phpinfo() PHP Version 8.1.0 loaded extensions"

        def get_side(url, **kwargs):
            if "phpinfo.php" in url:
                return self._resp(phpinfo_body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("phpinfo" in r["type"] for r in fails)

    def test_404_on_sensitive_path_skipped(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert not any(r["status"] == "FAIL" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_env_file_found(self):
        from tblue.scanner.credential_exposure import _check_sensitive_path
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "DB_PASSWORD=secret\nAPI_KEY=abc\n"
        http.get.return_value = r
        result = _check_sensitive_path(http, "https://example.com", "/.env", "FAIL", "env-file")
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_env_file_404(self):
        from tblue.scanner.credential_exposure import _check_sensitive_path
        http = MagicMock()
        r = MagicMock()
        r.status_code = 404
        r.text = ""
        http.get.return_value = r
        result = _check_sensitive_path(http, "https://example.com", "/.env", "FAIL", "env-file")
        assert result is None

    def test_check_git_config_content_mismatch(self):
        from tblue.scanner.credential_exposure import _check_sensitive_path
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "<html>Not found</html>"
        http.get.return_value = r
        result = _check_sensitive_path(http, "https://example.com", "/.git/config", "FAIL", "git-config")
        assert result is None
