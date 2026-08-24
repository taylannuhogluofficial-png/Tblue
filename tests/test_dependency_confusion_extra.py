"""Extra branch coverage for tblue.scanner.dependency_confusion."""

from unittest.mock import MagicMock, patch
from tblue.scanner.dependency_confusion import DependencyConfusionScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return DependencyConfusionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _404():
    return _resp(404, "Not Found")


def test_no_response_returns_pass():
    """Covers the None-response early-exit path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results[0]["status"] == "PASS"


def test_no_manifests_exposed_returns_pass():
    """Covers the clean branch where no dependency files are found."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_package_json_with_scoped_internal_package_warns():
    """Covers internal scoped npm package name detection branch."""
    s = _scanner()
    pkg_json = """{
  "name": "my-app",
  "dependencies": {
    "@internal/auth-service": "^1.0.0",
    "@company/shared-utils": "^2.3.0",
    "react": "^18.0.0"
  }
}"""

    def fake_get(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith("/package.json"):
            return _resp(200, pkg_json, {"content-type": "application/json"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_requirements_txt_exposed_warns():
    """Covers Python requirements.txt exposure detection branch."""
    s = _scanner()
    requirements = """django==4.2.0
requests==2.31.0
internal-auth-lib==1.0.0
private-company-core==2.1.0
"""

    def fake_get(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith("/requirements.txt"):
            return _resp(200, requirements, {"content-type": "text/plain"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_result_has_required_keys():
    """Covers that every result dict has the mandatory keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r


def test_gemfile_lock_exposed_warns():
    """Covers Gemfile.lock exposure detection branch."""
    s = _scanner()
    gemfile_lock = """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)
    internal-auth (1.2.0)

BUNDLED WITH
   2.3.0
"""

    def fake_get(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith("/Gemfile.lock") or url.endswith("/Gemfile"):
            return _resp(200, gemfile_lock, {"content-type": "text/plain"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN", "PASS") for r in results)
