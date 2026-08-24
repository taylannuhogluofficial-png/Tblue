"""Tests for SBOM passive scanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.sbom_scanner import SBOMScanner


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    return r


class TestSBOMScanner(unittest.TestCase):

    def _scanner(self):
        s = SBOMScanner.__new__(SBOMScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def _not_found(self):
        return _resp("", 404)

    def test_no_manifests_returns_pass(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("sbom_no_manifest_exposed", types)
        self.assertEqual(results[0]["severity"], "PASS")

    def test_package_json_exposed(self):
        s = self._scanner()
        pkg_json = '{"dependencies": {"lodash": "^4.17.20", "axios": "^1.4.0"}}'

        def get_side(url, **kw):
            if url.endswith("/package.json"):
                return _resp(pkg_json, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("sbom_manifest_exposed", types)
        self.assertIn("sbom_inventory_summary", types)

    def test_requirements_txt_exposed(self):
        s = self._scanner()
        req = "Django==4.2.1\nrequests==2.31.0\nnumpy==1.24.0\n"

        def get_side(url, **kw):
            if url.endswith("/requirements.txt"):
                return _resp(req, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("sbom_manifest_exposed", types)

    def test_go_mod_exposed(self):
        s = self._scanner()
        go_mod = "module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"

        def get_side(url, **kw):
            if url.endswith("/go.mod"):
                return _resp(go_mod, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("sbom_manifest_exposed", types)

    def test_no_response_skips(self):
        s = self._scanner()
        s.http.get.return_value = None
        results = s.scan("https://example.com")
        # None response counts as not found (status not in 200/206)
        # All probes return None → no_manifest_exposed
        types = [r["type"] for r in results]
        self.assertIn("sbom_no_manifest_exposed", types)

    def test_pom_xml_exposed(self):
        s = self._scanner()
        pom = ("<dependencies><dependency>"
               "<groupId>org.springframework</groupId>"
               "<artifactId>spring-core</artifactId>"
               "<version>5.3.27</version>"
               "</dependency></dependencies>")

        def get_side(url, **kw):
            if url.endswith("/pom.xml"):
                return _resp(pom, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("sbom_manifest_exposed", types)


if __name__ == "__main__":
    unittest.main()
