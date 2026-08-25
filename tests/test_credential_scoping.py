"""Security invariants reported by a public code review.

Three separate problems, all verified and fixed:

1. Credentials supplied for the target (--bearer/--auth/--cookie/--header)
   were attached to a shared Session that default scanners also used to reach
   crt.sh, AlienVault OTX, OSV and NVD. Tokens went to third parties.
2. The five active_* scanners sat in the default module list AND the registry,
   so a plain `tblue -u` performed port scanning, DNS enumeration, CORS
   fuzzing and verb probing despite the "passive" claim.
3. AI analysis shipped findings to Anthropic whenever ANTHROPIC_API_KEY
   happened to be in the environment, with no explicit opt-in.
"""
import types
import unittest

import requests

from tblue import cli
from tblue.http import HTTPClient

_SECRETS = ("SECRET_COOKIE", "SECRET_APIKEY", "SECRET_BEARER", "SECRET_PASSWORD")


def _authed_session():
    return cli.build_session(types.SimpleNamespace(
        cookie="session=SECRET_COOKIE",
        extra_headers=["X-API-Key: SECRET_APIKEY"],
        bearer="SECRET_BEARER",
        auth_basic="admin:SECRET_PASSWORD",
        timeout=10, retries=1, verbose=False))


class TestCredentialScoping(unittest.TestCase):

    def setUp(self):
        self.client = HTTPClient(_authed_session(), allowed_host="example.com")

    def _headers_for(self, url):
        sess = (self.client.session if self.client._in_scope(url)
                else self.client._clean_session())
        prepared = sess.prepare_request(requests.Request("GET", url))
        return prepared.headers

    def _assert_no_secrets(self, url):
        blob = repr(self._headers_for(url))
        import base64
        blob += base64.b64decode(
            self._headers_for(url).get("Authorization", "Basic ").split()[-1] + "=="
        ).decode("utf-8", "replace") if "Basic" in blob else ""
        for secret in _SECRETS:
            self.assertNotIn(secret, blob, f"{secret} leaked to {url}")

    def test_target_still_receives_credentials(self):
        h = self._headers_for("https://example.com/admin")
        self.assertEqual(h.get("X-API-Key"), "SECRET_APIKEY")
        self.assertIn("Authorization", h)

    def test_subdomain_of_target_receives_credentials(self):
        self.assertIn("Authorization", self._headers_for("https://api.example.com/v1"))

    def test_third_party_services_get_nothing(self):
        for url in ("https://crt.sh/?q=example.com",
                    "https://otx.alienvault.com/api/v1/indicators/domain/x/url_list",
                    "https://api.osv.dev/v1/query",
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "https://www.virustotal.com/api/v3/domains/x"):
            with self.subTest(url=url):
                self._assert_no_secrets(url)

    def test_suffix_confusion_is_not_in_scope(self):
        """example.com.evil.tld must not be treated as the target."""
        self.assertFalse(self.client._in_scope("https://example.com.evil.tld/steal"))
        self._assert_no_secrets("https://example.com.evil.tld/steal")

    def test_no_allowed_host_keeps_previous_behaviour(self):
        c = HTTPClient(_authed_session(), allowed_host=None)
        self.assertTrue(c._in_scope("https://anything.example/"))


class TestPassiveByDefault(unittest.TestCase):

    def test_active_modules_are_declared(self):
        self.assertTrue(cli.ACTIVE_MODULES)

    def test_active_scanners_are_not_in_default_registry(self):
        keys = {e[0] for e in cli._SCANNER_REGISTRY}
        for mod in cli.ACTIVE_MODULES:
            self.assertNotIn(mod, keys, f"{mod} would run on a default scan")

    def test_active_scanners_are_not_in_all_modules(self):
        for mod in cli.ACTIVE_MODULES:
            self.assertNotIn(mod, cli.ALL_MODULES, f"{mod} is in the default selection")

    def test_no_default_scanner_port_scans(self):
        """`ports` and `redis_exposure` were passive in name only: one opens
        TCP connections to 25 service ports, the other speaks the Redis wire
        protocol. Only TLS/DNS lookups against the target may use sockets."""
        import re
        from pathlib import Path
        allowed = {"dns_caa", "ssl", "tls_certificate_deep",
                   "tls_deep", "tls_protocol_version"}
        offenders = []
        for key in {e[0] for e in cli._SCANNER_REGISTRY}:
            src = Path("tblue/scanner") / f"{key}.py"
            if not src.exists() or key in allowed:
                continue
            if re.search(r"socket\.(socket|create_connection)", src.read_text()):
                offenders.append(key)
        self.assertEqual(offenders, [],
                         f"default scanners opening raw sockets: {offenders}")

    def test_resolve_modules_never_returns_an_active_scanner(self):
        for sel in (cli.resolve_modules("", ""),
                    cli.resolve_modules("", "headers"),
                    cli.resolve_modules("active_port_probe", "")):
            self.assertFalse(set(sel) & cli.ACTIVE_MODULES)


if __name__ == "__main__":
    unittest.main()
