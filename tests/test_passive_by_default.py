"""A default scan must not send traffic the target did not invite.

Reproduces, in-process, the measurement that produced ACTIVE_MODULES. Every
scanner in the default registry is run against a local stub server and every
outbound request is recorded. A default run may issue GET/HEAD (and a CORS
preflight OPTIONS); anything that mutates state or carries an attack payload
belongs behind --active.

Before this was enforced, a plain `tblue -u` sent 198 POSTs and 104 payload
requests per scan, including login attempts, password-reset submissions,
account-registration attempts, XXE and traversal strings.
"""
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from tblue import cli
from tblue.http import HTTPClient

_PAGE = (b"<html><body><form action='/login' method='POST'>"
         b"<input name='email'><input name='password' type='password'></form>"
         b"<a href='/about'>a</a><script src='/app.js'></script></body></html>")

# Some scanners only send their payload once they believe the service exists —
# the GraphQL modules, for instance, POST introspection only after a probe
# looks GraphQL-shaped. A stub that returns HTML for everything would let those
# pass while still being non-passive in the field, so the stub answers
# API-shaped paths with a plausible GraphQL/JSON body instead.
_JSON = (b'{"data":{"__schema":{"queryType":{"name":"Query"},'
         b'"types":[{"name":"User","kind":"OBJECT"}]}},"errors":[]}')
_API_HINT = ("graphql", "gql", "/api", "/query", "/v1", "/v2", "playground", "graphiql")

_PAYLOAD = re.compile(
    r"\.\./|%2e%2e|etc/passwd|<!ENTITY|<script|onerror=|javascript:"
    r"|UNION\s+SELECT|\$\{jndi:|%0d%0a|\{\{7\*7\}\}|'\s*OR\s*'?1", re.I)

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


class _Stub(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        api = any(h in self.path.lower() for h in _API_HINT)
        body = _JSON if api else _PAGE
        self.send_response(200)
        self.send_header("Content-Type",
                         "application/json" if api else "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _reply
    def log_message(self, *a):
        pass


class TestPassiveByDefault(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_no_default_scanner_sends_uninvited_traffic(self):
        target = f"http://127.0.0.1:{self.port}"
        sent = []
        original = HTTPClient._request

        def spy(inner_self, method, url, **kw):
            body = kw.get("data") or kw.get("json") or ""
            sent.append((method.upper(), url, str(body)[:300]))
            return original(inner_self, method, url, **kw)

        HTTPClient._request = spy
        try:
            offenders = {}
            for key, klass, _msg in cli._SCANNER_REGISTRY:
                sent.clear()
                session = requests.Session()
                try:
                    klass(session, timeout=2, retries=1,
                          allowed_host="127.0.0.1").scan(target)
                except Exception:
                    pass
                bad = [r for r in sent
                       if r[0] in _MUTATING or _PAYLOAD.search(r[1] + " " + r[2])]
                if bad:
                    offenders[key] = bad[0]
        finally:
            HTTPClient._request = original

        self.assertEqual(
            offenders, {},
            "default scanners sending uninvited traffic (move to "
            f"cli.ACTIVE_MODULES): {sorted(offenders)}")

    def test_active_modules_are_held_out_of_the_default_run(self):
        keys = {e[0] for e in cli._SCANNER_REGISTRY}
        for mod in cli.ACTIVE_MODULES:
            self.assertNotIn(mod, keys)
            self.assertNotIn(mod, cli.ALL_MODULES)

    def test_active_registry_is_reachable(self):
        """Held out of the default run, but still runnable via --active."""
        self.assertTrue(cli._ACTIVE_REGISTRY)
        active_keys = {e[0] for e in cli._ACTIVE_REGISTRY}
        self.assertTrue(active_keys <= cli.ACTIVE_MODULES)


if __name__ == "__main__":
    unittest.main()
