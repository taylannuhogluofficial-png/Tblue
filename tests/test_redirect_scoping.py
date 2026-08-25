"""Credentials must not survive a redirect that leaves the scan target.

HTTPClient._request picks a clean session for requests it issues itself at an
off-target host. That does not cover redirects: requests follows those inside a
single send(), on whichever session started the call. A target answering 302
with an off-host Location would otherwise hand that host the --header values
and the cookie jar.
"""

import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tblue.cli import build_session
from tblue.http import HTTPClient

_SECRETS = ("COOKIE_SECRET", "HEADER_SECRET", "BEARER_SECRET")


def _args():
    return types.SimpleNamespace(
        cookie="sessionid=COOKIE_SECRET",
        extra_headers=["X-API-Key: HEADER_SECRET"],
        bearer="BEARER_SECRET",
        auth_basic=None,
    )


class _Sink(BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        type(self).received.append(dict(self.headers))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class TestRedirectScoping(unittest.TestCase):

    def setUp(self):
        _Sink.received = []
        self.sink, self.sink_port = _serve(_Sink)
        sink_port = self.sink_port

        class _Redirector(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location",
                                 f"http://127.0.0.1:{sink_port}/landed")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.redir, self.redir_port = _serve(_Redirector)

    def tearDown(self):
        for s in (self.sink, self.redir):
            s.shutdown()
            s.server_close()

    def _leaked(self):
        out = []
        for headers in _Sink.received:
            for k, v in headers.items():
                if any(secret in str(v) for secret in _SECRETS):
                    out.append(f"{k}: {v}")
        return out

    def test_credentials_stripped_when_redirect_leaves_target(self):
        # Target is "localhost"; the 302 sends us to "127.0.0.1" — a different
        # hostname, so out of scope even though it is the same machine.
        client = HTTPClient(build_session(_args()), timeout=3, retries=1,
                            allowed_host="localhost")
        client.get(f"http://localhost:{self.redir_port}/")

        self.assertTrue(_Sink.received, "redirect was never followed")
        self.assertEqual(self._leaked(), [],
                         "credentials followed a redirect off the target host")

    def test_credentials_survive_an_in_scope_redirect(self):
        # Same host (127.0.0.1), different port — still the target, so the
        # stripping must not fire.
        client = HTTPClient(build_session(_args()), timeout=3, retries=1,
                            allowed_host="127.0.0.1")
        client.get(f"http://127.0.0.1:{self.redir_port}/")

        self.assertTrue(_Sink.received, "redirect was never followed")
        leaked = " ".join(self._leaked())
        self.assertIn("HEADER_SECRET", leaked)
        self.assertIn("COOKIE_SECRET", leaked)
        # Authorization is absent here, and that is requests' doing, not ours:
        # its own rebuild_auth drops the header whenever the netloc changes,
        # and the netloc includes the port. Asserted so the distinction between
        # upstream behaviour and ScopedSession's is not lost later.
        self.assertNotIn("BEARER_SECRET", leaked)

    def test_no_allowed_host_disables_stripping(self):
        # Library use with no declared target keeps prior behaviour.
        client = HTTPClient(build_session(_args()), timeout=3, retries=1)
        client.get(f"http://localhost:{self.redir_port}/")

        self.assertTrue(_Sink.received, "redirect was never followed")
        self.assertIn("HEADER_SECRET", " ".join(self._leaked()))


if __name__ == "__main__":
    unittest.main()
