"""Active HTTP Verb Probe — send non-standard HTTP methods and detect dangerous capabilities."""
import re
from .base import BaseScanner

active = True

_AHVP_ANY_RE = re.compile(r'^https?://', re.I)

_VERBS = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND", "MOVE"]


class ActiveHTTPVerbProbeScanner(BaseScanner):
    def scan(self, url: str) -> list:
        if not _AHVP_ANY_RE.match(url):
            return [self._result(url, "active_http_verb_not_used", "PASS")]

        findings = []
        allowed_methods = set()

        # Start with OPTIONS to get declared Allow header
        try:
            resp = self.http.get(url, method="OPTIONS")
            if resp is not None:
                allow_hdr = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
                if allow_hdr:
                    allowed_methods = {m.strip().upper() for m in allow_hdr.split(",")}

                    if "TRACE" in allowed_methods:
                        findings.append(self._result(
                            url, "active_http_verb_trace_in_allow", "WARN",
                            detail="Allow header declares TRACE — Cross-Site Tracing (XST) attack vector; TRACE echoes request headers including HttpOnly cookies to JavaScript; disable TRACE in web server config (TraceEnable off in Apache, deny TRACE in nginx).",
                        ))

                    dangerous = {"PUT", "DELETE", "MOVE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "LOCK", "UNLOCK"}
                    exposed = dangerous & allowed_methods
                    if exposed:
                        findings.append(self._result(
                            url, "active_http_verb_dangerous_methods_declared", "WARN",
                            detail=f"Allow header declares dangerous HTTP methods: {', '.join(sorted(exposed))} — PUT enables arbitrary file upload; DELETE enables file deletion; WebDAV methods (PROPFIND, MOVE, COPY) enable filesystem manipulation; restrict to GET, HEAD, POST, OPTIONS via LimitExcept in Apache or limit_except in nginx.",
                        ))
        except Exception:
            pass

        # Actually send TRACE and check if server echoes the request
        try:
            resp = self.http.get(url, method="TRACE")
            if resp is not None and resp.status_code in (200, 204):
                body = resp.text or ""
                if "TRACE" in body.upper() or "X-Tblue-Trace-Probe" in body:
                    findings.append(self._result(
                        url, "active_http_verb_trace_accepted", "FAIL",
                        detail="TRACE method accepted and server echoes request — Cross-Site Tracing (XST) enables JavaScript to read HttpOnly cookies and Authorization headers via XMLHttpRequest TRACE; disable TRACE on the web server.",
                    ))
                elif resp.status_code == 200:
                    findings.append(self._result(
                        url, "active_http_verb_trace_200_ok", "WARN",
                        detail="TRACE method returns HTTP 200 — server does not reject the TRACE verb; even without content echo, TRACE should return 405 Method Not Allowed on production servers.",
                    ))
        except Exception:
            pass

        # Send PUT to detect file upload capability
        try:
            test_path = url.rstrip("/") + "/active-probe-test-delete.txt"
            resp = self.http.get(test_path, method="PUT",
                                  data=b"tblue-active-probe",
                                  headers={"Content-Type": "text/plain"})
            if resp is not None and resp.status_code in (200, 201, 204):
                findings.append(self._result(
                    url, "active_http_verb_put_accepted", "FAIL",
                    detail=f"HTTP PUT accepted (status {resp.status_code}) — server allows arbitrary file upload via PUT; attacker can overwrite web content, upload web shells, or plant malicious files; restrict write methods at the server level.",
                ))
                # Attempt cleanup
                try:
                    self.http.get(test_path, method="DELETE")
                except Exception:
                    pass
        except Exception:
            pass

        # Send DELETE to detect destructive method acceptance
        try:
            resp = self.http.get(url, method="DELETE")
            if resp is not None and resp.status_code in (200, 202, 204):
                findings.append(self._result(
                    url, "active_http_verb_delete_accepted", "FAIL",
                    detail=f"HTTP DELETE accepted on root path (status {resp.status_code}) — server allows content deletion via DELETE verb; attackers can remove web content or trigger unintended resource deletion; restrict to authenticated API endpoints only.",
                ))
        except Exception:
            pass

        # Send PROPFIND (WebDAV) to detect WebDAV exposure
        try:
            resp = self.http.get(url, method="PROPFIND",
                                  headers={"Depth": "1"})
            if resp is not None and resp.status_code in (207, 200):
                findings.append(self._result(
                    url, "active_http_verb_webdav_propfind", "FAIL",
                    detail=f"WebDAV PROPFIND returns {resp.status_code} (Multi-Status) — server has WebDAV enabled; directory traversal, file listing, and file manipulation via WebDAV COPY/MOVE/LOCK; disable WebDAV unless intentionally required.",
                ))
        except Exception:
            pass

        return findings or [self._result(url, "active_http_verb_probe_clean", "PASS",
                                          detail="HTTP verb probe clean — TRACE/PUT/DELETE/PROPFIND either return 405/403 or are not accepted; server correctly restricts HTTP methods.")]
