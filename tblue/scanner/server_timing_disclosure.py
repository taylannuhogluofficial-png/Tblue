"""Server-Timing header disclosure — backend component names, DB query durations, timing sidechannel."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# Matches metric entries in Server-Timing header
_TIMING_ENTRY_RE = re.compile(r'([a-zA-Z0-9_\-]+)(?:;[^,]*)?', re.I)
# Component names that suggest backend internals
_INTERNAL_COMPONENT_RE = re.compile(
    r'\b(db|database|sql|mysql|postgres|redis|cache|memcache|mongo|elastic|'
    r'queue|worker|auth|session|render|template|compile|orm|query|fetch|'
    r'dynamo|cassandra|kafka|rabbitmq)\b',
    re.I,
)
# Timing value that reveals performance characteristics
_DUR_RE = re.compile(r'dur=([0-9.]+)', re.I)

_SLOW_THRESHOLD_MS = 1000  # > 1 second timing indicates heavy backend operation

_TIMING_PROBE_PATHS = [
    "",         # homepage
    "/api/",
    "/api/v1/",
    "/graphql",
]


def _analyze_timing_header(header_value: str, url: str) -> list:
    findings = []
    if not header_value:
        return findings

    entries = [e.strip() for e in header_value.split(",")]
    exposed_internals = []
    slow_ops = []

    for entry in entries:
        name_m = _TIMING_ENTRY_RE.match(entry)
        if not name_m:
            continue
        name = name_m.group(1)

        if _INTERNAL_COMPONENT_RE.search(name):
            exposed_internals.append(name)

        dur_m = _DUR_RE.search(entry)
        if dur_m:
            try:
                dur = float(dur_m.group(1))
                if dur > _SLOW_THRESHOLD_MS:
                    slow_ops.append(f"{name}={dur:.0f}ms")
            except ValueError:
                pass

    if exposed_internals:
        findings.append({
            "type": "server_timing_internal_disclosure",
            "status": "WARN",
            "url": url,
            "detail": (f"Server-Timing exposes internal component names: "
                       f"{', '.join(exposed_internals)} — aids attacker recon"),
        })

    if slow_ops:
        findings.append({
            "type": "server_timing_slow_operation",
            "status": "WARN",
            "url": url,
            "detail": (f"Server-Timing reveals slow backend operations: {', '.join(slow_ops)} "
                       f"— timing side-channel risk"),
        })

    return findings


class ServerTimingDisclosureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        probed = False
        for path in _TIMING_PROBE_PATHS:
            resp = self.http.get(origin + path)
            if resp is None:
                continue
            probed = True
            timing = resp.headers.get("server-timing", "") if resp.headers else ""
            if timing:
                for f in _analyze_timing_header(timing, origin + path):
                    results.append(self._result(f["url"], f["type"], f["status"],
                                                detail=f["detail"]))

        if not probed:
            return [self._result(url, "server_timing_no_response", "PASS",
                                 detail="No response")]

        if not results:
            results.append(self._result(url, "server_timing_clean", "PASS",
                                        detail="No Server-Timing disclosure detected"))
        return results
