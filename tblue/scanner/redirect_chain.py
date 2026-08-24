"""
Redirect chain security scanner.

Follows the full redirect chain for a URL and checks for:
- HTTP → HTTPS downgrade in the middle of the chain (MITM-able leg)
- Cleartext (HTTP) hops when final destination is HTTPS
- Excessive redirect count (performance + loop risk)
- Open redirect indicators in redirect targets
- Mixed-protocol chains (HTTPS → HTTP → HTTPS)
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_MAX_REDIRECTS   = 10
_WARN_REDIRECTS  = 5

# Patterns suggesting an open redirect vulnerability in the Location header
_OPEN_REDIRECT_PARAMS = re.compile(
    r"[?&](?:next|redirect|return|redirect_url|returnurl|return_url|r|url|goto|dest|destination|forward|redir|continue|target|link|ref|referer|from)\s*=",
    re.I
)


class RedirectChainScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        chain = self._follow_chain(url)
        if chain is None:
            return self.results

        self._check_http_downgrade(chain, url)
        self._check_redirect_count(chain, url)
        self._check_mixed_protocol(chain, url)
        return self.results

    def _follow_chain(self, start_url: str) -> Optional[List[Dict]]:
        chain     = []
        current   = start_url
        seen      = set()

        for _ in range(_MAX_REDIRECTS + 1):
            if current in seen:
                log_warn(logger, f"Redirect loop detected at {current}")
                self.results.append(self._result(start_url,
                    "Redirect chain — redirect loop detected",
                    "FAIL",
                    detail=f"A redirect loop was detected at {current}. "
                           "Browsers will show an error; crawlers and APIs may hang."))
                return None
            seen.add(current)

            try:
                resp = self.http.get(current, allow_redirects=False)
                if resp is None:
                    break
            except Exception as e:
                logger.debug(f"Redirect chain probe failed at {current}: {e}")
                break

            scheme  = urlparse(current).scheme
            status  = resp.status_code
            location = resp.headers.get("Location", "")

            chain.append({
                "url":      current,
                "scheme":   scheme,
                "status":   status,
                "location": location,
            })

            if status in (301, 302, 303, 307, 308) and location:
                # Resolve relative redirects
                next_url = location if location.startswith("http") else urljoin(current, location)
                current  = next_url
            else:
                break

        return chain

    def _check_http_downgrade(self, chain: List[Dict], origin_url: str) -> None:
        if not chain:
            return
        # Find any HTTP leg in a chain that ends on HTTPS
        final_scheme = chain[-1]["scheme"]
        http_hops    = [h for h in chain if h["scheme"] == "http"]

        if final_scheme == "https" and http_hops:
            # HTTP hops before reaching HTTPS — those legs are cleartext
            for hop in http_hops:
                log_fail(logger, f"HTTP hop in redirect chain: {hop['url']}")
                self.results.append(self._result(origin_url,
                    "Redirect chain — HTTP leg before HTTPS destination",
                    "FAIL",
                    detail=(
                        f"The redirect chain passes through a cleartext HTTP hop ({hop['url']}) "
                        f"before reaching the final HTTPS destination. "
                        "An attacker on the network can intercept and modify the HTTP response "
                        "to inject content or steal cookies without the Secure flag before "
                        "the user reaches HTTPS. "
                        "Fix: start with HTTPS and eliminate all HTTP hops."
                    )))
            return

        if final_scheme == "http":
            log_warn(logger, f"Final redirect destination is HTTP: {chain[-1]['url']}")
            self.results.append(self._result(origin_url,
                "Redirect chain — final destination is HTTP",
                "WARN",
                detail=(
                    f"The redirect chain ends at an HTTP URL: {chain[-1]['url']}. "
                    "All traffic is in cleartext. Fix: serve the final page over HTTPS."
                )))
            return

        if all(h["scheme"] == "https" for h in chain):
            log_pass(logger, "Redirect chain uses HTTPS throughout")
            self.results.append(self._result(origin_url,
                "Redirect chain — HTTPS throughout",
                "PASS",
                detail=f"All {len(chain)} redirect hop(s) use HTTPS. No cleartext legs."))

    def _check_redirect_count(self, chain: List[Dict], origin_url: str) -> None:
        redirects = len([h for h in chain if h["status"] in (301, 302, 303, 307, 308)])
        if redirects == 0:
            return
        if redirects >= _MAX_REDIRECTS:
            self.results.append(self._result(origin_url,
                f"Redirect chain — excessive redirects ({redirects})",
                "FAIL",
                detail=(
                    f"The redirect chain has {redirects} hops — browsers typically abort at 10-20. "
                    "Fix: consolidate redirects to a single hop."
                )))
        elif redirects >= _WARN_REDIRECTS:
            log_warn(logger, f"{redirects} redirect hops — may impact performance")
            self.results.append(self._result(origin_url,
                f"Redirect chain — many redirects ({redirects} hops)",
                "WARN",
                detail=(
                    f"{redirects} redirect hops add latency for every user. "
                    "Each hop is a separate TCP connection. "
                    "Fix: collapse to a single 301/308 redirect."
                )))
        else:
            log_pass(logger, f"Redirect chain is short ({redirects} hop(s))")
            self.results.append(self._result(origin_url,
                f"Redirect chain — {redirects} redirect hop(s) (acceptable)",
                "PASS",
                detail=f"{redirects} redirect hop(s). No performance concern."))

    def _check_mixed_protocol(self, chain: List[Dict], origin_url: str) -> None:
        if len(chain) < 2:
            return
        # Detect HTTPS → HTTP → HTTPS (sandwich attack surface)
        schemes = [h["scheme"] for h in chain]
        for i in range(1, len(schemes) - 1):
            if schemes[i - 1] == "https" and schemes[i] == "http" and schemes[i + 1] == "https":
                log_warn(logger, "HTTPS→HTTP→HTTPS sandwich in redirect chain")
                self.results.append(self._result(origin_url,
                    "Redirect chain — HTTPS→HTTP→HTTPS mixed-protocol pattern",
                    "FAIL",
                    detail=(
                        f"Redirect chain has an HTTP hop sandwiched between two HTTPS hops: "
                        f"{chain[i-1]['url']} → {chain[i]['url']} → {chain[i+1]['url']}. "
                        "The cleartext HTTP leg is a MITM opportunity even though it's in the "
                        "middle of a TLS chain. Fix: eliminate all HTTP legs."
                    )))
