"""
Security header scanner.
Checks all 10 critical security headers with value analysis and grading.
Follows redirects to check headers on the final destination URL.
"""

from typing import List, Dict, Any
from tblue.scanner.base import BaseScanner
from tblue.definitions.headers import SECURITY_HEADERS, DEPRECATED_HEADERS
from tblue.logger import get_logger, log_pass, log_fail, log_warn, log_head

logger = get_logger(__name__)


class HeaderScanner(BaseScanner):
    """
    Checks security headers on the target URL.
    Validates not just presence but actual header values.
    Follows redirects so the final destination headers are checked.
    Produces a letter grade A+ to F.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan headers on a single URL.

        Args:
            url: target URL

        Returns:
            List containing one result dict with all header details and grade
        """
        self.results = []

        # follow redirects so we check the final destination
        resp = self.http.get(url, allow_redirects=True)
        if not resp:
            return self.results

        final_url = resp.url
        if final_url != url:
            logger.info(f"Followed redirect: {url} → {final_url}")

        site_results: List[Dict[str, Any]] = []

        for h in SECURITY_HEADERS:
            val     = resp.headers.get(h["key"], "")
            present = bool(val)

            try:
                issues = h["validate"](val) if present else []
            except Exception:
                issues = []

            if not present:
                status = h["severity"]
                if h["severity"] == "FAIL":
                    log_fail(logger, f"Missing header: {h['name']}")
                else:
                    log_warn(logger, f"Missing header: {h['name']}")
            elif issues:
                status = "WARN"
                log_warn(logger, f"{h['name']} present but weak: {issues[0]}")
            else:
                status = "PASS"
                log_pass(logger, f"{h['name']} — OK")

            site_results.append({
                "name":     h["name"],
                "key":      h["key"],
                "desc":     h["desc"],
                "fix":      h["fix"],
                "severity": h["severity"],
                "present":  present,
                "value":    val,
                "issues":   issues,
                "status":   status,
            })

        grade = self._calc_grade(site_results)
        log_head(logger, f"Header grade for {final_url}: {grade}")

        self.results.append({
            "url":      final_url,
            "type":     "Security headers",
            "headers":  site_results,
            "grade":    grade,
            "status":   "PASS" if grade in ("A+", "A") else
                        "WARN" if grade in ("B", "C") else "FAIL",
        })

        self._check_duplicate_headers(final_url, resp)
        self._check_deprecated_headers(final_url, resp)
        self._check_cors_cross_reference(final_url, resp)
        return self.results

    def _check_duplicate_headers(self, url: str, resp) -> None:
        """Detect the same security header returned more than once with conflicting values."""
        try:
            raw_headers = resp.raw.headers
            getlist     = getattr(raw_headers, "getlist", None)
            if not getlist:
                return
            duplicates = []
            for h in SECURITY_HEADERS:
                values = getlist(h["key"])
                if len(values) > 1:
                    duplicates.append(f"{h['name']}: {values}")
            if duplicates:
                log_warn(logger, f"Duplicate security headers on {url}: {duplicates[0]}")
                self.results.append(self._result(
                    url, "Security headers — duplicate headers", "WARN",
                    detail=(
                        f"Same header returned multiple times with potentially conflicting values: "
                        f"{'; '.join(duplicates[:3])}. "
                        "Browsers may use the weakest value. "
                        "Fix: ensure your web server or CDN sets each security header exactly once."
                    )
                ))
        except Exception:
            pass

    def _check_deprecated_headers(self, url: str, resp) -> None:
        """Warn if deprecated security headers (e.g. Feature-Policy) are present."""
        for h in DEPRECATED_HEADERS:
            val = resp.headers.get(h["key"], "")
            if val:
                log_warn(logger, f"Deprecated header present: {h['name']}")
                self.results.append(self._result(
                    url, f"Security headers — deprecated: {h['name']}", "WARN",
                    detail=(
                        f"{h['desc']}. Value: '{val}'. Fix: {h['fix']}"
                    )
                ))

    def _check_cors_cross_reference(self, url: str, resp) -> None:
        """Warn if CORS is open (wildcard) but cookies with no SameSite are also present."""
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if acao != "*":
            return

        raw_cookies = (
            resp.raw.headers.getlist("Set-Cookie")
            if hasattr(resp.raw.headers, "getlist")
            else []
        )
        has_no_samesite = any(
            "samesite" not in c.lower() for c in raw_cookies if c
        )
        if has_no_samesite:
            log_warn(logger, f"CORS wildcard + cookies without SameSite on {url}")
            self.results.append(self._result(
                url, "Security headers — CORS + cookie SameSite gap", "WARN",
                detail=(
                    "Access-Control-Allow-Origin: * combined with cookies lacking SameSite "
                    "increases CSRF/cross-origin data exposure risk. "
                    "Fix: restrict CORS to specific origins, and add SameSite=Strict or Lax "
                    "to all cookies."
                )
            ))

    def _calc_grade(self, headers: List[Dict[str, Any]]) -> str:
        """
        Calculate A+ to F grade based on combined header results.

        Args:
            headers: list of header result dicts

        Returns:
            Grade string: A+, A, B, C, D, or F
        """
        crit_fail = sum(
            1 for h in headers
            if h["severity"] == "FAIL" and h["status"] != "PASS"
        )
        warn_fail = sum(
            1 for h in headers
            if h["severity"] == "WARN" and h["status"] != "PASS"
        )

        if crit_fail == 0 and warn_fail == 0: return "A+"
        if crit_fail == 0 and warn_fail <= 2: return "A"
        if crit_fail <= 1 and warn_fail <= 3: return "B"
        if crit_fail <= 2:                    return "C"
        if crit_fail <= 3:                    return "D"
        return "F"
