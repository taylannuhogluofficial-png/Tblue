"""
Iframe Allow Attribute Security Scanner.

The `allow` attribute on <iframe> elements delegates permissions from the
embedding page to the embedded document. Overly permissive `allow` attributes
grant third-party iframes access to hardware APIs, user data, and payment flows.

Security issues:

1. `allow="camera"` — grants camera access to the iframe without requiring
   the parent's Permissions-Policy to also allow it.
2. `allow="microphone"` — eavesdropping risk from embedded ads/widgets.
3. `allow="payment"` — third-party iframes can initiate Payment Request dialogs.
4. `allow="geolocation"` — precise location delegated to embedded content.
5. `allow="usb"`, `allow="serial"` — WebUSB/WebSerial access from iframes.
6. `allow="*"` — grants all feature permissions to the iframe (maximally permissive).
7. Cross-origin iframe with dangerous `allow` values is higher risk than same-origin.
8. Missing `sandbox` attribute on third-party iframes:
   Without `sandbox`, iframes can run scripts, navigate the top-level window,
   access cookies, etc.
9. `sandbox` without required restrictions:
   `sandbox="allow-scripts allow-same-origin"` together breaks the sandbox
   (same-origin + scripts = full script execution = effectively no sandbox).

CWE-276: Incorrect Default Permissions
CWE-732: Incorrect Permission Assignment for Critical Resource
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_IFRAME_RE = re.compile(r'<iframe\b([^>]*)>', re.I)
_SRC_RE    = re.compile(r'\bsrc\s*=\s*["\']([^"\']*)["\']', re.I)
_ALLOW_RE  = re.compile(r'\ballow\s*=\s*["\']([^"\']*)["\']', re.I)
_SANDBOX_RE = re.compile(r'\bsandbox\b(?:\s*=\s*["\']([^"\']*)["\'])?', re.I)

_DANGEROUS_FEATURES = {
    "camera":         "FAIL",
    "microphone":     "FAIL",
    "payment":        "FAIL",
    "geolocation":    "WARN",
    "usb":            "FAIL",
    "serial":         "FAIL",
    "bluetooth":      "WARN",
    "midi":           "WARN",
    "display-capture":"FAIL",
    "idle-detection": "WARN",
    "ambient-light-sensor": "WARN",
}

_SANDBOX_BREAK_COMBO = {"allow-scripts", "allow-same-origin"}


def _is_cross_origin(src: str, page_host: str) -> bool:
    if not src:
        return False
    try:
        p = urlparse(src)
        if p.scheme in ("data", "javascript", "about"):
            return False
        if p.netloc:
            return p.netloc.lower() != page_host.lower()
        if src.startswith("//"):
            host = src.lstrip("/").split("/")[0]
            return host.lower() != page_host.lower()
    except Exception:
        pass
    return False


class IframeAllowSecurityScanner(BaseScanner):
    """Detect dangerous permissions delegated to iframes via the allow= attribute."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Iframe allow security — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        page_host = urlparse(url).netloc.lower()
        iframes = _IFRAME_RE.findall(body)

        if not iframes:
            log_pass(logger, f"No iframes found at {url}")
            self.results.append(self._result(
                url, "Iframe allow security — no iframes found", "PASS",
                detail="No <iframe> elements detected on this page."
            ))
            return self.results

        for iframe_attrs in iframes:
            if findings >= 10:
                break

            src_m    = _SRC_RE.search(iframe_attrs)
            allow_m  = _ALLOW_RE.search(iframe_attrs)
            sandbox_m = _SANDBOX_RE.search(iframe_attrs)

            src   = src_m.group(1)   if src_m   else ""
            allow = allow_m.group(1) if allow_m else ""
            sandbox_attrs = sandbox_m.group(1).lower() if (sandbox_m and sandbox_m.group(1)) else ""
            has_sandbox = sandbox_m is not None

            cross_origin = _is_cross_origin(src, page_host)

            # Wildcard allow
            if allow.strip() == "*":
                log_fail(logger, f"Iframe allow='*' at {url}: {src[:60]}")
                self.results.append(self._result(
                    url,
                    f"Iframe allow security — allow='*' grants all permissions to iframe: {src[:60]}",
                    "FAIL",
                    detail=(
                        f"<iframe src='{src[:80]}' allow='*'> grants every browser feature "
                        "(camera, microphone, geolocation, payment, USB, etc.) to the "
                        "embedded document. Fix: replace allow='*' with an explicit list "
                        "of only the features this iframe actually needs."
                    )
                ))
                findings += 1
                continue

            # Check individual dangerous features
            if allow:
                allow_features = [f.strip().lower().split(";")[0].strip() for f in allow.split()]
                for feature in allow_features:
                    if feature in _DANGEROUS_FEATURES:
                        status = _DANGEROUS_FEATURES[feature]
                        if cross_origin:
                            # Cross-origin is always at least WARN
                            status = "FAIL" if status == "FAIL" else "WARN"
                        if status == "FAIL":
                            log_fail(logger, f"Iframe allow='{feature}' at {url}: {src[:60]}")
                        else:
                            log_warn(logger, f"Iframe allow='{feature}' at {url}: {src[:60]}")
                        self.results.append(self._result(
                            url,
                            f"Iframe allow security — '{feature}' delegated to {'cross-origin ' if cross_origin else ''}iframe: {src[:60]}",
                            status,
                            detail=(
                                f"<iframe src='{src[:80]}' allow='{feature}'> grants {feature} "
                                f"access to the {'cross-origin ' if cross_origin else ''}embedded document. "
                                f"{'Cross-origin iframes with hardware permissions are a high-risk delegation. ' if cross_origin else ''}"
                                f"Fix: remove '{feature}' from allow= if not required; use "
                                "Permissions-Policy on the iframe's own response to restrict further."
                            )
                        ))
                        findings += 1
                        if findings >= 10:
                            break

            # Sandbox without restriction (allow-scripts + allow-same-origin combo)
            if has_sandbox and sandbox_attrs:
                sandbox_tokens = set(sandbox_attrs.split())
                if _SANDBOX_BREAK_COMBO.issubset(sandbox_tokens) and findings < 10:
                    log_fail(logger, f"Iframe sandbox broken by allow-scripts+allow-same-origin at {url}")
                    self.results.append(self._result(
                        url,
                        f"Iframe allow security — sandbox broken: allow-scripts + allow-same-origin: {src[:60]}",
                        "FAIL",
                        detail=(
                            "iframe sandbox includes both 'allow-scripts' and 'allow-same-origin'. "
                            "This combination defeats the sandbox: same-origin scripts have full "
                            "DOM access and can remove the sandbox attribute, escaping containment. "
                            "Fix: never combine allow-scripts and allow-same-origin in sandbox."
                        )
                    ))
                    findings += 1

            # Cross-origin iframe without sandbox
            elif not has_sandbox and cross_origin and findings < 10:
                log_warn(logger, f"Cross-origin iframe without sandbox at {url}: {src[:60]}")
                self.results.append(self._result(
                    url,
                    f"Iframe allow security — cross-origin iframe without sandbox: {src[:60]}",
                    "WARN",
                    detail=(
                        f"<iframe src='{src[:80]}'> loads cross-origin content without a "
                        "sandbox attribute. Without sandbox, the iframe can run scripts, "
                        "navigate the top-level window, and access same-origin cookies. "
                        "Fix: add sandbox='allow-scripts allow-forms' and include only "
                        "the minimum required permissions."
                    )
                ))
                findings += 1

        if not self.results:
            log_pass(logger, f"No dangerous iframe allow attributes at {url}")
            self.results.append(self._result(
                url, "Iframe allow security — no dangerous allow attributes or sandbox issues detected", "PASS",
                detail="Iframes found; no dangerous permission delegation or sandbox bypass detected."
            ))

        return self.results
