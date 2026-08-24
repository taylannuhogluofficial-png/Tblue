"""
Permissions-Policy (formerly Feature-Policy) deep audit.

Checks each sensitive browser feature individually:
- Dangerous hardware: camera, microphone, geolocation, usb, serial, bluetooth
- Financial: payment
- Screen: display-capture, fullscreen, picture-in-picture
- Sensors: accelerometer, gyroscope, magnetometer, ambient-light-sensor
- Other: document-domain, sync-xhr, autoplay

For each sensitive feature, we check if it is:
1. Explicitly restricted to () [blocked] or self [current origin only] — PASS
2. Explicitly allowed for all origins (*) — FAIL
3. Not mentioned in the policy (browser default applies) — WARN for sensitive ones

Covers both the Permissions-Policy header and the deprecated Feature-Policy header.
"""

import re
from typing import List, Dict, Any, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# (feature_name, severity_if_wildcard, severity_if_missing, description)
_FEATURES = [
    # Highly sensitive — microphone/camera/location/payment
    ("camera",               "FAIL", "WARN", "Access to device camera"),
    ("microphone",           "FAIL", "WARN", "Access to device microphone"),
    ("geolocation",          "FAIL", "WARN", "Access to device GPS/location"),
    ("payment",              "FAIL", "WARN", "Payment Request API"),
    ("usb",                  "FAIL", "WARN", "WebUSB device access"),
    ("serial",               "FAIL", "WARN", "Web Serial API"),
    ("bluetooth",            "FAIL", "WARN", "Web Bluetooth API"),
    ("display-capture",      "FAIL", "WARN", "Screen capture / screen share"),
    # Medium sensitivity
    ("midi",                 "WARN", "INFO", "MIDI device access"),
    ("ambient-light-sensor", "WARN", "INFO", "Ambient light sensor"),
    ("accelerometer",        "WARN", "INFO", "Device accelerometer"),
    ("gyroscope",            "WARN", "INFO", "Device gyroscope"),
    ("magnetometer",         "WARN", "INFO", "Device magnetometer"),
    ("fullscreen",           "WARN", "INFO", "Fullscreen API"),
    ("picture-in-picture",   "WARN", "INFO", "Picture-in-picture video"),
    # Risky legacy/compat
    ("document-domain",      "WARN", "INFO", "document.domain mutability (origin isolation risk)"),
    ("sync-xhr",             "WARN", "INFO", "Synchronous XMLHttpRequest (blocks main thread)"),
    ("autoplay",             "INFO", "INFO", "Media autoplay"),
    ("cross-origin-isolated","INFO", "INFO", "Cross-Origin isolation requirement"),
]

# Features where 'missing' means FAIL not WARN (most critical)
_MUST_RESTRICT = {"camera", "microphone", "geolocation", "payment", "usb"}


def _parse_permissions_policy(header: str) -> Dict[str, str]:
    """Parse Permissions-Policy header into {feature: allowlist} dict."""
    result = {}
    # New format: feature=(allowlist), feature=()
    for token in header.split(","):
        token = token.strip()
        if not token:
            continue
        m = re.match(r'([\w-]+)\s*=\s*\(([^)]*)\)', token)
        if m:
            result[m.group(1).lower()] = m.group(2).strip()
            continue
        # Some servers emit: feature=none or feature=self without parens
        m2 = re.match(r'([\w-]+)\s*=\s*(\S+)', token)
        if m2:
            result[m2.group(1).lower()] = m2.group(2).strip()
    return result


def _parse_feature_policy(header: str) -> Dict[str, str]:
    """Parse deprecated Feature-Policy header into {feature: allowlist} dict."""
    result = {}
    for token in header.split(";"):
        token = token.strip()
        if not token:
            continue
        parts = token.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1].strip()
    return result


class PermissionsPolicyScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
        except Exception:
            return self.results
        if resp is None:
            return self.results

        pp_raw = resp.headers.get("Permissions-Policy", "")
        fp_raw = resp.headers.get("Feature-Policy", "")

        if not pp_raw and not fp_raw:
            self.results.append(self._result(url,
                "Permissions-Policy — header absent",
                "WARN",
                detail=(
                    "Neither Permissions-Policy nor the deprecated Feature-Policy header "
                    "is present. Without this header, browser features like camera, "
                    "microphone, geolocation, and payment are governed only by browser "
                    "defaults — third-party iframes or injected scripts can request them. "
                    "Fix: add Permissions-Policy: camera=(), microphone=(), geolocation=(), "
                    "payment=(), usb=() to restrict all sensitive features by default."
                )))
            return self.results

        policy: Dict[str, str] = {}
        if pp_raw:
            policy.update(_parse_permissions_policy(pp_raw))
        if fp_raw:
            # Feature-Policy fills in gaps not covered by Permissions-Policy
            for k, v in _parse_feature_policy(fp_raw).items():
                if k not in policy:
                    policy[k] = v

        if fp_raw and not pp_raw:
            self.results.append(self._result(url,
                "Permissions-Policy — only deprecated Feature-Policy header set",
                "WARN",
                detail=(
                    "The deprecated Feature-Policy header is set but the standard "
                    "Permissions-Policy header is not. Feature-Policy is not recognised "
                    "by modern browsers (Chrome 88+, Firefox 74+). "
                    "Fix: migrate to Permissions-Policy."
                )))

        self._audit_features(url, policy)
        return self.results

    def _audit_features(self, url: str, policy: Dict[str, str]) -> None:
        any_fail = False
        restricted_count = 0

        for feature, sev_wildcard, sev_missing, description in _FEATURES:
            allowlist = policy.get(feature)

            if allowlist is None:
                # Not mentioned in policy — browser default
                if feature in _MUST_RESTRICT:
                    log_warn(logger, f"Permissions-Policy: {feature} not restricted")
                    self.results.append(self._result(url,
                        f"Permissions-Policy — {feature} not restricted",
                        sev_missing if feature not in _MUST_RESTRICT else "WARN",
                        detail=(
                            f"{description} ({feature}) is not mentioned in Permissions-Policy. "
                            f"Browser default allows the current origin to use it, and "
                            f"third-party iframes inherit it unless individually restricted. "
                            f"Fix: add {feature}=() to deny all, or {feature}=(self) "
                            f"to allow only the current origin."
                        )))
                continue

            # Wildcard — explicitly allowing all origins
            if allowlist.strip() in ("*", '"*"', "'*'"):
                any_fail = True
                log_fail(logger, f"Permissions-Policy: {feature}=* (all origins allowed)")
                self.results.append(self._result(url,
                    f"Permissions-Policy — {feature} allowed for all origins (*)",
                    sev_wildcard,
                    detail=(
                        f"{description} ({feature}) is explicitly allowed for all origins "
                        f"({feature}=*). This allows any third-party iframe embedded in "
                        f"the page to request this feature. "
                        f"Fix: change to {feature}=() [deny all] or {feature}=(self) "
                        f"[current origin only]."
                    )))
            elif allowlist.strip() in ("", "()", "none"):
                # Blocked — ideal
                restricted_count += 1
                log_pass(logger, f"Permissions-Policy: {feature}=() (blocked)")
                self.results.append(self._result(url,
                    f"Permissions-Policy — {feature} blocked ()",
                    "PASS",
                    detail=f"{description} ({feature}) is blocked for all origins — ideal."))
            elif "self" in allowlist.lower():
                restricted_count += 1
                log_pass(logger, f"Permissions-Policy: {feature}=(self)")
                self.results.append(self._result(url,
                    f"Permissions-Policy — {feature} restricted to self",
                    "PASS",
                    detail=(
                        f"{description} ({feature}) is restricted to the current origin "
                        f"({feature}=(self)). Third-party iframes cannot use this feature."
                    )))
            else:
                # Some other allowlist value — domain-specific, treat as info
                self.results.append(self._result(url,
                    f"Permissions-Policy — {feature} partially restricted",
                    "WARN",
                    detail=(
                        f"{description} ({feature}) is allowed for specific origins: "
                        f"'{allowlist}'. Verify these are trusted and necessary."
                    )))

        if restricted_count > 0 and not any_fail:
            log_pass(logger, f"Permissions-Policy: {restricted_count} sensitive features restricted")
