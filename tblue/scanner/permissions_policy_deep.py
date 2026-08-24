"""
Permissions Policy Deep Audit Scanner.

The Permissions Policy header (formerly Feature-Policy) controls which browser
features and APIs are available to the page and its embedded iframes. Security issues:

1. Sensitive hardware APIs not restricted:
   - camera, microphone, geolocation, usb, serial, bluetooth, midi
   - Unrestricted access to sensors and hardware from embedded iframes.
2. Payment Request API exposure:
   - `payment` feature not restricted — iframes can initiate payment dialogs.
3. Interest-cohort / Topics API:
   - `interest-cohort=()` suppresses FLoC; `browsing-topics=()` suppresses Topics API.
   - Sites not opting out reveal cohort data to embedded third parties.
4. Screen capture and display:
   - `display-capture` not blocked allows screen recording from iframes.
5. Wake lock:
   - `screen-wake-lock` not blocked allows iframes to prevent device sleep.
6. Ambient sensors:
   - `accelerometer`, `gyroscope`, `magnetometer`, `ambient-light-sensor` can be
     used for fingerprinting and side-channel attacks.
7. Idle detection:
   - `idle-detection` leaks user inactivity state to third-party iframes.
8. XR/VR API:
   - `xr-spatial-tracking` allows access to AR/VR session data.
9. Permissions-Policy-Report-Only without enforcement:
   - Only logging violations; features remain available to embedded content.

CWE-276: Incorrect Default Permissions
CWE-732: Incorrect Permission Assignment for Critical Resource
"""

import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_FEATURES = {
    "camera":                 ("HIGH",   "access to device camera — iframe phishing attacks"),
    "microphone":             ("HIGH",   "access to device microphone — eavesdropping from iframes"),
    "geolocation":            ("HIGH",   "precise user location — privacy and tracking risk"),
    "payment":                ("HIGH",   "Payment Request API — iframes can initiate payment dialogs"),
    "usb":                    ("HIGH",   "WebUSB device access — hardware exploitation from iframes"),
    "serial":                 ("HIGH",   "Web Serial port access — device communication from iframes"),
    "bluetooth":              ("MEDIUM", "Web Bluetooth access — hardware control from iframes"),
    "midi":                   ("MEDIUM", "MIDI device access — potential input injection"),
    "display-capture":        ("HIGH",   "screen capture / screen recording from embedded frames"),
    "screen-wake-lock":       ("LOW",    "prevent device screen sleep — battery drain from iframes"),
    "idle-detection":         ("MEDIUM", "user inactivity detection — infers user presence/absence"),
    "accelerometer":          ("MEDIUM", "device motion sensor — fingerprinting and side-channel"),
    "gyroscope":              ("MEDIUM", "device gyroscope — fingerprinting and orientation leakage"),
    "magnetometer":           ("MEDIUM", "device magnetometer — fingerprinting"),
    "ambient-light-sensor":   ("MEDIUM", "ambient light sensor — environment inference"),
    "xr-spatial-tracking":    ("MEDIUM", "AR/VR spatial tracking — 3D environment data"),
    "interest-cohort":        ("MEDIUM", "FLoC cohort ID — privacy: opt out with interest-cohort=()"),
    "browsing-topics":        ("MEDIUM", "Topics API cohort — privacy: opt out with browsing-topics=()"),
    "notifications":          ("LOW",    "push notification permission from iframes"),
    "speaker-selection":      ("LOW",    "audio output device enumeration from iframes"),
}

_PRIVACY_OPT_OUTS = {"interest-cohort", "browsing-topics"}

def _parse_permissions_policy(header_value: str) -> Dict[str, str]:
    """Parse Permissions-Policy header into {feature: allowlist} dict."""
    result: Dict[str, str] = {}
    for directive in header_value.split(","):
        directive = directive.strip()
        if "=" in directive:
            feature, _, allowlist = directive.partition("=")
            result[feature.strip().lower()] = allowlist.strip()
        elif directive:
            result[directive.strip().lower()] = "*"
    return result


class PermissionsPolicyDeepScanner(BaseScanner):
    """Audit Permissions-Policy header for unrestricted sensitive features."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Permissions-Policy deep — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers.items() if hasattr(resp.headers, "items") else resp.headers)}

        pp_value    = headers.get("permissions-policy", "")
        pp_ro_value = headers.get("permissions-policy-report-only", "")

        if not pp_value and not pp_ro_value:
            log_warn(logger, f"No Permissions-Policy at {url}")
            self.results.append(self._result(
                url,
                "Permissions-Policy deep — header absent",
                "WARN",
                detail=(
                    "No Permissions-Policy header found. All browser features (camera, "
                    "microphone, geolocation, payment, USB, Bluetooth, etc.) are allowed "
                    "to embedded iframes by default origin allowlist. "
                    "Fix: add Permissions-Policy and explicitly disable unused features."
                )
            ))
            return self.results

        # Report-only without enforcement
        if pp_ro_value and not pp_value:
            log_warn(logger, f"Permissions-Policy report-only only at {url}")
            self.results.append(self._result(
                url,
                "Permissions-Policy deep — report-only without enforcement",
                "WARN",
                detail=(
                    "Only Permissions-Policy-Report-Only is set; the enforcing "
                    "Permissions-Policy header is absent. Violations are logged but "
                    "all features remain available to embedded frames. "
                    "Fix: graduate to Permissions-Policy to enforce restrictions."
                )
            ))
            findings += 1

        policy = _parse_permissions_policy(pp_value or pp_ro_value)

        for feature, (severity, description) in _SENSITIVE_FEATURES.items():
            if findings >= 12:
                break

            allowed = policy.get(feature)

            if allowed is None:
                # Feature absent from policy — defaults vary by feature/browser
                if feature in _PRIVACY_OPT_OUTS:
                    # Privacy-relevant features need explicit opt-out
                    log_warn(logger, f"Missing privacy opt-out for {feature} at {url}")
                    self.results.append(self._result(
                        url,
                        f"Permissions-Policy deep — missing opt-out for '{feature}' ({description})",
                        "WARN",
                        detail=(
                            f"The '{feature}' feature is not included in Permissions-Policy. "
                            f"Privacy implication: {description}. "
                            f"Fix: add '{feature}=()' to opt out of this API."
                        )
                    ))
                    findings += 1
                continue

            # Check if the allowlist is too permissive
            if allowed in ("*", "(*)"):
                status = "FAIL" if severity == "HIGH" else "WARN"
                log_fail(logger, f"Permissions-Policy {feature}=* at {url}") if status == "FAIL" else log_warn(logger, f"Permissions-Policy {feature}=* at {url}")
                self.results.append(self._result(
                    url,
                    f"Permissions-Policy deep — '{feature}' allowed for all origins (wildcard)",
                    status,
                    detail=(
                        f"Permissions-Policy sets '{feature}=*', granting {description} "
                        f"to all embedded frames including cross-origin ones. "
                        f"Fix: set '{feature}=()' to deny, or '{feature}=(self)' to "
                        f"allow only same-origin frames."
                    )
                ))
                findings += 1
            elif "http://" in allowed.lower():
                log_warn(logger, f"Permissions-Policy {feature} allows HTTP origin at {url}")
                self.results.append(self._result(
                    url,
                    f"Permissions-Policy deep — '{feature}' allows HTTP (non-TLS) origin",
                    "WARN",
                    detail=(
                        f"Permissions-Policy grants '{feature}' to an HTTP (cleartext) origin. "
                        f"This origin is susceptible to MITM. "
                        f"Fix: only grant sensitive features to HTTPS origins."
                    )
                ))
                findings += 1

        if not self.results:
            log_pass(logger, f"Permissions-Policy adequately restricts features at {url}")
            self.results.append(self._result(
                url,
                "Permissions-Policy deep — sensitive features appear well-restricted",
                "PASS",
                detail="Permissions-Policy header present and sensitive features are restricted."
            ))

        return self.results
