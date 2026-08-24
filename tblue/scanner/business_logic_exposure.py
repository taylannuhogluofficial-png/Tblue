"""Business logic exposure — price manipulation indicators, admin functions without auth, mass assignment."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# Price/discount manipulation indicators in JS
_PRICE_CLIENT_RE = re.compile(
    r'(?:total|price|amount|cost|discount)\s*[=:]\s*(?:parseInt|parseFloat|Number)\s*\(',
    re.I,
)
_NEGATIVE_PRICE_RE = re.compile(r'(?:price|amount|cost)\s*<\s*0', re.I)
_DISCOUNT_100_RE = re.compile(r'discount\s*(?:>=|===|==)\s*100', re.I)

# Mass assignment vulnerability indicators (fields that shouldn't be user-settable)
_MASS_ASSIGN_RE = re.compile(
    r'(?:"|\b)(?:is_admin|role|admin|superuser|permission[s]?|privilege[s]?|'
    r'verified|confirmed|enabled|is_staff|is_superuser)(?:"|:)',
    re.I,
)

# API paths that suggest admin/privileged operations
_ADMIN_API_PATHS = [
    "/api/admin", "/api/v1/admin", "/api/users", "/api/v1/users",
    "/admin/api", "/manage/", "/internal/api",
]

# HTTP verbs for admin probe
_ADMIN_INDICATORS_RE = re.compile(
    r'(?:admin|superuser|is_admin|role.*admin|manage.*user)', re.I
)


def _check_client_side_price_logic(body: str, url: str) -> list:
    findings = []
    if _PRICE_CLIENT_RE.search(body):
        findings.append({
            "type": "business_logic_client_price_calc",
            "status": "WARN",
            "url": url,
            "detail": "Price/amount calculation appears to be done client-side — "
                      "values may be manipulable by attacker before form submission",
        })
    if _NEGATIVE_PRICE_RE.search(body) or _DISCOUNT_100_RE.search(body):
        findings.append({
            "type": "business_logic_price_boundary_missing",
            "status": "WARN",
            "url": url,
            "detail": "Price or discount boundary check detected client-side — "
                      "negative prices or 100% discount may bypass validation if checked only in JS",
        })
    return findings


def _check_mass_assignment_fields(body: str, url: str) -> list:
    """Check if privileged fields appear in forms or JSON responses."""
    findings = []
    if _MASS_ASSIGN_RE.search(body):
        findings.append({
            "type": "business_logic_mass_assignment_fields",
            "status": "WARN",
            "url": url,
            "detail": "Privileged field names (is_admin, role, permission, verified) found in response — "
                      "verify these cannot be set via mass assignment on update endpoints",
        })
    return findings


def _check_admin_api_accessible(http, origin: str) -> list:
    findings = []
    for path in _ADMIN_API_PATHS[:4]:
        try:
            r = http.get(origin + path)
            if r and r.status_code == 200:
                body = r.text or ""
                if _ADMIN_INDICATORS_RE.search(body):
                    findings.append({
                        "type": "business_logic_admin_api_exposed",
                        "status": "FAIL",
                        "url": origin + path,
                        "detail": (f"Admin API endpoint {path} accessible without auth "
                                   f"and returns admin-related data — broken access control"),
                    })
                    return findings
        except Exception:
            pass
    return findings


class BusinessLogicExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "business_logic_no_response", "PASS",
                                 detail="No response")]

        for f in _check_client_side_price_logic(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_mass_assignment_fields(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_admin_api_accessible(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "business_logic_clean", "PASS",
                                        detail="No business logic exposure indicators detected"))
        return results
