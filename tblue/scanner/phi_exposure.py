"""PHI exposure — passive detection of Protected Health Information in API responses."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_HEALTH_API_PATHS = [
    "/api/patients", "/api/patient", "/api/medical", "/api/records",
    "/api/appointments", "/api/prescriptions", "/api/diagnoses",
    "/api/v1/patients", "/api/v1/records", "/api/health",
    "/fhir/Patient", "/fhir/Observation", "/fhir/MedicationRequest",
    "/api/users", "/api/profile",
]

_SSN_RE = re.compile(r'(?<!\d)\d{3}[-\s]?\d{2}[-\s]?\d{4}(?!\d)')
_DOB_JSON_RE = re.compile(r'"(?:dob|date_of_birth|birth_date|birthDate)"\s*:\s*"[^"]{5,15}"', re.I)
_DIAGNOSIS_RE = re.compile(
    r'"(?:diagnosis|diagnos[ei]s|icd[_\-]?(?:code|10)|condition|medical_condition)"\s*:\s*"[^"]{1,100}"',
    re.I,
)
_MEDICATION_RE = re.compile(
    r'"(?:medication|prescription|drug|rx|treatment)"\s*:\s*"[^"]{2,80}"',
    re.I,
)
_MRN_RE = re.compile(
    r'"(?:mrn|medical_record(?:_number)?|patient_id|record_number)"\s*:\s*"?[A-Z0-9\-]{4,20}"?',
    re.I,
)
_INSURANCE_RE = re.compile(
    r'"(?:insurance(?:_id|_number)?|policy(?:_number)?|member_id|group_number)"\s*:\s*"[^"]{3,30}"',
    re.I,
)
_FHIR_RESOURCE_RE = re.compile(r'"resourceType"\s*:\s*"(?:Patient|Observation|Medication|Condition|Encounter)"', re.I)

_PHI_PATTERNS = [
    ("phi_ssn_pattern", _SSN_RE, "FAIL", "SSN-pattern value"),
    ("phi_date_of_birth", _DOB_JSON_RE, "FAIL", "date of birth field"),
    ("phi_diagnosis_field", _DIAGNOSIS_RE, "FAIL", "diagnosis/condition field"),
    ("phi_medication_field", _MEDICATION_RE, "WARN", "medication/prescription field"),
    ("phi_medical_record_number", _MRN_RE, "FAIL", "medical record number (MRN)"),
    ("phi_insurance_field", _INSURANCE_RE, "WARN", "insurance/policy ID field"),
    ("phi_fhir_resource", _FHIR_RESOURCE_RE, "FAIL", "FHIR healthcare resource"),
]


def _scan_body_for_phi(body: str) -> list:
    findings = []
    reported = set()
    for type_id, pattern, status, label in _PHI_PATTERNS:
        if type_id in reported:
            continue
        m = pattern.search(body)
        if m:
            findings.append({
                "type": type_id,
                "status": status,
                "detail": (f"PHI detected: {label} found in API response — "
                           f"verify HIPAA/GDPR authorization controls; match: {m.group(0)[:60]!r}"),
            })
            reported.add(type_id)
    return findings


class PHIExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        phi_found = False
        for path in _HEALTH_API_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp is None or resp.status_code != 200:
                    continue
                body = resp.text or ""
                if not body or len(body) < 10:
                    continue
                ct = ""
                if hasattr(resp.headers, "get"):
                    ct = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
                elif isinstance(resp.headers, dict):
                    ct = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
                if "html" in (ct or "").lower() and "<html" in body[:200].lower():
                    continue

                for f in _scan_body_for_phi(body):
                    phi_found = True
                    results.append(self._result(
                        origin + path, f["type"], f["status"],
                        detail=f["detail"],
                    ))
            except Exception:
                continue

        if not results:
            if phi_found:
                pass
            results.append(self._result(url, "phi_exposure_none_detected", "PASS",
                                        detail="No PHI patterns detected in accessible API responses"))
        return results
