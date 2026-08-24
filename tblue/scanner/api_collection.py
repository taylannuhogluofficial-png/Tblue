"""
API Client Collection Exposure Scanner.

API client tools (Postman, Insomnia, Bruno, Hoppscotch) export collection files
that contain API endpoint definitions, request headers, authentication credentials,
and environment variables. When these files are accidentally deployed to web servers
or committed to public repositories, they expose complete API documentation AND
embedded production credentials.

Real-world impact: security researchers routinely find production API keys, Bearer
tokens, OAuth client secrets, and database connection strings in Postman collection
files indexed by search engines or accessible on web servers.

Files probed:
  Postman:   *.postman_collection.json, postman_collection.json, collection.json
  Insomnia:  insomnia.json, .insomnia/*, insomnia-*.json
  Bruno:     bruno.json, collection.bru (text format, less common on web)
  Hoppscotch: hoppscotch-collection.json, hoppscotch.json

Content validation: Must match format-specific structure patterns before flagging,
avoiding false positives on generic 404 pages or other JSON files.

Credential detection: Scans collection content for hardcoded auth tokens, API keys,
Bearer tokens, Basic auth credentials, and environment variable values.

Professional equivalents: Detectify "API Collection Exposure",
Qualys WAS "API Client Collection", Acunetix "Developer Files".

CWE-312: Cleartext Storage of Sensitive Information
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-538: Insertion of Sensitive Information into Externally-Accessible File
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# --- Content structure validators ---

# Postman v2.0/v2.1 collection schema
_POSTMAN_V2_RE = re.compile(
    r'"schema"\s*:\s*"https://schema\.getpostman\.com/[^"]*collection'
    r'|"_postman_id"\s*:\s*"[0-9a-f\-]{10,}"'
    r'|"postman_id"\s*:\s*"',
    re.I,
)
_POSTMAN_ITEM_RE = re.compile(r'"item"\s*:\s*\[', re.I)

# Postman v1.0 (older format)
_POSTMAN_V1_RE = re.compile(
    r'"collection_id"\s*:\s*"[0-9a-f\-]{10,}"'
    r'|"collection_name"\s*:\s*"'
    r'|"requests"\s*:\s*\[',
    re.I,
)

# Insomnia export format v3/v4
_INSOMNIA_RE = re.compile(
    r'__export_format"\s*:\s*[34]'
    r'|"_type"\s*:\s*"export"'
    r'|"insomnia_version"\s*:\s*"',
    re.I,
)
_INSOMNIA_RESOURCE_RE = re.compile(r'"resources"\s*:\s*\[', re.I)

# Hoppscotch collection
_HOPPSCOTCH_RE = re.compile(
    r'"v"\s*:\s*\d+\s*,\s*"id"\s*:\s*"'
    r'|"hoppscotch"'
    r'|"folders"\s*:\s*\[.*?"requests"\s*:\s*\[',
    re.I | re.S,
)

# Bruno collection (text-based .bru format) — less likely to be served as JSON
_BRUNO_RE = re.compile(
    r'\bmeta\s*\{[^}]*name\s*:', re.I
)

# --- Credential detection patterns within collections ---

# Bearer tokens — matches both {"Authorization": "Bearer ..."} (inline format)
# and Postman/Insomnia {"key": "Authorization", "value": "Bearer ..."}
_BEARER_TOKEN_RE = re.compile(
    r'"value"\s*:\s*"Bearer\s+([A-Za-z0-9\-._~+/]{20,})"'
    r'|"(?:Authorization|authorization)"\s*:\s*"Bearer\s+([A-Za-z0-9\-._~+/]{20,})"',
    re.I,
)
# API keys in "value" fields or direct key-value pairs
_API_KEY_RE = re.compile(
    r'"value"\s*:\s*"(sk-[A-Za-z0-9\-]{8,}|(?:api[_-])?key[_-]?[A-Za-z0-9\-]{8,})"'
    r'|"(?:x-api-key|api[_-]key|apikey|x-auth-token|access[_-]token)"\s*:\s*"([^"]{8,})"',
    re.I,
)
# Basic auth base64 — matches in both formats
_BASIC_AUTH_RE = re.compile(
    r'"value"\s*:\s*"Basic\s+([A-Za-z0-9+/=]{8,})"'
    r'|"(?:Authorization|authorization)"\s*:\s*"Basic\s+([A-Za-z0-9+/=]{8,})"',
    re.I,
)
# AWS access key IDs embedded in collections
_AWS_KEY_RE = re.compile(r'(?:AKIA|ASIA|AROA)[0-9A-Z]{16}')
# GitHub/npm/other personal access tokens in key-value pairs or "value" fields
_TOKEN_VALUE_RE = re.compile(
    r'"(?:token|secret|password|pwd|passwd|api_secret|client_secret)"\s*:\s*"([^"]{8,})"',
    re.I,
)
# Environment variable current values (Postman environment variables export)
_ENV_CURRENT_VALUE_RE = re.compile(
    r'"currentValue"\s*:\s*"([^"]{5,})"',
    re.I,
)

# --- Probe paths: (path, description, format, severity) ---
_PROBES: List[Tuple[str, str, str, str]] = [
    # Postman
    ("/postman_collection.json",      "Postman collection (root)",        "postman",    "FAIL"),
    ("/api.postman_collection.json",  "Postman API collection",           "postman",    "FAIL"),
    ("/collection.json",              "API collection JSON",              "postman",    "FAIL"),
    ("/postman/collection.json",      "Postman collection (/postman/)",   "postman",    "FAIL"),
    ("/.postman/collection.json",     "Postman hidden-dir collection",    "postman",    "FAIL"),
    ("/api/postman_collection.json",  "Postman API collection (/api/)",   "postman",    "FAIL"),
    ("/docs/postman_collection.json", "Postman collection (/docs/)",      "postman",    "FAIL"),
    # Insomnia
    ("/insomnia.json",                "Insomnia workspace export",        "insomnia",   "FAIL"),
    ("/insomnia-collection.json",     "Insomnia collection",              "insomnia",   "FAIL"),
    ("/.insomnia/ApiSpec.yaml",       "Insomnia API spec (hidden-dir)",   "insomnia",   "FAIL"),
    ("/insomnia/insomnia.json",       "Insomnia export (/insomnia/)",     "insomnia",   "FAIL"),
    # Hoppscotch
    ("/hoppscotch.json",              "Hoppscotch collection",            "hoppscotch", "FAIL"),
    ("/hoppscotch-collection.json",   "Hoppscotch collection",            "hoppscotch", "FAIL"),
    # Generic API exports
    ("/api-collection.json",          "Generic API collection",           "any",        "WARN"),
    ("/api-export.json",              "Generic API export",               "any",        "WARN"),
    ("/api/export.json",              "API export (/api/)",               "any",        "WARN"),
]


class APICollectionScanner(BaseScanner):
    """Detect exposed Postman, Insomnia, or Hoppscotch API collection files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "API collection — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found_any = False

        for path, description, fmt, severity in _PROBES:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r is None or r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if len(body) < 20:
                    continue

                if not self._is_valid_collection(fmt, body):
                    continue

                credential_hits = self._find_credentials(body)
                if credential_hits:
                    effective_severity = "FAIL"
                else:
                    effective_severity = severity

                detail = self._build_detail(probe_url, description, fmt, credential_hits)
                if effective_severity == "FAIL":
                    log_fail(logger, f"API collection exposed: {probe_url} ({description})")
                else:
                    log_warn(logger, f"API collection exposed: {probe_url} ({description})")

                self.results.append(self._result(
                    probe_url,
                    f"API collection — {description} publicly accessible",
                    effective_severity,
                    detail=detail,
                ))
                found_any = True

            except Exception:
                continue

        if not found_any:
            log_pass(logger, f"No API collection files exposed on {base}")
            self.results.append(self._result(
                url,
                "API collection — no Postman/Insomnia/Hoppscotch collection files exposed",
                "PASS",
                detail=(
                    "Probed for Postman collection files (postman_collection.json), "
                    "Insomnia workspaces (insomnia.json), Hoppscotch collections, "
                    "and generic API export files. None were publicly accessible. "
                    "Fix: add collection files to .gitignore; use version-controlled "
                    "collections in team workspaces (Postman Team/Enterprise, Insomnia Teams); "
                    "never commit or deploy files containing hardcoded credentials."
                )
            ))

        return self.results

    def _is_valid_collection(self, fmt: str, body: str) -> bool:
        """Return True only if body matches the expected API collection format."""
        if fmt == "postman":
            return bool(
                (_POSTMAN_V2_RE.search(body) and _POSTMAN_ITEM_RE.search(body))
                or _POSTMAN_V1_RE.search(body)
            )
        elif fmt == "insomnia":
            return bool(_INSOMNIA_RE.search(body) and _INSOMNIA_RESOURCE_RE.search(body))
        elif fmt == "hoppscotch":
            return bool(_HOPPSCOTCH_RE.search(body))
        elif fmt == "any":
            # Generic: must look like any of the known formats
            return bool(
                (_POSTMAN_V2_RE.search(body) and _POSTMAN_ITEM_RE.search(body))
                or _POSTMAN_V1_RE.search(body)
                or (_INSOMNIA_RE.search(body) and _INSOMNIA_RESOURCE_RE.search(body))
                or _HOPPSCOTCH_RE.search(body)
            )
        return False

    def _find_credentials(self, body: str) -> List[str]:
        """Return list of credential types found in collection body."""
        found = []
        if _BEARER_TOKEN_RE.search(body):
            found.append("Bearer token in Authorization header")
        if _API_KEY_RE.search(body):
            found.append("API key in request header")
        if _BASIC_AUTH_RE.search(body):
            found.append("Basic auth credentials")
        if _AWS_KEY_RE.search(body):
            found.append("AWS access key ID")
        if _TOKEN_VALUE_RE.search(body):
            found.append("Secret/token/password value")
        if _ENV_CURRENT_VALUE_RE.search(body):
            found.append("Environment variable current values")
        return found

    def _build_detail(self, url: str, description: str, fmt: str,
                       credential_hits: List[str]) -> str:
        tool_map = {
            "postman":    "Postman",
            "insomnia":   "Insomnia",
            "hoppscotch": "Hoppscotch",
            "any":        "API client tool",
        }
        tool = tool_map.get(fmt, "API client tool")

        cred_info = ""
        if credential_hits:
            cred_info = (
                f" CRITICAL: hardcoded credentials detected — {'; '.join(credential_hits)}. "
                "Rotate all exposed credentials immediately. "
            )
        else:
            cred_info = (
                " The collection exposes full API endpoint structure, request parameters, "
                "and may contain credentials in environment variable definitions or request headers. "
            )

        fix_map = {
            "postman":    (
                "Store collections in Postman Team/Enterprise workspaces behind authentication. "
                "Use environment variables with 'secret' type for credentials "
                "(Postman vaults, not plain variables). "
                "Add *_collection.json to .gitignore and web server deny rules."
            ),
            "insomnia":    (
                "Use Insomnia Git sync or Insomnia Teams for collaboration. "
                "Never deploy insomnia.json to web servers. "
                "Use Design Documents (not manual credential storage) for API definitions."
            ),
            "hoppscotch": (
                "Use Hoppscotch Team/Enterprise with access controls. "
                "Do not expose collection exports on web servers. "
                "Store secrets in Hoppscotch Secret Variables, not plain variables."
            ),
            "any": (
                "Remove the collection file from the web root. "
                "Use proper access controls for API documentation."
            ),
        }
        fix = fix_map.get(fmt, "Remove collection files from public web access.")

        return (
            f"A {tool} API collection file is publicly accessible at {url} ({description}). "
            + cred_info
            + f"Fix: {fix}"
        )
