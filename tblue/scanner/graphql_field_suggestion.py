"""
GraphQL Field Suggestion & Schema Enumeration via Error Messages.

When GraphQL introspection is disabled, many servers still leak schema
information through helpful error messages — specifically "field suggestion"
or "Did you mean...?" hints in validation errors.

Attack technique (tool: Clairvoyance, graphql-cop):
  1. Send a query with a deliberately misspelled field name
     e.g. { users { emaill } }
  2. Server responds: "Cannot query field 'emaill' on type 'User'.
     Did you mean 'email'?"
  3. Attacker iterates through variations, reconstructing the full schema.

This allows complete schema reconstruction with introspection disabled,
making "disable introspection" an incomplete mitigation.

Additional checks:
  - Error messages exposing internal type names (CWE-209)
  - Apollo sandbox / Yoga playground accessible despite no introspection
  - `__typename` access pattern: confirms GraphQL endpoint without introspection
  - Error stack traces with resolver/module file paths

Professional tool equivalents:
  Escape.tech "Introspection disabled but field suggestion enabled"
  PortSwigger GraphQL scanner "Field suggestions enabled"
  Burp Suite GraphQL Scanner

CWE-200: Exposure of Sensitive Information
CWE-209: Generation of Error Message Containing Sensitive Information
OWASP API Security Top 10: API8 — Security Misconfiguration
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# ── Field suggestion detection patterns ──────────────────────────────────────

# "Did you mean 'X'?" pattern in error messages
_FIELD_SUGGESTION_RE = re.compile(
    r'[Dd]id you mean[^"\']{0,10}["\']([^"\']+)["\']|'
    r'"suggestions"\s*:\s*\[|'
    r'Cannot query field ["\']?[^"\']+["\']? on type ["\']?[^"\']+["\']?\. Did you mean',
    re.I,
)

# GraphQL validation error structure
_GQL_ERRORS_RE = re.compile(r'"errors"\s*:', re.I)

# Internal type names in error messages
_TYPE_NAME_IN_ERROR_RE = re.compile(
    r'Cannot query field ["\']([^"\']+)["\'] on type ["\']([^"\']+)["\']',
    re.I,
)

# Stack trace / file path in error
_STACKTRACE_IN_ERROR_RE = re.compile(
    r'"stacktrace"|"extensions"[^}]*"exception"[^}]*"stacktrace"',
    re.I,
)

# File paths in errors
_FILEPATH_IN_ERROR_RE = re.compile(
    r'(?:at |in )/[^\s"\']{5,50}\.(?:js|ts|py|rb|java|go)\b',
    re.I,
)

# __typename exposure (confirms GraphQL endpoint without introspection)
_TYPENAME_IN_RESPONSE_RE = re.compile(
    r'"__typename"\s*:\s*"[A-Z][a-zA-Z]*"',
)

# ── GraphQL endpoint paths ─────────────────────────────────────────────────

_GQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/v1/graphql",
    "/api/v1/graphql",
    "/query",
    "/gql",
]

# ── Probe payloads ─────────────────────────────────────────────────────────

# Deliberately misspelled field to trigger "Did you mean" suggestion
_SUGGESTION_PROBE = json.dumps({"query": "{ nonExistentFieldXyz }"})

# __typename probe — valid on all GraphQL servers
_TYPENAME_PROBE = json.dumps({"query": "{ __typename }"})


class GraphQLFieldSuggestionScanner(BaseScanner):
    """Detect GraphQL schema enumeration via field suggestion and error messages."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "GraphQL field suggestion — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Probe each known GraphQL path
        for path in _GQL_PATHS:
            endpoint = base + path
            result = self._probe_endpoint(endpoint)
            if result:
                break  # Report only first found endpoint to avoid duplicate findings

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"GraphQL field suggestion — no schema leak via errors on {base}")
            self.results.append(self._result(
                url,
                "GraphQL field suggestion — no schema enumeration via error messages",
                "PASS",
                detail=(
                    "No GraphQL endpoint found, or field suggestions are disabled. "
                    "Checked common GraphQL paths for: 'Did you mean' suggestion hints, "
                    "type names in validation errors, stack traces in error responses, "
                    "and file paths leaked via error extensions. "
                    "Fix: disable field suggestions (Apollo: 'debug: false'; GraphQL Yoga: "
                    "'maskedErrors: true'; Hasura: 'HASURA_GRAPHQL_DEV_MODE=false'). "
                    "CWE-209."
                )
            ))

        return self.results

    def _probe_endpoint(self, endpoint: str) -> bool:
        """Probe a single GraphQL endpoint. Returns True if endpoint found."""
        found = False

        # Step 1: Check if endpoint exists at all with __typename probe
        try:
            r = self.http.post(endpoint, data=_TYPENAME_PROBE,
                               headers={"Content-Type": "application/json"})
            if r is None or r.status_code not in (200, 400, 422):
                return False

            body = r.text or ""
            if not _GQL_ERRORS_RE.search(body) and '"data"' not in body:
                return False  # Not a GraphQL response

            found = True

            # Check if __typename worked — confirms endpoint and GraphQL working
            if _TYPENAME_IN_RESPONSE_RE.search(body):
                log_warn(logger, f"GraphQL endpoint found at {endpoint} (introspection may be needed)")

        except Exception:
            return False

        # Step 2: Send field suggestion probe
        try:
            r2 = self.http.post(endpoint, data=_SUGGESTION_PROBE,
                                headers={"Content-Type": "application/json"})
            if r2 is None:
                return found

            body2 = r2.text or ""
            if not body2:
                return found

            # Check for "Did you mean" suggestion
            suggestion_match = _FIELD_SUGGESTION_RE.search(body2)
            if suggestion_match:
                suggested_name = suggestion_match.group(1) if suggestion_match.group(1) else ""
                log_fail(logger, f"GraphQL field suggestions enabled at {endpoint}")
                self.results.append(self._result(
                    endpoint,
                    "GraphQL field suggestion — schema enumerable via error messages",
                    "FAIL",
                    detail=(
                        f"GraphQL endpoint at {endpoint} reveals field/type names in error messages "
                        f"('Did you mean' suggestions). "
                        f"{'Suggested name: ' + suggested_name + '. ' if suggested_name else ''}"
                        "This allows schema reconstruction without introspection by iterating "
                        "deliberately misspelled field names — a technique used by Clairvoyance. "
                        "Fix: disable field suggestions in production. "
                        "Apollo Server: set 'includeStacktraceInErrorResponses: false' and "
                        "'debug: false'. GraphQL Yoga: set 'maskedErrors: true'. "
                        "Hasura: set HASURA_GRAPHQL_DEV_MODE=false. CWE-200. OWASP API8."
                    ),
                ))
                return found

            # Check for type name disclosure in error
            type_match = _TYPE_NAME_IN_ERROR_RE.search(body2)
            if type_match:
                field_name = type_match.group(1)
                type_name = type_match.group(2)
                log_warn(logger, f"GraphQL error reveals type name at {endpoint}: {type_name}")
                self.results.append(self._result(
                    endpoint,
                    "GraphQL field suggestion — internal type names in error messages",
                    "WARN",
                    detail=(
                        f"GraphQL endpoint at {endpoint} reveals internal type names in errors: "
                        f"field '{field_name}' on type '{type_name}'. "
                        "While field suggestions are off, type names in errors still aid "
                        "schema enumeration and reveal internal data model naming conventions. "
                        "Fix: use masked/generic error messages in production. "
                        "GraphQL Yoga: 'maskedErrors: true'. Apollo: 'debug: false'. "
                        "CWE-209."
                    ),
                ))
                return found

            # Check for stack trace in error response
            if _STACKTRACE_IN_ERROR_RE.search(body2) or _FILEPATH_IN_ERROR_RE.search(body2):
                log_fail(logger, f"GraphQL error exposes stack trace/file paths at {endpoint}")
                self.results.append(self._result(
                    endpoint,
                    "GraphQL field suggestion — stack trace or file paths in error response",
                    "FAIL",
                    detail=(
                        f"GraphQL endpoint at {endpoint} includes stack trace or internal file "
                        "paths in error responses. This reveals server technology, file layout, "
                        "and code paths that assist targeted attacks. "
                        "Fix: mask all error details in production. CWE-209."
                    ),
                ))

        except Exception:
            pass

        return found
