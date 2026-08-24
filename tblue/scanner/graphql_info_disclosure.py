"""GraphQL information disclosure — __typename, error messages, schema exposure via errors."""
import re
import json
from urllib.parse import urlparse
from .base import BaseScanner

_GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]

_FIELD_SUGGESTION_RE = re.compile(
    r'"message"\s*:\s*"[^"]*(?:Did you mean|Cannot query field|Unknown field|'
    r'Unknown argument|Unknown type)[^"]*"',
    re.I,
)
_STACK_TRACE_IN_GQL_RE = re.compile(
    r'"extensions"\s*:\s*\{[^}]*"exception"\s*:\s*\{[^}]*"stacktrace"',
    re.I | re.S,
)
_VERSION_IN_ERRORS_RE = re.compile(
    r'"extensions"\s*:\s*\{[^}]*"code"\s*:\s*"GRAPHQL_VALIDATION_FAILED"',
    re.I,
)


def _probe_introspection_errors(http, gql_url: str) -> list:
    """Send a malformed query to elicit schema-leaking error messages."""
    findings = []
    payload = '{"query": "{ nonExistentField_tbl9z7x }"}'
    try:
        resp = http.post(gql_url, data=payload,
                         headers={"Content-Type": "application/json"})
        if resp is None or resp.status_code not in (200, 400):
            return findings
        body = resp.text
        if _FIELD_SUGGESTION_RE.search(body):
            findings.append({
                "type": "graphql_field_suggestion_disclosure",
                "status": "WARN",
                "url": gql_url,
                "detail": "GraphQL leaks schema via 'Did you mean' field suggestions in errors",
            })
        if _STACK_TRACE_IN_GQL_RE.search(body):
            findings.append({
                "type": "graphql_stack_trace_in_errors",
                "status": "FAIL",
                "url": gql_url,
                "detail": "GraphQL error response contains server-side stack trace",
            })
    except Exception:
        pass
    return findings


def _probe_typename_exposure(http, gql_url: str) -> list:
    """Check if __typename is exposed without authentication."""
    findings = []
    payload = '{"query": "{ __typename }"}'
    try:
        resp = http.post(gql_url, data=payload,
                         headers={"Content-Type": "application/json"})
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if data.get("data", {}).get("__typename"):
                    findings.append({
                        "type": "graphql_typename_exposed",
                        "status": "WARN",
                        "url": gql_url,
                        "detail": "GraphQL __typename accessible without authentication — "
                                  "confirms endpoint existence and type system access",
                    })
            except (json.JSONDecodeError, AttributeError):
                pass
    except Exception:
        pass
    return findings


class GraphQLInfoDisclosureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "graphql_info_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _GQL_PATHS:
            gql_url = origin + path
            for f in _probe_introspection_errors(self.http, gql_url):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))
            for f in _probe_typename_exposure(self.http, gql_url):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))

        if not results:
            results.append(self._result(url, "graphql_info_clean", "PASS",
                                        detail="No GraphQL information disclosure detected"))
        return results
