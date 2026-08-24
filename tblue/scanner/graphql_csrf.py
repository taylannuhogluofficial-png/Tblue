"""GraphQL CSRF — mutations via GET, no CSRF token enforcement, form-urlencoded content-type accepted."""
import re
from urllib.parse import urlparse, urlencode
from .base import BaseScanner

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"]

_MUTATION_QUERY = "mutation { __typename }"
_INTROSPECTION_QUERY = "{ __typename }"

_GQL_RESPONSE_RE = re.compile(r'"data"\s*:', re.I)
_GQL_TYPENAME_RE = re.compile(r'"__typename"', re.I)
_GQL_ERROR_RE = re.compile(r'"errors"\s*:', re.I)


def _is_graphql_response(text: str) -> bool:
    return bool(_GQL_RESPONSE_RE.search(text) or _GQL_ERROR_RE.search(text))


def _check_get_mutation(http, gql_url: str) -> list:
    """Check if GraphQL accepts mutations via GET (CSRF vector)."""
    findings = []
    try:
        resp = http.get(gql_url, params={"query": _MUTATION_QUERY})
        if resp and resp.status_code == 200 and _is_graphql_response(resp.text or ""):
            findings.append({
                "type": "graphql_csrf_get_mutation",
                "status": "FAIL",
                "url": gql_url,
                "detail": (f"GraphQL endpoint at {gql_url} accepts mutations via GET — "
                           f"enables CSRF attacks using simple GET requests from any origin"),
            })
    except Exception:
        pass
    return findings


def _check_form_urlencoded(http, gql_url: str) -> list:
    """Check if GraphQL accepts application/x-www-form-urlencoded (CSRF without preflight)."""
    findings = []
    try:
        body = urlencode({"query": _INTROSPECTION_QUERY})
        resp = http.get(gql_url, data=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        if resp and resp.status_code == 200 and _is_graphql_response(resp.text or ""):
            findings.append({
                "type": "graphql_csrf_form_urlencoded",
                "status": "WARN",
                "url": gql_url,
                "detail": (f"GraphQL at {gql_url} responds to application/x-www-form-urlencoded — "
                           f"this content-type doesn't trigger CORS preflight, enabling form-based CSRF"),
            })
    except Exception:
        pass
    return findings


def _check_missing_csrf_header(http, gql_url: str) -> list:
    """Check if GraphQL endpoint enforces a custom CSRF header (X-Requested-With, etc.)."""
    findings = []
    try:
        resp = http.get(gql_url,
                        data='{"query":"{ __typename }"}',
                        headers={"Content-Type": "application/json"})
        if resp and resp.status_code == 200 and _is_graphql_response(resp.text or ""):
            findings.append({
                "type": "graphql_csrf_no_header_check",
                "status": "WARN",
                "url": gql_url,
                "detail": (f"GraphQL at {gql_url} responds to JSON POST without CSRF token or "
                           f"X-Requested-With header — pair with CORS audit to assess exposure"),
            })
    except Exception:
        pass
    return findings


class GraphQLCSRFScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        gql_url = None
        for path in _GRAPHQL_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp and resp.status_code in (200, 400, 405):
                    body = resp.text or ""
                    if _is_graphql_response(body) or "graphql" in body.lower():
                        gql_url = origin + path
                        break
            except Exception:
                continue

        if gql_url is None:
            return [self._result(url, "graphql_csrf_no_endpoint", "PASS",
                                 detail="No GraphQL endpoint found at common paths")]

        for f in _check_get_mutation(self.http, gql_url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_form_urlencoded(self.http, gql_url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_missing_csrf_header(self.http, gql_url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(gql_url, "graphql_csrf_protected", "PASS",
                                        detail="GraphQL endpoint found but no CSRF weaknesses detected"))
        return results
