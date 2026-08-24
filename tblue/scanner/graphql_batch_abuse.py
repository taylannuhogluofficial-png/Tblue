"""
GraphQL Batch Abuse Scanner.

GraphQL's batching feature allows multiple operations in a single HTTP request.
While efficient, it enables rate limit bypass and brute force amplification:

  1. Array batching — sending [{query: "..."}, {query: "..."}] allows an
     attacker to send N operations per rate-limited HTTP request.

  2. Alias batching — using GraphQL aliases to run the same mutation N times
     in one request: { a: login(pass:"p1") b: login(pass:"p2") ... }.

  3. No query complexity limit — deeply nested or wide queries cause server
     resource exhaustion without batching.

  4. Introspection still enabled in production — combined with batching,
     introspection accelerates reconnaissance.

  5. Batch size not limited — server accepts arrays of arbitrary length.

Read-only: sends benign batch probes to the GraphQL endpoint.

CWE-770: Allocation of Resources Without Limits or Throttling
CWE-307: Improper Restriction of Excessive Authentication Attempts
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]

_INTROSPECTION_QUERY = '{ __typename }'
_BATCH_PAYLOAD = json.dumps([
    {"query": _INTROSPECTION_QUERY},
    {"query": _INTROSPECTION_QUERY},
    {"query": _INTROSPECTION_QUERY},
])

_ALIAS_PAYLOAD = json.dumps({
    "query": "{ a: __typename b: __typename c: __typename d: __typename e: __typename }"
})


def _find_graphql_endpoint(http, base_origin: str) -> Optional[str]:
    for path in _GRAPHQL_PATHS:
        url = base_origin + path
        resp = http.get(url)
        if resp and resp.status_code not in (404, 410):
            return url
    return None


def _check_array_batching(http, gql_url: str) -> Optional[Dict]:
    resp = http.get(gql_url, headers={"Content-Type": "application/json"})
    if resp is None:
        return None

    # POST the batch (passive-ish: benign __typename queries)
    post_resp = getattr(http, "post", None)
    if post_resp is None:
        return None
    try:
        r = http.post(gql_url, data=_BATCH_PAYLOAD,
                      headers={"Content-Type": "application/json"})
    except Exception:
        return None

    if r is None:
        return None

    try:
        body = r.text or ""
        if body.startswith("[") and "__typename" in body:
            parsed = json.loads(body)
            if isinstance(parsed, list) and len(parsed) >= 3:
                return {
                    "type": "graphql-batch-array-batching-accepted",
                    "status": "WARN",
                    "detail": (
                        f"GraphQL endpoint at {gql_url} accepts array batching "
                        f"({len(parsed)} operations returned).\n\n"
                        f"Array batching allows an attacker to send N operations per "
                        f"rate-limited HTTP request. Credential stuffing with 100 "
                        f"operations per request bypasses a rate limit of 1 req/s by 100×.\n\n"
                        f"Fix: disable or limit GraphQL batching. Set a maximum batch "
                        f"size of 1-5 operations. Apply rate limiting per-operation, "
                        f"not per-HTTP-request."
                    ),
                }
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def _check_alias_batching(http, gql_url: str) -> Optional[Dict]:
    try:
        r = http.post(gql_url, data=_ALIAS_PAYLOAD,
                      headers={"Content-Type": "application/json"})
    except Exception:
        return None

    if r is None:
        return None

    try:
        body = r.text or ""
        parsed = json.loads(body)
        data = parsed.get("data", {})
        if isinstance(data, dict) and len(data) >= 5 and all(
                v == "Query" or v is not None for v in data.values()):
            return {
                "type": "graphql-batch-alias-batching-accepted",
                "status": "WARN",
                "detail": (
                    f"GraphQL endpoint at {gql_url} accepts alias batching "
                    f"({len(data)} aliases returned in one request).\n\n"
                    f"Alias batching allows an attacker to call the same mutation "
                    f"(e.g., login) multiple times in one HTTP request, bypassing "
                    f"per-request rate limits.\n\n"
                    f"Fix: implement query complexity analysis and alias counting. "
                    f"Limit aliases per field to a small number (e.g., 3-5)."
                ),
            }
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return None


class GraphQLBatchAbuseScanner(BaseScanner):
    """Checks GraphQL endpoints for array batching and alias batching abuse potential."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "GraphQL Batch Abuse — target unreachable", "PASS",
                detail="No response; GraphQL batch abuse check skipped."))
            return self.results

        gql_url = _find_graphql_endpoint(self.http, base_origin)
        if not gql_url:
            log_pass(logger, f"GraphQL Batch Abuse — no GraphQL endpoint at {url}")
            self.results.append(self._result(
                url, "GraphQL Batch Abuse — no GraphQL endpoint detected", "PASS",
                detail="No GraphQL endpoint found at standard paths."))
            return self.results

        found = False
        seen_types: set = set()

        for check_fn in [_check_array_batching, _check_alias_batching]:
            f = check_fn(self.http, gql_url)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"GraphQL Batch Abuse — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"GraphQL Batch Abuse — no batch abuse indicators at {url}")
            self.results.append(self._result(
                url, "GraphQL Batch Abuse — no GraphQL batch abuse detected", "PASS",
                detail="GraphQL endpoint found but batching appears limited or not supported."))

        return self.results
