"""
GraphQL Batch Attack & Alias Flooding Scanner.

Detects GraphQL endpoint misconfigurations that allow:
1. Query batching (array of operations in one request) — bypasses rate limiting
2. Alias flooding (N aliases of the same expensive query) — CPU/memory DoS
3. GraphQL IDE (GraphiQL / Apollo Sandbox) exposed in production
4. GET-based query execution (enables CSRF on GraphQL)
5. Introspection available without authentication
"""

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_GQL_PATHS = ["/graphql", "/api/graphql", "/query", "/gql", "/v1/graphql"]

_GRAPHQL_ERROR_RE = re.compile(r'"errors"\s*:\s*\[', re.I)
_GRAPHQL_DATA_RE  = re.compile(r'"data"\s*:', re.I)
_IDE_SIGNALS = ("graphiql", "apollo studio", "playground", "graphql explorer", "altair")

_BATCH_BODY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

_ALIAS_BODY = json.dumps({
    "query": (
        "{ "
        + " ".join(f"a{i}: __typename" for i in range(10))
        + " }"
    )
})

_INTROSPECTION_BODY = json.dumps({
    "query": "{ __schema { queryType { name } } }"
})

_CSRF_INTROSPECTION = "query=%7B+__typename+%7D"


class GraphQLBatchAttackScanner(BaseScanner):
    """Detect GraphQL batch attack, alias flooding, IDE exposure, and CSRF risks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        gql_url = self._find_graphql(origin)
        if gql_url is None:
            log_pass(logger, f"No GraphQL endpoint found at {url}")
            self.results.append(self._result(
                url, "GraphQL batch — no GraphQL endpoint found", "PASS",
                detail="No GraphQL endpoint detected on common paths."
            ))
            return self.results

        self._check_batching(gql_url)
        self._check_alias_flooding(gql_url)
        self._check_ide_exposure(origin, gql_url)
        self._check_get_execution(gql_url)
        self._check_introspection(gql_url)

        if not self.results:
            log_pass(logger, f"GraphQL endpoint at {gql_url} has no batch attack risks")
            self.results.append(self._result(
                gql_url, "GraphQL batch — no batch attack misconfigurations", "PASS",
                detail="GraphQL endpoint does not appear to allow batching, alias flooding, or IDE access."
            ))

        return self.results

    def _find_graphql(self, origin: str):
        for path in _GQL_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp.status_code in (200, 400, 405) and (
                    _GRAPHQL_ERROR_RE.search(resp.text) or
                    _GRAPHQL_DATA_RE.search(resp.text) or
                    "graphql" in resp.headers.get("content-type", "").lower()
                ):
                    return origin + path
                resp2 = self.http.get(
                    origin + path,
                    headers={"Content-Type": "application/json"},
                )
                if resp2.status_code in (200, 400) and (
                    _GRAPHQL_ERROR_RE.search(resp2.text) or
                    _GRAPHQL_DATA_RE.search(resp2.text)
                ):
                    return origin + path
            except Exception:
                continue
        return None

    def _check_batching(self, gql_url: str) -> None:
        try:
            resp = self.http.get(
                gql_url,
                headers={"Content-Type": "application/json"},
                data=_BATCH_BODY,
            )
            if resp.status_code == 200 and resp.text.strip().startswith("["):
                log_warn(logger, f"GraphQL batching enabled at {gql_url}")
                self.results.append(self._result(
                    gql_url, "GraphQL — query batching enabled", "WARN",
                    detail=(
                        "The GraphQL endpoint accepts batched queries (array of operations). "
                        "Batching allows an attacker to bundle hundreds of auth probes into a "
                        "single HTTP request, bypassing per-request rate limiting. "
                        "Fix: disable or limit batch size in the GraphQL server configuration; "
                        "implement per-operation rate limiting rather than per-request only."
                    )
                ))
        except Exception:
            pass

    def _check_alias_flooding(self, gql_url: str) -> None:
        try:
            resp = self.http.get(
                gql_url,
                headers={"Content-Type": "application/json"},
                data=_ALIAS_BODY,
            )
            if resp.status_code == 200 and _GRAPHQL_DATA_RE.search(resp.text):
                aliases_in_resp = resp.text.count('"a')
                if aliases_in_resp >= 5:
                    log_warn(logger, f"GraphQL alias flooding possible at {gql_url}")
                    self.results.append(self._result(
                        gql_url, "GraphQL — alias flooding (no complexity limit)", "WARN",
                        detail=(
                            "The GraphQL endpoint returned results for 10 aliased field requests "
                            "in a single query with no apparent complexity or depth limit. "
                            "Alias flooding allows DoS by multiplying resolver cost N times. "
                            "Fix: implement a query complexity limit (e.g., graphql-query-complexity); "
                            "enforce per-query alias count limits."
                        )
                    ))
        except Exception:
            pass

    def _check_ide_exposure(self, origin: str, gql_url: str) -> None:
        ide_paths = [
            gql_url,
            origin + "/graphiql",
            origin + "/api/graphiql",
            origin + "/playground",
            origin + "/studio",
        ]
        for path in ide_paths:
            try:
                resp = self.http.get(path, headers={"Accept": "text/html"})
                body_lower = resp.text.lower()
                if resp.status_code == 200 and any(sig in body_lower for sig in _IDE_SIGNALS):
                    log_fail(logger, f"GraphQL IDE exposed at {path}")
                    self.results.append(self._result(
                        path, "GraphQL — IDE exposed in production", "FAIL",
                        detail=(
                            f"A GraphQL IDE (GraphiQL, Apollo Sandbox, or Playground) is accessible "
                            f"at {path}. This gives attackers a fully interactive query interface "
                            "for exploring the API, running mutations, and enumerating schema. "
                            "Fix: disable GraphQL IDE in production environments; "
                            "restrict to localhost or authenticated admin users only."
                        )
                    ))
                    return
            except Exception:
                continue

    def _check_get_execution(self, gql_url: str) -> None:
        try:
            resp = self.http.get(
                gql_url + "?" + _CSRF_INTROSPECTION,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200 and _GRAPHQL_DATA_RE.search(resp.text):
                log_warn(logger, f"GraphQL GET query execution enabled at {gql_url}")
                self.results.append(self._result(
                    gql_url + "?" + _CSRF_INTROSPECTION,
                    "GraphQL — GET query execution (CSRF risk)", "WARN",
                    detail=(
                        "The GraphQL endpoint executes queries submitted via HTTP GET. "
                        "GET-based GraphQL enables CSRF attacks against mutation operations "
                        "using simple image tags or link prefetching. "
                        "Fix: require POST for all mutation operations; "
                        "enforce Content-Type: application/json (rejects simple-request CSRF)."
                    )
                ))
        except Exception:
            pass

    def _check_introspection(self, gql_url: str) -> None:
        try:
            resp = self.http.get(
                gql_url,
                headers={"Content-Type": "application/json"},
                data=_INTROSPECTION_BODY,
            )
            if resp.status_code == 200 and '"queryType"' in resp.text:
                log_warn(logger, f"GraphQL introspection enabled at {gql_url}")
                self.results.append(self._result(
                    gql_url, "GraphQL — introspection enabled", "WARN",
                    detail=(
                        "GraphQL introspection is enabled, exposing the full schema "
                        "(all types, fields, queries, mutations, and subscriptions) without "
                        "authentication. Introspection provides attackers a complete API blueprint. "
                        "Fix: disable introspection in production "
                        "(graphql-disable-introspection, Apollo Server: introspection: false)."
                    )
                ))
        except Exception:
            pass
