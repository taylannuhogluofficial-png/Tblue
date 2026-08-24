"""
GraphQL security scanner for Tblue.

Probes common GraphQL endpoints for:
- Introspection enabled in production (leaks full schema)
- Developer playground/IDE exposed (GraphiQL, Apollo Studio)
- Query batching enabled (DoS amplification / rate-limit bypass risk)
"""

import json
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/gql", "/graph", "/graphql/v1", "/api/v1/graphql",
    "/graphiql", "/playground", "/api/graphiql",
]

_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}types{name kind}}}"}
_BATCH_QUERY         = [{"query": "{__typename}"}, {"query": "{__typename}"}]

_INTROSPECTION_MARKERS = ("__schema", "queryType", "mutationType")

_PLAYGROUND_MARKERS = (
    "graphiql", "apollo studio", "graphql playground",
    "graphql-playground", "__graphql__", "graphql ide",
    "graphql explorer", "altair graphql",
)


class GraphQLScanner(BaseScanner):
    """
    Discovers GraphQL endpoints and checks their security configuration.
    Reports PASS only when no endpoint is found (clean result).
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        base = _base_url(url)
        found_any = False

        for path in _GRAPHQL_PATHS:
            endpoint = urljoin(base, path)
            if self._probe_endpoint(url, endpoint):
                found_any = True

        if not found_any:
            log_pass(logger, f"No GraphQL endpoints found — {url}")
            self.results.append(self._result(
                url, "GraphQL — no endpoint detected", "PASS",
                detail="No GraphQL endpoints found at common paths."
            ))

        return self.results

    def _probe_endpoint(self, origin_url: str, endpoint: str) -> bool:
        """Test one candidate endpoint. Returns True if GraphQL was detected."""

        # ── GET: look for playground HTML ────────────────────────────────────
        get_resp = self.http.get(endpoint, allow_redirects=True)
        if get_resp and get_resp.status_code == 200:
            body_lower = (get_resp.text or "").lower()
            if any(m in body_lower for m in _PLAYGROUND_MARKERS):
                log_warn(logger, f"GraphQL playground exposed at {endpoint}")
                self.results.append(self._result(
                    endpoint, "GraphQL — playground/IDE exposed in production", "WARN",
                    detail=(
                        f"A GraphQL developer playground (GraphiQL / Apollo Studio) is accessible "
                        f"at {endpoint}. It exposes your schema and allows arbitrary queries. "
                        "Fix: disable the playground in production. In Apollo Server: "
                        "set NODE_ENV=production or pass playground: false to ApolloServer."
                    )
                ))
                return True

        # ── POST: probe introspection ─────────────────────────────────────────
        post_resp = self.http.post(
            endpoint,
            json=_INTROSPECTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if not post_resp or post_resp.status_code not in (200, 201):
            return False

        body = post_resp.text or ""
        if not any(m in body for m in _INTROSPECTION_MARKERS):
            return False

        # GraphQL confirmed — introspection is on
        has_mutations = "mutationType" in body
        log_fail(logger, f"GraphQL introspection enabled at {endpoint}")
        self.results.append(self._result(
            endpoint, "GraphQL — introspection enabled", "FAIL",
            detail=(
                f"GraphQL introspection is enabled at {endpoint}. "
                "This exposes your entire API schema — all types, fields, queries"
                + (", and mutations" if has_mutations else "")
                + " — to any unauthenticated visitor. "
                "Attackers use introspection to map your data model before targeted attacks. "
                "Fix: disable introspection in production. "
                "Apollo Server: introspection: process.env.NODE_ENV !== 'production'. "
                "Graphene (Python): schema = graphene.Schema(..., auto_camelcase=False) "
                "and set GRAPHQL_INTROSPECTION=false."
            )
        ))

        # ── POST: check batch query support ───────────────────────────────────
        batch_resp = self.http.post(
            endpoint,
            json=_BATCH_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if batch_resp and batch_resp.status_code == 200:
            try:
                parsed = json.loads(batch_resp.text or "[]")
                if isinstance(parsed, list) and len(parsed) > 1:
                    log_warn(logger, f"GraphQL batching enabled at {endpoint}")
                    self.results.append(self._result(
                        endpoint, "GraphQL — query batching enabled", "WARN",
                        detail=(
                            f"GraphQL batch queries are accepted at {endpoint}. "
                            "Batching allows many queries in a single HTTP request — "
                            "attackers use this to amplify DoS attacks or bypass per-request rate limits. "
                            "Fix: disable batching in your GraphQL server, or implement "
                            "per-query depth and complexity limits."
                        )
                    ))
            except Exception:
                pass

        return True


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
