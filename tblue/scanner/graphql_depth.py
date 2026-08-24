"""
GraphQL Depth & Complexity Limiting Scanner.

Without query depth limits, GraphQL APIs are vulnerable to:

1. Deeply nested query DoS (e.g. friends { friends { friends {...} } })
2. Query complexity attacks (requesting many expensive fields at once)
3. Alias-based field duplication amplification

These attacks can exhaust CPU/memory on the server with a single request.
This scanner sends progressively deeper introspection-style queries
and measures whether the server enforces a limit.

Note: This scanner sends harmless, read-only GraphQL queries.
No mutation or data-modification attempts are made.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

_GRAPHQL_RESPONSE_RE = re.compile(
    r'"data"\s*:|"errors"\s*:\s*\[',
    re.I,
)

_DEPTH_ERROR_RE = re.compile(
    r"max.*depth|depth.*limit|query.*too.*deep|complexity.*limit|"
    r"max.*complexity|query.*cost|rate.*limit.*query",
    re.I,
)

_TIMEOUT_ERROR_RE = re.compile(
    r"timeout|timed out|query.*exceeded|execution.*time",
    re.I,
)

# A deep nested query (12 levels) using __typename — completely safe, read-only
def _build_deep_query(depth: int) -> str:
    """Build a nested query 'depth' levels deep using __typename."""
    inner = "__typename"
    # Build a deeply nested query using a self-referential pattern
    # This uses a fragment-based approach to create depth
    query = '{ __typename ' + ('... on Query { __typename ' * depth) + inner + (' }' * depth) + ' }'
    return query


# Simpler approach: alias duplication (amplification)
def _build_alias_query(count: int) -> str:
    """Build a query with 'count' aliases of __typename (amplification attack)."""
    aliases = " ".join(f"f{i}: __typename" for i in range(count))
    return "{ " + aliases + " }"


# Direct depth-testing query using the __schema introspection hierarchy
_DEEP_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      fields {
        type {
          fields {
            type {
              fields {
                type {
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}
"""

_DEEP_QUERY_8 = """
{
  __typename
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          fields {
            name
            type {
              name
              fields {
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


class GraphQLDepthScanner(BaseScanner):
    """Detects absence of depth/complexity limiting on GraphQL endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping GraphQL depth checks: {url}")
            self.results.append(self._result(
                url, "GraphQL depth limiting — no response", "PASS",
                detail="Target did not respond; GraphQL depth checks skipped."
            ))
            return self.results

        # ── Find GraphQL endpoint ─────────────────────────────────────────────
        gql_endpoint = self._find_graphql_endpoint(url)
        if not gql_endpoint:
            log_pass(logger, f"No GraphQL endpoint found on {url}")
            self.results.append(self._result(
                url, "GraphQL depth limiting — no endpoint detected", "PASS",
                detail="No GraphQL endpoint found at common paths."
            ))
            return self.results

        # ── Test 1: Deep introspection query ──────────────────────────────────
        deep_resp = self.http.post(
            gql_endpoint,
            json={"query": _DEEP_QUERY_8}
        )
        if deep_resp is not None:
            body = deep_resp.text or ""
            if _GRAPHQL_RESPONSE_RE.search(body):
                if _DEPTH_ERROR_RE.search(body):
                    log_pass(logger, f"GraphQL depth limit enforced at {gql_endpoint}")
                    self.results.append(self._result(
                        gql_endpoint, "GraphQL depth limiting — enforced", "PASS",
                        detail="Server rejected the deep query with a depth/complexity error."
                    ))
                else:
                    log_fail(logger, f"GraphQL deep query accepted without limit: {gql_endpoint}")
                    self.results.append(self._result(
                        gql_endpoint, "GraphQL depth limiting — deep query accepted without limit", "FAIL",
                        detail=(
                            f"An 8-level deep introspection query was accepted at {gql_endpoint} "
                            "without any depth limit error. "
                            "Without query depth limits, an attacker can craft exponentially nested "
                            "queries that exhaust server CPU/memory (GraphQL DoS). "
                            "Fix: implement query depth limiting (max 5-7 levels) using "
                            "graphql-depth-limit (Node.js), graphene-django query limits (Python), "
                            "or equivalent. Also implement query complexity scoring."
                        )
                    ))

        # ── Test 2: Alias amplification ───────────────────────────────────────
        alias_resp = self.http.post(
            gql_endpoint,
            json={"query": _build_alias_query(100)}
        )
        if alias_resp is not None:
            body = alias_resp.text or ""
            if _GRAPHQL_RESPONSE_RE.search(body) and "f99" in body:
                log_warn(logger, f"GraphQL alias amplification accepted (100 aliases): {gql_endpoint}")
                self.results.append(self._result(
                    gql_endpoint, "GraphQL alias amplification — no field count limit", "WARN",
                    detail=(
                        f"A query with 100 aliased fields was accepted at {gql_endpoint}. "
                        "Alias amplification can multiply the work for expensive resolvers. "
                        "Fix: implement query complexity scoring that counts aliases; "
                        "reject queries above a complexity threshold (e.g. 1000)."
                    )
                ))

        if not self.results:
            log_pass(logger, f"No GraphQL depth/complexity issues found on {url}")
            self.results.append(self._result(
                url, "GraphQL depth limiting — no issues detected", "PASS",
                detail="No GraphQL endpoint found or depth limits appear to be enforced."
            ))

        return self.results

    def _find_graphql_endpoint(self, url: str) -> Optional[str]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _GRAPHQL_PATHS:
            probe = base + path
            r = self.http.post(probe, json={"query": "{ __typename }"})
            if r is None:
                continue
            body = r.text or ""
            if _GRAPHQL_RESPONSE_RE.search(body):
                return probe
        return None
