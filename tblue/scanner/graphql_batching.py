"""
GraphQL Batching and Alias Abuse Scanner.

GraphQL supports two forms of query multiplication that attackers abuse:

1. **Query Batching** (array syntax):
   Send a JSON array of operations in a single HTTP request:
   [{"query": "..."}, {"query": "..."}, ...]
   If enabled without limits, attackers can send N authentication probes
   in a single request, bypassing per-request rate limits.

2. **Alias Multiplication** (alias syntax):
   Repeat a field under different aliases in a single query:
   { a1: login(user:"u1") a2: login(user:"u2") ... }
   This achieves the same effect without needing array batching.

Blue-team checks (read-only, passive):
1. Probe for batch support by sending [op, op] — check if both execute
2. Probe for alias multiplication — send multi-alias query, check response
3. Check for rate limiting headers on GraphQL endpoint (X-RateLimit-*)
4. Check for query complexity / depth limit headers or error messages

References:
  OWASP API Security: API4:2023 Unrestricted Resource Consumption
  CWE-799: Improper Control of Interaction Frequency
  Escape.tech "GraphQL Batching Attack"
  Adam Baso's "Bypassing GitHub's OAuth flow" (alias attack)
  https://lab.wallarm.com/graphql-batching-attack/
"""

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse


from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common GraphQL endpoint paths
_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/graphiql",
    "/graphql/v1",
    "/graphql/v2",
    "/api/v1/graphql",
    "/api/v2/graphql",
]

# Introspection probe to detect a live GraphQL endpoint
_INTROSPECTION_PROBE = {"query": "{ __typename }"}

# Batch probe — two identical introspection queries
_BATCH_PROBE = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

# Alias multiplication probe — 10 aliases of __typename
_ALIAS_COUNT = 10
_ALIAS_PROBE = {
    "query": "{ " + " ".join(f"a{i}: __typename" for i in range(_ALIAS_COUNT)) + " }"
}

# Rate-limit headers
_RATE_LIMIT_HEADERS = frozenset({
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
    "x-rate-limit",
})

# Patterns indicating the server enforced a limit
_LIMIT_ERROR_RE = re.compile(
    r"rate.?limit|too many requests|query complexity|depth limit|"
    r"query cost|alias limit|batching.?not.?allowed|batch.?disabled",
    re.I,
)


class GraphQLBatchingScanner(BaseScanner):
    """Detect GraphQL batching and alias abuse attack surfaces."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Discover GraphQL endpoints from the page
        endpoints = self._discover_endpoints(url, base)
        if not endpoints:
            log_pass(logger, f"No GraphQL endpoints found on {url}")
            self.results.append(self._result(
                url,
                "GraphQL batching — no GraphQL endpoint found",
                "PASS",
                detail="No GraphQL endpoint was detected. If the application uses GraphQL, "
                       "ensure it is not exposed at well-known paths.",
            ))
            return self.results

        for ep in endpoints:
            self._check_endpoint(ep)

        return self.results

    def _discover_endpoints(self, url: str, base: str) -> List[str]:
        """Find GraphQL endpoints from page source and known paths."""
        found = []

        # Check common paths
        for path in _GRAPHQL_PATHS:
            ep_url = base + path
            r = self.http.post(ep_url, json=_INTROSPECTION_PROBE)
            if r and r.status_code == 200 and '"data"' in (r.text or ""):
                found.append(ep_url)
                break  # one endpoint is enough for now

        # Also look at page source for graphql endpoint hints
        if not found:
            r = self.http.get(url)
            if r and r.text:
                body = r.text
                for path in _GRAPHQL_PATHS:
                    if path in body:
                        ep_url = base + path
                        r2 = self.http.post(ep_url, json=_INTROSPECTION_PROBE)
                        if r2 and r2.status_code == 200 and '"data"' in (r2.text or ""):
                            found.append(ep_url)
                            break

        return found

    def _check_endpoint(self, ep_url: str) -> None:
        """Check a live GraphQL endpoint for batching/alias abuse surface."""
        self._check_batching(ep_url)
        self._check_alias_multiplication(ep_url)
        self._check_rate_limit_headers(ep_url)

    def _check_batching(self, ep_url: str) -> None:
        """Test if the endpoint accepts array-format batch queries."""
        r = self.http.post(ep_url, json=_BATCH_PROBE)
        if r is None:
            return

        body = r.text or ""

        if _LIMIT_ERROR_RE.search(body):
            log_pass(logger, f"GraphQL batching: endpoint rejects batches at {ep_url}")
            self.results.append(self._result(
                ep_url,
                "GraphQL batching — batch queries enforced/blocked",
                "PASS",
                detail="The endpoint rejects array-format batch queries or enforces a limit. "
                       "This prevents attackers from multiplying requests to bypass rate limits.",
            ))
            return

        try:
            data = json.loads(body)
        except Exception:
            return

        if isinstance(data, list) and len(data) >= 2:
            # Both queries in the batch were executed
            both_have_data = all(
                isinstance(item, dict) and "data" in item
                for item in data
            )
            if both_have_data:
                log_fail(logger, f"GraphQL batching: endpoint allows unrestricted batching at {ep_url}")
                self.results.append(self._result(
                    ep_url,
                    "GraphQL batching — unrestricted batch queries enabled",
                    "FAIL",
                    method="POST",
                    detail=(
                        f"The GraphQL endpoint at {ep_url} accepts array-format batch queries "
                        "without enforcing any per-batch limit. Attackers can send N queries "
                        "in a single HTTP request, effectively multiplying their throughput "
                        "and bypassing per-request rate limits. This enables:\n"
                        "• Credential stuffing via batched login mutations\n"
                        "• Brute-forcing OTPs or tokens at N× speed\n"
                        "• Data exfiltration amplification\n"
                        "Fix: disable batching entirely, or enforce a maximum batch size "
                        "(1-5 operations) and apply rate limits per-query, not per-request. "
                        "Libraries: graphql-batch-limit (npm), graphene-django batching limits."
                    ),
                ))

    def _check_alias_multiplication(self, ep_url: str) -> None:
        """Test if the endpoint allows alias multiplication for rate limit bypass."""
        r = self.http.post(ep_url, json=_ALIAS_PROBE)
        if r is None:
            return

        body = r.text or ""

        if _LIMIT_ERROR_RE.search(body):
            log_pass(logger, f"GraphQL alias: endpoint limits aliases at {ep_url}")
            self.results.append(self._result(
                ep_url,
                "GraphQL batching — alias multiplication limited",
                "PASS",
                detail="The endpoint returns a rate limit or complexity error for "
                       f"{_ALIAS_COUNT}-alias queries. Alias abuse is mitigated.",
            ))
            return

        try:
            data = json.loads(body)
        except Exception:
            return

        if isinstance(data, dict) and "data" in data:
            response_data = data.get("data") or {}
            if isinstance(response_data, dict):
                alias_count_returned = sum(
                    1 for k in response_data if k.startswith("a") and k[1:].isdigit()
                )
                if alias_count_returned >= _ALIAS_COUNT:
                    log_warn(logger, f"GraphQL alias: endpoint allows {alias_count_returned} aliases at {ep_url}")
                    self.results.append(self._result(
                        ep_url,
                        f"GraphQL batching — alias multiplication ({alias_count_returned} aliases) allowed",
                        "WARN",
                        method="POST",
                        detail=(
                            f"The GraphQL endpoint at {ep_url} returns data for "
                            f"{alias_count_returned} aliased fields in a single query. "
                            "Alias multiplication allows an attacker to effectively execute "
                            "N requests in one HTTP round-trip, bypassing per-request rate limits. "
                            "For example: { a1: login(...) a2: login(...) a3: login(...) }\n"
                            "Fix: enforce query complexity limits or alias counting "
                            "(graphql-query-complexity npm package, or Nexus/Pothos field-level "
                            "complexity). Block or throttle queries with >5 aliases of mutable fields.",
                        ),
                    ))

    def _check_rate_limit_headers(self, ep_url: str) -> None:
        """Check whether rate limiting headers are present on the GraphQL endpoint."""
        r = self.http.post(ep_url, json=_INTROSPECTION_PROBE)
        if r is None:
            return

        hdrs = {k.lower(): v for k, v in (r.headers or {}).items()}
        found_limit = any(h in hdrs for h in _RATE_LIMIT_HEADERS)

        if found_limit:
            log_pass(logger, f"GraphQL rate limit headers present at {ep_url}")
            self.results.append(self._result(
                ep_url,
                "GraphQL batching — rate limit headers present",
                "PASS",
                detail="Rate-limiting headers (X-RateLimit-*, Retry-After) were detected on "
                       "the GraphQL endpoint. This indicates some form of rate limiting is active.",
            ))
        else:
            log_warn(logger, f"GraphQL rate limit headers absent at {ep_url}")
            self.results.append(self._result(
                ep_url,
                "GraphQL batching — no rate limit headers on endpoint",
                "WARN",
                detail=(
                    f"The GraphQL endpoint at {ep_url} does not return rate-limiting headers. "
                    "Without visible rate limiting, it may be possible to send unlimited queries. "
                    "Fix: apply rate limiting at the API gateway or application layer and expose "
                    "X-RateLimit-Limit / X-RateLimit-Remaining headers so clients can self-throttle.",
                ),
            ))
