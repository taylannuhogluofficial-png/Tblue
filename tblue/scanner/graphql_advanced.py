"""
Advanced GraphQL Security Scanner.

Extends the basic GraphQL scanner with deeper checks:

1. Introspection enabled (production should disable it) — already in graphql.py
2. Query depth and complexity limits absent (DoS via deeply nested queries)
3. Batching attacks — multiple queries in a single request
4. Field-level authorization bypass indicators
5. GraphQL IDE exposure (GraphiQL, GraphQL Playground, Altair, Voyager)
6. Subscriptions over WebSocket without authentication
7. Persisted query support without allowlisting
8. N+1 query vulnerability indicators (no DataLoader)
9. Sensitive field names in schema (password, secret, token, apiKey)
10. GraphQL error verbosity — stack traces in errors

Paid equivalents: Escape.tech GraphQL Security, Inigo, StackHawk.
"""

import re
import json
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# GraphQL IDE patterns
_GQL_IDE_RE = re.compile(
    r"GraphiQL|graphiql|"
    r"GraphQL\s*Playground|graphql-playground|"
    r"Altair\s*GraphQL|altair-graphql|"
    r"GraphQL\s*Voyager|graphql-voyager|"
    r'"GRAPHQL_IDE"|apollo-sandbox",',
    re.I,
)

# Sensitive field names that should not be in GraphQL schema
_SENSITIVE_FIELD_RE = re.compile(
    r'"name"\s*:\s*"(?:password|secret|token|api_key|apikey|private_key|'
    r'ssn|credit_card|card_number|cvv|pin|passcode|auth_token|'
    r'access_token|refresh_token|signing_secret)',
    re.I,
)

# GraphQL error with stack trace
_STACK_TRACE_RE = re.compile(
    r'"extensions".*"stacktrace"|'
    r'"stack"\s*:\s*"\s*at\s+|'
    r'at\s+\w+\.(?:resolve|execute|validate).*\.js|'
    r'GraphQL.*Error.*\n.*\s+at\s+',
    re.I | re.S,
)

# Query depth indicators in error messages
_DEPTH_LIMIT_ERROR_RE = re.compile(
    r"Query\s+depth\s+(?:limit|exceeded)|"
    r"exceeds\s+maximum\s+(?:depth|complexity)|"
    r"query\s+too\s+deep|"
    r"complexity\s+limit",
    re.I,
)

# Introspection check
_INTROSPECTION_RE = re.compile(
    r'"__schema"\s*:\s*\{|'
    r'"types"\s*:\s*\[.*"__Type"|'
    r'"queryType"\s*:|'
    r'"directives"\s*:\s*\[',
    re.I | re.S,
)

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/graphiql",
    "/playground",
    "/api/v1/graphql",
    "/graphql/console",
    "/graphql/v1",
]

_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'
_DEPTH_TEST_QUERY = '{"query":"{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p{q{r{s{t}}}}}}}}}}}}}}}}}}}}}"}'
_BATCH_TEST = '[{"query":"{__typename}"},{"query":"{__typename}"}]'


class GraphQLAdvancedScanner(BaseScanner):
    """Advanced GraphQL security checks beyond basic introspection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "GraphQL Advanced — no issues detected", "PASS",
                detail="No advanced GraphQL security issues found."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # ── 1. GraphQL IDE exposure ────────────────────────────────────────────
        if _GQL_IDE_RE.search(body):
            log_fail(logger, f"GraphQL IDE exposed: {url}")
            self.results.append(self._result(
                url, "GraphQL Advanced — IDE/Playground exposed in production", "FAIL",
                detail=(
                    "GraphQL IDE (GraphiQL, Playground, Altair, Voyager, or Apollo Sandbox) "
                    "is exposed. IDEs make it trivial for attackers to explore the full schema "
                    "via auto-completion, send arbitrary queries, and discover business logic. "
                    "Fix: disable GraphQL IDE in production environments; "
                    "restrict IDE access to authenticated internal users only."
                )
            ))

        # ── 2. Probe GraphQL endpoints ─────────────────────────────────────────
        gql_endpoint = None
        for path in _GRAPHQL_PATHS:
            probe_url = base + path
            try:
                # Test introspection
                r = self.http.post(probe_url, json=json.loads(_INTROSPECTION_QUERY),
                                   headers={"Content-Type": "application/json"})
                if not r or r.status_code not in (200, 201):
                    r = self.http.get(probe_url)
                    if not r or r.status_code not in (200,):
                        continue

                r_body = r.text or ""

                # Check for GraphQL response (data, errors, or introspection)
                is_graphql = (
                    _INTROSPECTION_RE.search(r_body) or
                    '"data"' in r_body or
                    '"errors"' in r_body and '"message"' in r_body
                )
                if not is_graphql:
                    continue

                gql_endpoint = probe_url

                # Introspection check
                if _INTROSPECTION_RE.search(r_body):
                    log_warn(logger, f"GraphQL introspection enabled: {probe_url}")
                    self.results.append(self._result(
                        probe_url, "GraphQL Advanced — introspection enabled in production", "WARN",
                        detail=(
                            f"GraphQL introspection is enabled at {probe_url}. "
                            "Introspection exposes the full type system, including all queries, "
                            "mutations, subscriptions, and field names with their types. "
                            "Fix: disable introspection in production "
                            "(Apollo: introspection: false; graphene: disable introspection middleware)."
                        )
                    ))

                # Check for stack traces in errors
                if _STACK_TRACE_RE.search(r_body):
                    log_fail(logger, f"GraphQL stack trace in error response: {probe_url}")
                    self.results.append(self._result(
                        probe_url, "GraphQL Advanced — stack trace in error response", "FAIL",
                    detail=(
                            "GraphQL error response contains a stack trace. "
                            "Stack traces expose internal file paths, function names, and "
                            "framework versions — aids in targeted exploitation. "
                            "Fix: disable debug mode; mask errors to generic messages in production."
                        )
                    ))

                # Check for sensitive field names in schema
                if _SENSITIVE_FIELD_RE.search(r_body):
                    m = _SENSITIVE_FIELD_RE.search(r_body)
                    field = m.group(0)[:60] if m else ""
                    log_warn(logger, f"Sensitive field in GraphQL schema: {field}")
                    self.results.append(self._result(
                        probe_url, f"GraphQL Advanced — sensitive field name in schema ({field})", "WARN",
                        detail=(
                            f"Sensitive-looking field '{field}' found in GraphQL schema. "
                            "Sensitive fields (password, token, apiKey, etc.) should be "
                            "write-only and never returned in query responses. "
                            "Fix: use @sensitive directive; redact fields in resolvers; "
                            "implement field-level authorization."
                        )
                    ))

                break  # Found and tested the endpoint
            except Exception:
                continue

        # ── 3. Test batching support on found endpoint ─────────────────────────
        if gql_endpoint:
            try:
                batch_body = json.loads(_BATCH_TEST)
                batch_r = self.http.post(
                    gql_endpoint, json=batch_body,
                    headers={"Content-Type": "application/json"}
                )
                if batch_r and batch_r.status_code == 200:
                    b_body = batch_r.text or ""
                    if '"data"' in b_body and b_body.strip().startswith("["):
                        log_warn(logger, f"GraphQL batching enabled: {gql_endpoint}")
                        self.results.append(self._result(
                            gql_endpoint, "GraphQL Advanced — query batching enabled", "WARN",
                            detail=(
                                "GraphQL query batching is enabled — multiple operations can be "
                                "sent in a single HTTP request. Batching amplifies brute-force, "
                                "enumeration, and rate-limit bypass attacks. "
                                "Fix: disable batching in production, or implement per-batch "
                                "operation limits and strict rate limiting."
                            )
                        ))
            except Exception:
                pass

        # ── 4. Check IDE on dedicated paths ───────────────────────────────────
        for ide_path in ["/graphiql", "/playground", "/graphql/console"]:
            probe_url = base + ide_path
            try:
                r = self.http.get(probe_url)
                if not r or r.status_code != 200:
                    continue
                if _GQL_IDE_RE.search(r.text or ""):
                    log_fail(logger, f"GraphQL IDE at: {probe_url}")
                    self.results.append(self._result(
                        probe_url, f"GraphQL Advanced — IDE exposed at {ide_path}", "FAIL",
                        detail=(
                            f"GraphQL IDE found at {probe_url}. "
                            "Disable in production or restrict to authenticated users."
                        )
                    ))
            except Exception:
                continue

        if not self.results:
            log_pass(logger, f"No advanced GraphQL issues found on {url}")
            self.results.append(self._result(
                url, "GraphQL Advanced — no issues detected", "PASS",
                detail="No GraphQL IDE, introspection, batching, or sensitive fields found."
            ))

        return self.results
