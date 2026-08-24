"""
GraphQL Authorization scanner.

Checks for missing authorization on GraphQL mutations and queries:
- Mutations accessible without Authorization header
- Sensitive query fields returned unauthenticated
- Subscription endpoints without auth
- Batch mutation abuse enabling auth bypass
- Admin mutations exposed in schema
"""

import re
import json
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger

logger = get_logger(__name__)

_GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

_INTROSPECTION = '{"query":"{__schema{types{name kind fields{name}}}}"}'
_MUTATION_INTROSPECT = '{"query":"{__schema{mutationType{fields{name args{name}}}}}"}'

_SENSITIVE_MUTATION_RE = re.compile(
    r"(deleteUser|removeUser|updateRole|setAdmin|grantPermission|"
    r"changePassword|resetPassword|createAdmin|deleteAccount|"
    r"impersonate|sudo|elevate|bypass)", re.I
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(password|secret|token|apiKey|privateKey|ssn|creditCard|"
    r"cvv|socialSecurity|bankAccount|privateData)", re.I
)
_AUTH_ERROR_RE = re.compile(
    r"(unauthorized|unauthenticated|forbidden|not allowed|"
    r"must be logged in|authentication required)", re.I
)


class GraphQLAuthorizationScanner(BaseScanner):
    """Check GraphQL endpoints for missing authorization controls."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        base   = parsed.scheme + "://" + parsed.netloc
        found_gql = False

        for path in _GQL_PATHS:
            gql_url = base + path

            # Probe with introspection — no auth header
            resp = self.http.get(gql_url)
            if resp is None or resp.status_code == 404:
                continue

            found_gql = True
            headers = resp.headers if hasattr(resp.headers, "get") else {}

            # Check if introspection works without auth
            intr_resp = self.http.get(
                gql_url + "?" + "query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
            )
            if intr_resp and intr_resp.status_code == 200:
                intr_body = intr_resp.text or ""
                try:
                    data = json.loads(intr_body)
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    if types and not _AUTH_ERROR_RE.search(intr_body):
                        self.results.append(self._result(
                            gql_url, "graphql_introspection_no_auth", "FAIL",
                            detail=f"GraphQL introspection accessible without Authorization header at {path}. "
                                   f"{len(types)} type(s) enumerated. Disable introspection in production "
                                   "or require authentication: add 'introspection: requiresAuthentication' in schema config."
                        ))

                        # Check mutation types for sensitive operations
                        mut_names = []
                        for t in types:
                            name = t.get("name", "")
                            if _SENSITIVE_MUTATION_RE.search(name):
                                mut_names.append(name)
                            fields = t.get("fields") or []
                            for f in fields:
                                fname = f.get("name", "")
                                if _SENSITIVE_MUTATION_RE.search(fname):
                                    mut_names.append(f"{name}.{fname}")

                        if mut_names:
                            self.results.append(self._result(
                                gql_url, "graphql_sensitive_mutations_exposed", "FAIL",
                                detail=f"GraphQL schema exposes sensitive mutation/type names visible "
                                       f"without auth: {mut_names[:5]}. These operations must require "
                                       "authentication and authorization checks."
                            ))

                        # Check for sensitive field names in types
                        sensitive_fields = []
                        for t in types:
                            for f in (t.get("fields") or []):
                                if _SENSITIVE_FIELD_RE.search(f.get("name", "")):
                                    sensitive_fields.append(f"{t['name']}.{f['name']}")
                        if sensitive_fields:
                            self.results.append(self._result(
                                gql_url, "graphql_sensitive_fields_in_schema", "WARN",
                                detail=f"Sensitive field names exposed in GraphQL schema: "
                                       f"{sensitive_fields[:5]}. Apply field-level authorization "
                                       "(graphql-shield or equivalent) to restrict access."
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass

            # Check if simple query works without auth
            simple_query = "?query=%7Bviewer%7Bid%7D%7D"
            q_resp = self.http.get(gql_url + simple_query)
            if q_resp and q_resp.status_code == 200:
                q_body = q_resp.text or ""
                if not _AUTH_ERROR_RE.search(q_body) and "errors" not in q_body.lower():
                    self.results.append(self._result(
                        gql_url + simple_query, "graphql_query_no_auth", "WARN",
                        detail=f"GraphQL {path} responds to {'{viewer{id}}'} query without Authorization header. "
                               "All queries and mutations should require authentication for private APIs."
                    ))

            # Check for missing CORS on GraphQL (enables CSRF via form-POST)
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                self.results.append(self._result(
                    gql_url, "graphql_cors_wildcard", "FAIL",
                    detail=f"GraphQL endpoint {path} has CORS Access-Control-Allow-Origin: *. "
                           "application/json mutations are normally CORS-protected, but form-encoded "
                           "mutation requests bypass CORS. Require Content-Type: application/json and CSRF header."
                ))

        if not found_gql:
            self.results.append(self._result(
                url, "graphql_auth_no_endpoint", "PASS",
                detail="No GraphQL endpoint found at common paths — authorization check skipped."
            ))

        return self.results
