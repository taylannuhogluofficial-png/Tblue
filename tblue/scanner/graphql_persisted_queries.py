"""
GraphQL Persisted Query Security Scanner.

Persisted queries (APQ — Automatic Persisted Queries) cache query hashes
server-side to avoid sending full query text. Security issues:

  1. Arbitrary query via hash — if the server accepts unknown hashes and
     returns the full query body alongside results, it leaks schema info.

  2. Persisted query ID enumeration — if queryId/operationName accepts
     sequential IDs or predictable names, internal queries can be executed.

  3. GET-based query execution — GraphQL over GET allows queries in URL
     parameters. Combined with APQ, this enables CSRF (GET is same-site).

  4. Missing persisted query enforcement — if a server advertises APQ
     support but still accepts arbitrary query text in POST bodies, the
     APQ feature provides no security benefit.

  5. Introspection via persisted query — if the server has disabled
     introspection via POST but allows it via a persisted query hash,
     the restriction is bypassed.

Read-only. No mutations submitted.

CWE-200: Exposure of Sensitive Information
CWE-284: Improper Access Control
"""

import json
import hashlib
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_GQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/api/query"]

_INTROSPECTION_QUERY = "{ __schema { types { name } } }"
_INTROSPECTION_HASH = hashlib.sha256(_INTROSPECTION_QUERY.encode()).hexdigest()

_APQ_PROBE_QUERY = "{ __typename }"
_APQ_PROBE_HASH = hashlib.sha256(_APQ_PROBE_QUERY.encode()).hexdigest()


def _post_gql(http, url: str, payload: dict) -> Optional[object]:
    try:
        return http.post(url, json=payload,
                         headers={"Content-Type": "application/json"})
    except Exception:
        return None


def _check_apq_support(http, url: str) -> Optional[Dict]:
    """Check if APQ is supported by sending a hash without query text."""
    payload = {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": _APQ_PROBE_HASH,
            }
        }
    }
    resp = _post_gql(http, url, payload)
    if resp is None or resp.status_code not in (200, 400):
        return None
    try:
        body = resp.json() if hasattr(resp, "json") else json.loads(resp.text or "")
    except Exception:
        return None
    errors = body.get("errors", [])
    # "PersistedQueryNotFound" means APQ is supported
    if any("PersistedQueryNotFound" in str(e) or "persisted" in str(e).lower()
           for e in errors):
        return {
            "type": "graphql-apq-supported",
            "status": "WARN",
            "detail": (
                f"Automatic Persisted Queries (APQ) are enabled at {url}.\n\n"
                f"APQ allows clients to register arbitrary queries by hash. If combined "
                f"with GET-based execution, it enables CSRF on GraphQL mutations. "
                f"If hash collision or enumeration is possible, internal queries leak.\n\n"
                f"Fix: ensure APQ is paired with query allowlisting. Disable arbitrary "
                f"query registration in production."
            ),
        }
    return None


def _check_get_based_query(http, url: str) -> Optional[Dict]:
    """Check if GraphQL queries are accepted via HTTP GET."""
    get_url = f"{url}?query={_APQ_PROBE_QUERY.replace(' ', '+')}"
    resp = http.get(get_url)
    if resp is None or resp.status_code not in (200, 201):
        return None
    try:
        body = resp.json() if hasattr(resp, "json") else json.loads(resp.text or "{}")
    except Exception:
        return None
    if "data" in body and "__typename" in str(body.get("data", {})):
        return {
            "type": "graphql-query-execution-via-get",
            "status": "WARN",
            "detail": (
                f"GraphQL endpoint at {url} executes queries via HTTP GET.\n\n"
                f"GET-based GraphQL is vulnerable to CSRF: a malicious page can "
                f"embed a <img src='/graphql?query={...}'> that executes as the "
                f"victim user. Even with SameSite cookies, cross-site navigations "
                f"can trigger GETs.\n\n"
                f"Fix: accept queries only via POST. If GET is needed for caching, "
                f"restrict to read-only operations with strict CSRF controls."
            ),
        }
    return None


def _check_introspection_via_apq(http, url: str) -> Optional[Dict]:
    """Try executing introspection via APQ hash after registration."""
    # Step 1: register hash + query
    reg_payload = {
        "query": _INTROSPECTION_QUERY,
        "extensions": {
            "persistedQuery": {"version": 1, "sha256Hash": _INTROSPECTION_HASH}
        }
    }
    resp1 = _post_gql(http, url, reg_payload)
    if resp1 is None:
        return None

    # Step 2: execute via hash only (no query text)
    hash_payload = {
        "extensions": {
            "persistedQuery": {"version": 1, "sha256Hash": _INTROSPECTION_HASH}
        }
    }
    resp2 = _post_gql(http, url, hash_payload)
    if resp2 is None or resp2.status_code != 200:
        return None
    try:
        body = resp2.json() if hasattr(resp2, "json") else json.loads(resp2.text or "{}")
    except Exception:
        return None
    if "data" in body and "__schema" in str(body.get("data", {})):
        return {
            "type": "graphql-introspection-via-apq-bypass",
            "status": "FAIL",
            "detail": (
                f"Introspection query executed via APQ hash at {url} — possible "
                f"introspection restriction bypass.\n\n"
                f"If introspection is blocked for direct POST queries but APQ allows "
                f"registering and replaying any query, the restriction is bypassed.\n\n"
                f"Fix: apply introspection blocking at the query execution level, not "
                f"just at the HTTP body parsing level. Block introspection fields "
                f"regardless of how the query arrives."
            ),
        }
    return None


class GraphQLPersistedQueriesScanner(BaseScanner):
    """Checks GraphQL endpoints for APQ support, GET execution, and introspection bypass."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + [urljoin(base_origin, p) for p in _GQL_PATHS]

        for ep in endpoints:
            for check_fn in [_check_apq_support, _check_get_based_query,
                             _check_introspection_via_apq]:
                f = check_fn(self.http, ep)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    lvl = log_fail if f["status"] == "FAIL" else log_warn
                    lvl(logger, f"GraphQL Persisted Queries — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"GraphQL Persisted Queries — no issues found for {url}")
            self.results.append(self._result(
                url,
                "GraphQL Persisted Queries — no APQ or GET query execution issues",
                "PASS",
                detail="No APQ support, GET-based execution, or introspection bypass found.",
            ))

        return self.results
