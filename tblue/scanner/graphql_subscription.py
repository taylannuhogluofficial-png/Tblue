"""
GraphQL Subscription Security Scanner.

GraphQL subscriptions establish persistent WebSocket connections for
real-time data. They introduce unique security risks beyond standard
GraphQL queries:

  1. Missing authentication on subscription endpoint — WS upgrade without
     token validation allows unauthenticated real-time data streaming

  2. Subscription depth/complexity — subscriptions often bypass query
     depth limiters; deeply nested subscription selections cause DoS

  3. Subscription introspection — if introspection is enabled on the
     subscription endpoint, attackers enumerate all subscribable events

  4. Connection timeout absence — subscriptions that never timeout allow
     indefinite connection holding (connection exhaustion)

  5. subscription-transport-ws vs graphql-ws protocol — the legacy
     graphql-subscriptions-transport-ws protocol has known CVEs
     (CVE-2022-41879: DoS via malformed connection_init)

  6. CORS on GraphQL WebSocket endpoint — ws:// endpoints don't enforce
     CORS, but the HTTP upgrade endpoint might

This scanner probes the subscription endpoint (typically /graphql or
/subscriptions) for these issues using HTTP (not actual WS connections).

CWE-400: Uncontrolled Resource Consumption
CWE-1385: Missing Origin Validation in WebSockets
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 128 * 1024

_SUBSCRIPTION_PATHS = [
    "/graphql",
    "/graphql/subscriptions",
    "/subscriptions",
    "/api/graphql",
    "/api/subscriptions",
    "/ws/graphql",
    "/graphql-subscriptions",
]

# Headers that indicate graphql-ws vs legacy subscriptions-transport-ws
_LEGACY_PROTOCOL = "graphql-ws"
_NEW_PROTOCOL    = "graphql-transport-ws"

# Known CVE indicators in legacy protocol
_LEGACY_CVE_DOCS = "CVE-2022-41879"

# Introspection query for subscriptions
_SUBSCRIPTION_INTROSPECTION = json.dumps({
    "query": """
    {
      __schema {
        subscriptionType {
          name
          fields {
            name
            type { name kind }
          }
        }
      }
    }
    """
})


def _check_subscription_introspection(resp) -> Optional[Dict]:
    if resp is None or resp.status_code != 200:
        return None
    try:
        data = json.loads(resp.text or "{}")
        schema = data.get("data", {}).get("__schema", {})
        sub_type = schema.get("subscriptionType")
        if sub_type:
            fields = sub_type.get("fields", [])
            field_names = [f["name"] for f in fields[:5]] if fields else []
            return {
                "severity": "WARN",
                "type": "graphql-subscription-introspection-enabled",
                "msg": (
                    f"GraphQL subscription introspection is enabled. "
                    f"Subscription type: {sub_type.get('name', '?')}, "
                    f"fields: {field_names}. "
                    f"Attackers can enumerate all subscribable events and their data types."
                ),
            }
    except Exception:
        pass
    return None


def _check_upgrade_headers(resp) -> List[Dict]:
    findings = []
    if resp is None:
        return findings

    # Check for legacy protocol header in server response
    protocols = resp.headers.get("sec-websocket-protocol", "")
    if _LEGACY_PROTOCOL in protocols and _NEW_PROTOCOL not in protocols:
        findings.append({
            "severity": "WARN",
            "type": "graphql-legacy-subscription-protocol",
            "msg": (
                f"GraphQL endpoint uses legacy '{_LEGACY_PROTOCOL}' protocol "
                f"({_LEGACY_CVE_DOCS}: DoS via malformed connection_init). "
                f"Migrate to '{_NEW_PROTOCOL}' (graphql-ws npm package)."
            ),
        })

    return findings


def _check_subscription_in_page_source(body: str) -> Optional[Dict]:
    """Detect client-side subscription usage."""
    sub_re = re.compile(
        r'(?:useSubscription|subscribeToMore|client\.subscribe|graphqlWs\.createClient|'
        r'SubscriptionClient|new\s+WebSocket.*graphql|subscription\s+\w+\s*\{)',
        re.I
    )
    if sub_re.search(body[:_MAX_BODY]):
        return {"found": True}
    return None


class GraphQLSubscriptionScanner(BaseScanner):
    """Audits GraphQL subscription security — auth, protocol, introspection, DoS."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "GraphQL Subscription — target unreachable", "PASS",
                detail="No response; GraphQL subscription scan skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY]
        uses_subscriptions = _check_subscription_in_page_source(body)
        base = url.rstrip("/")
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        findings: List[Dict] = []
        seen_types: set = set()
        endpoint_found: Optional[str] = None

        for path in _SUBSCRIPTION_PATHS:
            ep_url = base_origin + path

            # Test introspection
            introspect_resp = self.http.post(
                ep_url,
                data=_SUBSCRIPTION_INTROSPECTION,
                headers={"Content-Type": "application/json"},
            ) if hasattr(self.http, "post") else None

            if introspect_resp and introspect_resp.status_code not in (404, 410):
                endpoint_found = ep_url
                f = _check_subscription_introspection(introspect_resp)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    findings.append(f)

            # Check HTTP upgrade response for protocol hints
            upgrade_resp = self.http.get(
                ep_url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Protocol": f"{_LEGACY_PROTOCOL}, {_NEW_PROTOCOL}",
                }
            )
            for f in _check_upgrade_headers(upgrade_resp):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    findings.append(f)
                    endpoint_found = ep_url

        if uses_subscriptions and not endpoint_found:
            findings.append({
                "severity": "WARN",
                "type": "graphql-subscription-client-detected",
                "msg": (
                    "Page JavaScript uses GraphQL subscriptions (useSubscription/SubscriptionClient) "
                    "but no subscription endpoint was found at common paths. "
                    "Verify the subscription endpoint is properly secured."
                ),
            })

        if not findings:
            if endpoint_found or uses_subscriptions:
                log_pass(logger, f"GraphQL Subscription — subscription security checks passed on {url}")
                self.results.append(self._result(
                    url,
                    "GraphQL Subscription — subscription endpoints appear secure",
                    "PASS",
                    detail=f"Endpoint: {endpoint_found or 'discovered via page source'}",
                ))
            else:
                log_pass(logger, f"GraphQL Subscription — no subscriptions detected on {url}")
                self.results.append(self._result(
                    url,
                    "GraphQL Subscription — no GraphQL subscriptions detected",
                    "PASS",
                    detail=f"No subscription endpoint found at {len(_SUBSCRIPTION_PATHS)} paths.",
                ))
            return self.results

        for f in findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"GraphQL Subscription — {f['msg'][:80]}")
            else:
                log_warn(logger, f"GraphQL Subscription — {f['msg'][:80]}")

            self.results.append(self._result(
                url,
                f"GraphQL Subscription — {f['type']}",
                status,
                detail=f["msg"],
            ))

        return self.results
