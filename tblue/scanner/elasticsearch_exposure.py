"""
Elasticsearch / OpenSearch exposure scanner.

Probes for publicly accessible Elasticsearch and OpenSearch instances
on default ports. Unauthenticated access to these APIs allows full
cluster enumeration, index listing, and bulk data exfiltration.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger

logger = get_logger(__name__)

_ES_PORTS = [9200, 9201, 9300]
_OS_PORTS = [9200, 9201]

_ES_FINGERPRINTS = [
    (re.compile(r'"cluster_name"\s*:', re.I), "Elasticsearch cluster info endpoint exposed"),
    (re.compile(r'"version"\s*:\s*\{[^}]*"number"', re.I), "Elasticsearch version block in response"),
    (re.compile(r'"tagline"\s*:\s*"You Know, for Search"', re.I), "Elasticsearch default tagline"),
    (re.compile(r'"distribution"\s*:\s*"opensearch"', re.I), "OpenSearch instance exposed"),
]

_INDEX_RE  = re.compile(r'"index"\s*:\s*"([^"]+)"', re.I)
_HEALTH_RE = re.compile(r'"status"\s*:\s*"(green|yellow|red)"', re.I)


class ElasticsearchExposureScanner(BaseScanner):
    """Detect publicly exposed Elasticsearch / OpenSearch instances."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        host   = parsed.hostname or parsed.netloc.split(":")[0]
        found  = False

        for port in _ES_PORTS:
            probe_url = f"http://{host}:{port}/"
            resp = self.http.get(probe_url)
            if resp is None or resp.status_code not in (200, 401, 403):
                continue

            body = resp.text or ""

            # Check for authentication enforcement
            if resp.status_code in (401, 403):
                self.results.append(self._result(
                    probe_url, "elasticsearch_auth_enforced", "PASS",
                    detail=f"Elasticsearch/OpenSearch on port {port} requires authentication (HTTP {resp.status_code})."
                ))
                found = True
                continue

            for pattern, label in _ES_FINGERPRINTS:
                if pattern.search(body):
                    found = True
                    self.results.append(self._result(
                        probe_url, "elasticsearch_unauthenticated_access", "FAIL",
                        detail=f"Elasticsearch/OpenSearch: {label} on port {port}. "
                               "Unauthenticated access allows full index enumeration, data exfiltration, "
                               "and cluster manipulation. Enable X-Pack security or network-level access controls."
                    ))
                    break

            # Check _cat/indices for index listing
            cat_url = f"http://{host}:{port}/_cat/indices?format=json"
            cat_resp = self.http.get(cat_url)
            if cat_resp and cat_resp.status_code == 200:
                idx_matches = _INDEX_RE.findall(cat_resp.text or "")
                if idx_matches:
                    self.results.append(self._result(
                        cat_url, "elasticsearch_index_listing", "FAIL",
                        detail=f"Elasticsearch /_cat/indices accessible without auth — "
                               f"{len(idx_matches)} index/indices enumerated: {idx_matches[:5]}. "
                               "Restrict /_cat and /_cluster APIs with role-based access control."
                    ))

            # Check cluster health
            health_url = f"http://{host}:{port}/_cluster/health"
            h_resp = self.http.get(health_url)
            if h_resp and h_resp.status_code == 200:
                m = _HEALTH_RE.search(h_resp.text or "")
                if m:
                    self.results.append(self._result(
                        health_url, "elasticsearch_cluster_health_exposed", "WARN",
                        detail=f"Elasticsearch /_cluster/health accessible without auth — "
                               f"cluster status: '{m.group(1)}'. Internal topology exposed."
                    ))

        if not found:
            self.results.append(self._result(
                url, "elasticsearch_not_exposed", "PASS",
                detail="No publicly accessible Elasticsearch/OpenSearch instance detected on standard ports."
            ))

        return self.results
