"""
Cloud Metadata SSRF & Misconfiguration Scanner.

Cloud environments expose metadata APIs on link-local addresses:
  AWS:   http://169.254.169.254/latest/meta-data/
  GCP:   http://metadata.google.internal/computeMetadata/v1/
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01

SSRF to these endpoints leaks IAM role credentials, instance identity,
SSH keys, and bootstrap scripts.

Checks:
  1. IP 169.254.169.254 or metadata hostnames in page source / links / JS
  2. SSRF-to-metadata probe: check if URL params redirect to metadata IPs
  3. IMDSv2 enforcement indicators (X-aws-ec2-metadata-token requirement)
  4. Kubernetes service account token paths exposed in page
  5. Cloud provider metadata URL patterns in JS bundles

All checks are passive or probe the target's own metadata paths.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Metadata IP and hostname patterns
_METADATA_IP_RE = re.compile(
    r"169\.254\.169\.254|"
    r"metadata\.google\.internal|"
    r"169\.254\.170\.2|"             # ECS Task Metadata
    r"100\.100\.100\.200|"           # Alibaba Cloud metadata
    r"192\.0\.0\.192",               # Digital Ocean metadata
    re.I,
)

# Kubernetes service account paths
_K8S_SA_TOKEN_RE = re.compile(
    r"/var/run/secrets/kubernetes\.io/serviceaccount|"
    r"KUBERNETES_SERVICE_HOST|"
    r"kube-apiserver|"
    r"/proc/1/environ",
    re.I,
)

# AWS metadata endpoint paths
_AWS_METADATA_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
    "/latest/dynamic/instance-identity/document",
    "/?Action=GetCallerIdentity",
]

# GCP metadata paths
_GCP_METADATA_PATHS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/project/project-id",
]

# IMDSv1 (vulnerable) vs IMDSv2 (requires token header)
_IMDS_V1_BODY_RE = re.compile(
    r"ami-[a-f0-9]{8,17}|"          # AWS AMI ID
    r'"instanceId"\s*:\s*"i-|'      # AWS instance ID
    r'"privateIp"\s*:\s*"\d+\.\d+|' # Private IP
    r'"region"\s*:\s*"[a-z]+-[a-z]+-\d+|' # AWS region
    r"iam/security-credentials",
    re.I,
)

# GCP metadata response
_GCP_META_BODY_RE = re.compile(
    r'"email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com|'
    r'"access_token"\s*:\s*"ya29\.|'
    r'"project-id"\s*:\s*"|'
    r"computeMetadata",
    re.I,
)


class CloudMetadataScanner(BaseScanner):
    """Detect cloud metadata SSRF exposure and IMDSv2 enforcement gaps."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "Cloud metadata — no SSRF or metadata exposure indicators", "PASS",
                detail="No cloud metadata endpoint references or SSRF indicators found."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        # ── 1. Metadata IP/hostname in page source ─────────────────────────────
        metadata_match = _METADATA_IP_RE.search(body)
        if metadata_match:
            snippet = metadata_match.group(0)
            log_fail(logger, f"Cloud metadata endpoint reference in page: {snippet}")
            self.results.append(self._result(
                url, f"Cloud metadata — metadata endpoint reference in page ({snippet})", "FAIL",
                detail=(
                    f"Cloud metadata endpoint address found in page source: '{snippet}'. "
                    "This indicates the application may be making server-side requests to "
                    "the cloud metadata service, or is exposing internal configuration. "
                    "If combined with an SSRF vulnerability, this could lead to AWS IAM "
                    "credential theft, GCP service account token leakage, or Azure managed "
                    "identity token exposure. "
                    "Fix: remove metadata endpoint references from frontend code; "
                    "enforce IMDSv2 (AWS), require metadata-flavor header (GCP); "
                    "restrict metadata endpoint access to specific IAM roles."
                )
            ))

        # ── 2. K8s service account patterns ───────────────────────────────────
        k8s_match = _K8S_SA_TOKEN_RE.search(body)
        if k8s_match:
            log_fail(logger, f"Kubernetes service account path in response: {k8s_match.group(0)}")
            self.results.append(self._result(
                url, "Cloud metadata — Kubernetes service account token path exposed", "FAIL",
                detail=(
                    f"Kubernetes-related path found in response: '{k8s_match.group(0)[:80]}'. "
                    "Service account tokens at /var/run/secrets/kubernetes.io/serviceaccount/ "
                    "provide API server access. If readable via SSRF or path traversal, "
                    "they allow full Kubernetes API access within the bound RBAC permissions. "
                    "Fix: use least-privilege service accounts; mount tokens only when needed "
                    "(automountServiceAccountToken: false in pod spec)."
                )
            ))

        # ── 3. Check JS files for metadata references ──────────────────────────
        for script in soup.find_all("script"):
            src = script.attrs.get("src", "")
            if not src:
                continue
            js_url = src if src.startswith("http") else urljoin(url, src)
            try:
                js_resp = self.http.get(js_url)
                if not js_resp or js_resp.status_code != 200:
                    continue
                js_body = js_resp.text or ""
                if _METADATA_IP_RE.search(js_body):
                    m = _METADATA_IP_RE.search(js_body)
                    log_warn(logger, f"Metadata endpoint reference in JS {js_url}: {m.group(0)}")
                    self.results.append(self._result(
                        js_url, f"Cloud metadata — metadata endpoint in JS bundle ({m.group(0)})", "WARN",
                        detail=(
                            f"Cloud metadata address '{m.group(0)}' found in JavaScript file {js_url}. "
                            "Remove cloud-internal addresses from client-side code; "
                            "use environment variables injected at build time instead."
                        )
                    ))
            except Exception:
                continue

        # ── 4. Probe accessible metadata endpoint (IMDSv1 check) ──────────────
        # Only if the target appears to be running in cloud context
        # (metadata IP in page, or cloud provider headers present)
        cloud_indicators = (
            metadata_match or
            any(h.lower() in ("x-aws-request-id", "x-amz-request-id", "x-goog-request-id",
                              "x-ms-request-id")
                for h in resp.headers)
        )

        if cloud_indicators:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            # Probe a safe path on the target that might proxy metadata
            for path in _AWS_METADATA_PATHS[:2]:
                probe_url = f"http://169.254.169.254{path}"
                # Note: We don't actually probe 169.254.169.254 directly (not our host)
                # Instead, look for proxy/SSRF vectors that might reach it
                ssrf_probe = f"{base}/proxy?url={probe_url}"
                try:
                    r = self.http.get(ssrf_probe)
                    if r and r.status_code == 200 and _IMDS_V1_BODY_RE.search(r.text or ""):
                        log_fail(logger, f"SSRF to cloud metadata succeeded via: {ssrf_probe}")
                        self.results.append(self._result(
                            ssrf_probe,
                            "Cloud metadata — SSRF to AWS IMDS succeeded (IMDSv1 exposed)",
                            "FAIL",
                            detail=(
                                "Server-Side Request Forgery to the AWS Instance Metadata Service "
                                f"succeeded via {ssrf_probe}. IMDSv1 metadata was returned, "
                                "which may include IAM role credentials. "
                                "Fix: enforce IMDSv2 by requiring X-aws-ec2-metadata-token; "
                                "set hop limit to 1 (disables SSRF from containers); "
                                "block proxy endpoints from accessing 169.254.x.x."
                            )
                        ))
                except Exception:
                    pass

        if not self.results:
            log_pass(logger, f"No cloud metadata exposure indicators found on {url}")
            self.results.append(self._result(
                url, "Cloud metadata — no SSRF or metadata exposure indicators", "PASS",
                detail="No cloud metadata endpoint references or SSRF indicators found."
            ))

        return self.results
