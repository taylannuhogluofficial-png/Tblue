"""
Public cloud storage bucket detector.

Checks common bucket naming patterns derived from the target domain against
AWS S3, Azure Blob Storage, and Google Cloud Storage. A bucket that returns
a 200 with a ListBucketResult/EnumerationResults body is publicly readable
and almost certainly a misconfiguration.

All checks are plain HTTP GET — no cloud credentials needed.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# S3 bucket listing response signature
_S3_SIGNATURE    = re.compile(r"<ListBucketResult|<Error><Code>NoSuchBucket|<Error><Code>AccessDenied", re.I)
_S3_PUBLIC_LIST  = re.compile(r"<ListBucketResult", re.I)

# Azure blob listing signature
_AZURE_SIGNATURE = re.compile(r"<EnumerationResults|BlobNotFound|ResourceNotFound", re.I)
_AZURE_PUBLIC    = re.compile(r"<EnumerationResults", re.I)

# GCS listing signature
_GCS_SIGNATURE   = re.compile(r'"kind":\s*"storage#objects"|"error":', re.I)
_GCS_PUBLIC      = re.compile(r'"kind":\s*"storage#objects"', re.I)

_TIMEOUT = 8


def _name_variants(domain: str) -> List[str]:
    """Generate bucket name candidates from a domain name."""
    parts = domain.split(".")
    base  = parts[0]
    variants = {
        base,
        domain.replace(".", "-"),
        domain.replace(".", ""),
        f"{base}-assets",
        f"{base}-static",
        f"{base}-media",
        f"{base}-uploads",
        f"{base}-backup",
        f"{base}-backups",
        f"{base}-data",
        f"{base}-prod",
        f"{base}-staging",
        f"{base}-dev",
        f"{base}-files",
        f"{base}-public",
        f"{base}-private",
        f"assets.{domain}".replace(".", "-"),
        f"static.{domain}".replace(".", "-"),
        f"media.{domain}".replace(".", "-"),
    }
    return list(variants)


class CloudStorageScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        host   = urlparse(url).hostname or ""
        domain = host.lstrip("www.") if host.startswith("www.") else host
        if not domain:
            return self.results

        names    = _name_variants(domain)
        findings = []

        for name in names:
            # AWS S3
            s3_url = f"https://{name}.s3.amazonaws.com/"
            finding = self._probe_s3(s3_url, name)
            if finding:
                findings.append(finding)

            # Azure Blob
            az_url = f"https://{name}.blob.core.windows.net/{name}?restype=container&comp=list"
            finding = self._probe_azure(az_url, name)
            if finding:
                findings.append(finding)

            # GCS
            gcs_url = f"https://storage.googleapis.com/{name}/"
            finding = self._probe_gcs(gcs_url, name)
            if finding:
                findings.append(finding)

        self.results.extend(findings)

        if not findings:
            log_pass(logger, f"No publicly accessible cloud buckets found for {domain}")
            self.results.append(self._result(url,
                "Cloud storage — no public buckets detected",
                "PASS",
                detail=f"Checked {len(names)} bucket name variants across AWS S3, Azure Blob, "
                       "and Google Cloud Storage — none are publicly listable."))
        return self.results

    def _probe_s3(self, s3_url: str, name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.http.get(s3_url)
            if not resp:
                return None
            if _S3_PUBLIC_LIST.search(resp.text):
                log_fail(logger, f"Public S3 bucket: {name}")
                return self._result(s3_url,
                    f"Cloud storage — public S3 bucket ({name})",
                    "FAIL",
                    detail=(
                        f"AWS S3 bucket '{name}' ({s3_url}) is publicly listable. "
                        "Anyone can enumerate and download all files. "
                        "Fix: in S3 console → Block Public Access settings → enable all four blocks. "
                        "Also audit bucket policy and ACLs for public read grants."
                    ))
        except Exception:
            pass
        return None

    def _probe_azure(self, az_url: str, name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.http.get(az_url)
            if not resp:
                return None
            if _AZURE_PUBLIC.search(resp.text):
                log_fail(logger, f"Public Azure blob container: {name}")
                return self._result(az_url,
                    f"Cloud storage — public Azure blob container ({name})",
                    "FAIL",
                    detail=(
                        f"Azure Blob container '{name}' ({az_url}) is publicly listable. "
                        "Fix: in Azure Portal → Storage Account → Containers → "
                        "set Access Level to 'Private' and remove public access."
                    ))
        except Exception:
            pass
        return None

    def _probe_gcs(self, gcs_url: str, name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.http.get(gcs_url)
            if not resp:
                return None
            if _GCS_PUBLIC.search(resp.text):
                log_fail(logger, f"Public GCS bucket: {name}")
                return self._result(gcs_url,
                    f"Cloud storage — public GCS bucket ({name})",
                    "FAIL",
                    detail=(
                        f"Google Cloud Storage bucket '{name}' ({gcs_url}) is publicly listable. "
                        f"Fix: gsutil iam ch -d allUsers gs://{name} — then audit IAM bindings."
                    ))
        except Exception:
            pass
        return None


