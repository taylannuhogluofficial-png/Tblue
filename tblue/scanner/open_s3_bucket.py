"""Open S3 bucket and cloud storage detection — targeted bucket name guessing from domain."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_S3_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
_S3_PUBLIC_RE  = re.compile(r"<ListBucketResult|<Contents>|<Key>", re.I)
_S3_DENY_RE    = re.compile(r"AccessDenied|NoSuchBucket|AllAccessDisabled", re.I)
_GCS_PUBLIC_RE = re.compile(r"<ListBucketResult|<item>.*?<name>", re.I | re.S)
_AZURE_PUBLIC_RE = re.compile(r'<EnumerationResults\b|<Blob>\s*<Name>', re.I | re.S)

# Common bucket naming patterns derived from a domain name
def _bucket_candidates(domain: str) -> list:
    base = domain.split(".")[0]  # strip TLD
    return [
        base, f"{base}-assets", f"{base}-static", f"{base}-media",
        f"{base}-uploads", f"{base}-files", f"{base}-backup",
        f"{base}-dev", f"{base}-staging", f"{base}-prod",
        f"{base}-public", f"{base}-data",
    ]


def _check_s3_bucket(http, bucket_name: str) -> dict | None:
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    try:
        r = http.get(url)
        if r is None:
            return None
        if r.status_code == 200 and _S3_PUBLIC_RE.search(r.text):
            return {
                "type": "open_s3_bucket_listing",
                "status": "FAIL",
                "url": url,
                "detail": f"S3 bucket publicly listable: {bucket_name}",
            }
        if r.status_code == 403 and not _S3_DENY_RE.search(r.text):
            return {
                "type": "s3_bucket_exists_no_list",
                "status": "WARN",
                "url": url,
                "detail": f"S3 bucket exists but listing denied: {bucket_name} — verify ACLs",
            }
    except Exception:
        pass
    return None


def _check_gcs_bucket(http, bucket_name: str) -> dict | None:
    url = f"https://storage.googleapis.com/{bucket_name}/"
    try:
        r = http.get(url)
        if r and r.status_code == 200 and _GCS_PUBLIC_RE.search(r.text):
            return {
                "type": "open_gcs_bucket_listing",
                "status": "FAIL",
                "url": url,
                "detail": f"Google Cloud Storage bucket publicly listable: {bucket_name}",
            }
    except Exception:
        pass
    return None


def _check_azure_blob(http, bucket_name: str) -> dict | None:
    url = f"https://{bucket_name}.blob.core.windows.net/?comp=list"
    try:
        r = http.get(url)
        if r and r.status_code == 200 and _AZURE_PUBLIC_RE.search(r.text):
            return {
                "type": "open_azure_blob_listing",
                "status": "FAIL",
                "url": url,
                "detail": f"Azure Blob Storage container publicly listable: {bucket_name}",
            }
    except Exception:
        pass
    return None


class OpenS3BucketScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "open_s3_bucket_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        candidates = _bucket_candidates(domain)

        for bucket_name in candidates[:5]:  # limit to 5 candidates
            s3 = _check_s3_bucket(self.http, bucket_name)
            if s3:
                results.append(self._result(s3["url"], s3["type"], s3["status"],
                                            detail=s3["detail"]))
                break

            gcs = _check_gcs_bucket(self.http, bucket_name)
            if gcs:
                results.append(self._result(gcs["url"], gcs["type"], gcs["status"],
                                            detail=gcs["detail"]))
                break

            azure = _check_azure_blob(self.http, bucket_name)
            if azure:
                results.append(self._result(azure["url"], azure["type"], azure["status"],
                                            detail=azure["detail"]))
                break

        if not results:
            results.append(self._result(url, "open_s3_bucket_clean", "PASS",
                                        detail="No publicly accessible cloud storage buckets detected"))
        return results
