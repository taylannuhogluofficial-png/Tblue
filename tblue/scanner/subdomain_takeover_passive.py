"""Subdomain takeover passive — dangling DNS CNAME, cloud service error pages, unclaimed buckets."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# Known cloud service error pages that indicate unclaimed subdomain
_TAKEOVER_SIGNATURES = [
    ("github_pages", re.compile(r"There isn't a GitHub Pages site here", re.I), "FAIL"),
    ("heroku_app_error", re.compile(r"No such app|herokucdn\.com.*app.*not.*found", re.I), "FAIL"),
    ("shopify_missing", re.compile(r"Sorry, this shop is currently unavailable", re.I), "FAIL"),
    ("fastly_missing", re.compile(r"Fastly error: unknown domain", re.I), "FAIL"),
    ("azure_missing", re.compile(r"404 Web Site not found.*azurewebsites", re.I), "FAIL"),
    ("aws_elb_missing", re.compile(r"Invalid Endpoint|no healthy upstream", re.I), "WARN"),
    ("s3_no_bucket", re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I), "FAIL"),
    ("netlify_missing", re.compile(r"Not found - Request ID:", re.I), "FAIL"),
    ("zendesk_missing", re.compile(r"Help Center Closed|Zendesk.*not found", re.I), "FAIL"),
    ("bitbucket_missing", re.compile(r"Repository not found.*bitbucket", re.I), "FAIL"),
    ("surge_missing", re.compile(r"project not found.*surge\.sh|surge.*not found", re.I), "FAIL"),
    ("tumblr_missing", re.compile(r"Whatever you were looking for doesn't currently exist at this address", re.I), "WARN"),
    ("acquia_missing", re.compile(r"The site you are looking for could not be found.*acquia", re.I), "FAIL"),
    ("cargo_missing", re.compile(r"If you're moving your domain away from Cargo", re.I), "FAIL"),
    ("unbounce_missing", re.compile(r"The requested URL was not found on this server.*unbounce", re.I), "WARN"),
]

_CNAME_DANGLING_HEADERS = {
    "x-github-request-id": "github_pages",
    "x-served-by": None,
    "x-cache": None,
}


def _check_takeover_signatures(body: str, headers: dict, url: str) -> list:
    findings = []
    for name, pattern, severity in _TAKEOVER_SIGNATURES:
        if pattern.search(body):
            findings.append({
                "type": f"subdomain_takeover_{name}",
                "status": severity,
                "url": url,
                "detail": f"Subdomain takeover indicator: {name.replace('_', ' ')} error page detected — "
                          f"this domain's DNS points to an unclaimed cloud resource",
            })
    return findings


class SubdomainTakeoverPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "subdomain_takeover_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        for f in _check_takeover_signatures(resp.text, headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "subdomain_takeover_clean", "PASS",
                                        detail="No subdomain takeover indicators detected"))
        return results
