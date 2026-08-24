"""
Serverless Function Exposure Scanner.

Serverless platforms (AWS Lambda, Google Cloud Functions, Azure Functions,
Vercel, Netlify, Cloudflare Workers) introduce distinct exposure patterns:

  1. Cold start fingerprinting — X-AWS-Lambda-*, X-Cloud-Trace-Context,
     CF-Worker-* headers identify the runtime and sometimes version.

  2. Function URL direct access — AWS Lambda function URLs
     (.lambda-url.<region>.on.aws) and similar bypass API Gateway controls.

  3. Debug / dev endpoints — /.netlify/functions/*, /api/*, /_worker.js,
     /api/index.js patterns expose function entry points.

  4. Environment variable leakage — some frameworks expose environment
     config at /_env, /config.json, /.env, or in error responses.

  5. Timeout and resource limit headers — X-Vercel-Cache, X-Execution-Time
     expose infrastructure metadata.

  6. Serverless framework artifacts — .serverless/, serverless.yml,
     netlify.toml, vercel.json, wrangler.toml in web root.

Read-only.

CWE-200: Exposure of Sensitive Information
CWE-16: Configuration
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SERVERLESS_HEADERS = {
    "x-amzn-requestid": ("AWS Lambda", "WARN"),
    "x-amzn-trace-id": ("AWS X-Ray", "WARN"),
    "x-aws-lambda-request-id": ("AWS Lambda direct", "WARN"),
    "x-cloud-trace-context": ("Google Cloud Functions", "WARN"),
    "function-execution-id": ("Google Cloud Functions", "WARN"),
    "x-azure-functions-instanceid": ("Azure Functions", "WARN"),
    "x-vercel-cache": ("Vercel", "WARN"),
    "x-vercel-id": ("Vercel", "WARN"),
    "x-nf-request-id": ("Netlify", "WARN"),
    "cf-ray": ("Cloudflare Workers", "WARN"),
    "cf-worker": ("Cloudflare Workers", "WARN"),
}

_CONFIG_PATHS = [
    "/.env", "/config.json", "/.env.local", "/.env.production",
    "/serverless.yml", "/serverless.yaml", "/netlify.toml",
    "/vercel.json", "/wrangler.toml", "/wrangler.json",
    "/.serverless/", "/next.config.js",
]

_FUNCTION_PATHS = [
    "/.netlify/functions/", "/.netlify/functions/hello",
    "/api/hello", "/api/index", "/api/handler",
    "/_worker.js", "/api/edge",
]

_ENV_DISCLOSURE_RE = re.compile(
    r'(?:AWS_[A-Z_]+|GOOGLE_[A-Z_]+|AZURE_[A-Z_]+|'
    r'VERCEL_[A-Z_]+|NETLIFY_[A-Z_]+)\s*[=:]', re.I
)


def _check_serverless_headers(headers: dict, url: str) -> List[Dict]:
    findings = []
    lower_h = {k.lower(): v for k, v in headers.items()}
    for hdr, (platform, severity) in _SERVERLESS_HEADERS.items():
        if hdr in lower_h:
            findings.append({
                "type": f"serverless-platform-header-{hdr.replace('-', '_')}",
                "status": severity,
                "detail": (
                    f"{platform} header {hdr!r} found in response from {url}.\n\n"
                    f"Platform-specific headers reveal the serverless vendor, "
                    f"function instance, and request tracing IDs.\n\n"
                    f"Fix: configure the platform or edge layer to strip internal "
                    f"headers before returning responses to clients."
                ),
            })
    return findings


def _check_config_files(http, base_origin: str) -> List[Dict]:
    findings = []
    for path in _CONFIG_PATHS:
        ep = urljoin(base_origin, path)
        resp = http.get(ep)
        if resp is None or resp.status_code not in (200, 206):
            continue
        body = resp.text or ""
        if len(body) < 10:
            continue
        severity = "FAIL" if ".env" in path else "WARN"
        findings.append({
            "type": f"serverless-config-file-exposed-{path.strip('/').replace('/', '_').replace('.', '')}",
            "status": severity,
            "detail": (
                f"Serverless configuration file accessible at {ep}.\n\n"
                f"Configuration files may contain API keys, secrets, "
                f"database URLs, and deployment settings.\n\n"
                f"Fix: add these files to .gitignore and ensure they are "
                f"not deployed to the web root."
            ),
        })
        if _ENV_DISCLOSURE_RE.search(body):
            findings.append({
                "type": "serverless-environment-variable-disclosed",
                "status": "FAIL",
                "detail": (
                    f"Environment variable names (AWS_*, GOOGLE_*, AZURE_*, etc.) "
                    f"found in accessible file at {ep}.\n\n"
                    f"Fix: remove configuration files from web-accessible directories "
                    f"and use platform secrets managers."
                ),
            })
        break  # one file exposure is enough signal
    return findings


class ServerlessExposureScanner(BaseScanner):
    """Checks for serverless platform header disclosure and exposed config files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Serverless Exposure — target unreachable", "PASS",
                detail="No response; serverless exposure check skipped."))
            return self.results

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        for f in _check_serverless_headers(resp.headers, url):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Serverless Exposure — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"][:100], f["status"], detail=f["detail"]))

        for f in _check_config_files(self.http, base_origin):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                lvl = log_fail if f["status"] == "FAIL" else log_warn
                lvl(logger, f"Serverless Exposure — {f['type']}")
                self.results.append(self._result(
                    url, f["type"][:100], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Serverless Exposure — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Serverless Exposure — no platform headers or config file exposure",
                "PASS",
                detail="No serverless platform headers or exposed configuration files found.",
            ))

        return self.results
