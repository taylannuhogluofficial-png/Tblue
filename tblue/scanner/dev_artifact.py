"""
Developer Artifact / Configuration File Exposure Scanner.

Modern development workflows generate numerous sensitive files that, when
accidentally deployed to web servers, expose infrastructure details, credentials,
and secrets. This scanner probes for developer artifacts not covered by
info_disclosure.py's basic .git/.env checks.

Files checked:
  HAR files         — HTTP Archive files from browser DevTools sessions containing
                      cookies, auth tokens, request headers, and full request/response
                      data for all browser sessions
  Terraform state   — terraform.tfstate: cloud infrastructure inventory, IAM roles,
                      database passwords, resource IDs and secrets
  npm/yarn config   — .npmrc, .yarnrc.yml: auth tokens for private npm registries
  SSH private keys  — id_rsa, id_ed25519: accidentally deployed SSH keys
  Docker config     — config.json: registry auth tokens in base64
  AWS credentials   — .aws/credentials, .aws/config: AWS access key IDs and secrets
  Kubernetes config — kubeconfig, .kube/config: cluster access tokens
  package-lock.json — git+https:// URLs with embedded tokens
  Composer auth     — auth.json: Packagist/GitHub OAuth tokens

All probes are read-only GET requests. Detection uses content validation
(checking format-specific patterns) to avoid false positives on generic 404 pages.

Professional equivalents: Detectify "Developer Artifact Exposure",
Qualys WAS "Sensitive Developer Files", Acunetix "Dev Tool Files Found".

CWE-312: Cleartext Storage of Sensitive Information
CWE-538: Insertion of Sensitive Information into Externally-Accessible File
CWE-215: Insertion of Sensitive Information into Log Files
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# --- Content validation patterns ---

# HAR file: must have {"log": {"entries": [...]}} structure
_HAR_STRUCTURE_RE = re.compile(r'"log"\s*:\s*\{', re.I)
_HAR_ENTRIES_RE = re.compile(r'"entries"\s*:\s*\[', re.I)
_HAR_COOKIES_RE = re.compile(r'"cookies"\s*:\s*\[', re.I)

# Terraform state: must have terraform_version and resources
_TF_STATE_RE = re.compile(
    r'"terraform_version"\s*:|"serial"\s*:\s*\d+|"resources"\s*:\s*\[',
    re.I,
)
_TF_SECRET_RE = re.compile(
    r'"(?:password|secret|key|token|connection_string)"\s*:\s*"[^"]{4,}"',
    re.I,
)

# npm .npmrc auth token
_NPMRC_AUTH_RE = re.compile(
    r'(?:_authToken|_auth|npm_token|//[^\n:]+:_authToken)',
    re.I,
)
_NPMRC_TOKEN_VALUE_RE = re.compile(
    r'_authToken\s*=\s*[^\n\r\s]+',
    re.I,
)

# SSH private key indicators
_SSH_KEY_RE = re.compile(
    r'-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|ED25519)\s+PRIVATE\s+KEY-----',
    re.I,
)

# Docker config.json auth tokens
_DOCKER_AUTH_RE = re.compile(
    r'"auths"\s*:\s*\{.*?"auth"\s*:\s*"[A-Za-z0-9+/=]{10,}"',
    re.I | re.S,
)
_DOCKER_CREDSSTORE_RE = re.compile(r'"credsStore"\s*:\s*"', re.I)

# AWS credentials
_AWS_KEY_RE = re.compile(r'(?:AKIA|ASIA|AROA|AIDA|AIOA)[0-9A-Z]{16}', re.I)
_AWS_SECRET_RE = re.compile(r'aws_secret_access_key\s*=\s*[^\n\r\s]+', re.I)

# Kubernetes kubeconfig
_KUBECONFIG_RE = re.compile(
    r'apiVersion:\s*v1|kind:\s*Config|current-context:|clusters:|contexts:',
    re.I,
)
_KUBECONFIG_TOKEN_RE = re.compile(r'token:\s*[^\n\r\s]{10,}', re.I)

# package-lock.json with git+https tokens
_PKGLOCK_GIT_TOKEN_RE = re.compile(
    r'git\+https://[^@\n]+:[^@\n]+@',
    re.I,
)

# Composer auth.json
_COMPOSER_AUTH_RE = re.compile(
    r'"github-oauth"\s*:\s*\{|"http-basic"\s*:\s*\{|"bitbucket-oauth"\s*:\s*\{',
    re.I,
)
_COMPOSER_TOKEN_VALUE_RE = re.compile(
    r'"token"\s*:\s*"[a-zA-Z0-9_\-]{10,}"',
    re.I,
)

# yarn.lock with git credentials
_YARN_LOCK_TOKEN_RE = re.compile(
    r'https://[^@\n]+:[^@\n]+@(?:npm|registry)',
    re.I,
)

# Probe paths: (path, description, severity, content_validator_fn_name)
_PROBES: List[Tuple[str, str, str, str]] = [
    # HAR files
    ("/app.har",         "Browser HAR session file",           "FAIL", "har"),
    ("/network.har",     "Browser network HAR file",           "FAIL", "har"),
    ("/api.har",         "API session HAR file",               "FAIL", "har"),
    ("/debug.har",       "Debug HAR session file",             "FAIL", "har"),
    ("/site.har",        "Site HAR session file",              "FAIL", "har"),
    # Terraform
    ("/terraform.tfstate",        "Terraform state file",       "FAIL", "tfstate"),
    ("/terraform.tfstate.backup", "Terraform state backup",     "FAIL", "tfstate"),
    ("/.terraform/terraform.tfstate", "Terraform .terraform state", "FAIL", "tfstate"),
    # npm/yarn
    ("/.npmrc",          ".npmrc npm auth config",             "FAIL", "npmrc"),
    ("/.yarnrc.yml",     ".yarnrc.yml yarn auth config",       "WARN", "npmrc"),
    ("/package-lock.json","package-lock.json",                  "WARN", "pkglock"),
    ("/yarn.lock",       "yarn.lock",                           "WARN", "yarnlock"),
    # SSH
    ("/id_rsa",          "SSH RSA private key",                "FAIL", "ssh"),
    ("/id_ed25519",      "SSH ED25519 private key",            "FAIL", "ssh"),
    ("/id_ecdsa",        "SSH ECDSA private key",              "FAIL", "ssh"),
    ("/.ssh/id_rsa",     "SSH private key (.ssh/)",           "FAIL", "ssh"),
    ("/server.key",      "TLS server private key",            "FAIL", "ssh"),
    # Docker
    ("/docker-config.json", "Docker config.json",              "FAIL", "docker"),
    ("/.docker/config.json","Docker auth config",              "FAIL", "docker"),
    # AWS
    ("/.aws/credentials", "AWS credentials file",             "FAIL", "aws"),
    ("/.aws/config",    "AWS config file",                    "WARN", "aws_config"),
    # Kubernetes
    ("/kubeconfig",      "Kubernetes kubeconfig",              "FAIL", "kubeconfig"),
    ("/.kube/config",   "Kubernetes .kube/config",            "FAIL", "kubeconfig"),
    # Composer
    ("/auth.json",       "Composer auth.json",                "FAIL", "composer"),
]


class DevArtifactScanner(BaseScanner):
    """Detect exposed developer configuration files and secrets."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Developer artifact — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        for path, description, severity, validator in _PROBES:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r is None or r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if len(body) < 5:
                    continue

                # Validate content matches expected format
                if not self._validate(validator, body):
                    continue

                detail = self._build_detail(probe_url, description, validator, body, severity)
                if severity == "FAIL":
                    log_fail(logger, f"Developer artifact exposed: {probe_url} ({description})")
                else:
                    log_warn(logger, f"Developer artifact exposed: {probe_url} ({description})")

                self.results.append(self._result(
                    probe_url,
                    f"Developer artifact — {description} exposed",
                    severity,
                    detail=detail,
                ))
                found_any = True

            except Exception:
                continue

        if not found_any:
            log_pass(logger, f"No developer artifact files exposed on {base}")
            self.results.append(self._result(
                url,
                "Developer artifact — no sensitive developer files exposed",
                "PASS",
                detail=(
                    "Probed for HAR files, Terraform state, .npmrc, SSH keys, Docker config, "
                    "AWS credentials, Kubernetes config, package-lock.json, and Composer auth.json. "
                    "None were publicly accessible. "
                    "Fix: add these files to .gitignore; configure web server to deny access "
                    "to all non-web-served paths; audit deployment processes for accidental uploads."
                )
            ))

        return self.results

    def _validate(self, validator: str, body: str) -> bool:
        """Return True if body content matches the expected file format."""
        if validator == "har":
            return bool(_HAR_STRUCTURE_RE.search(body) and _HAR_ENTRIES_RE.search(body))
        elif validator == "tfstate":
            return bool(_TF_STATE_RE.search(body))
        elif validator == "npmrc":
            return bool(_NPMRC_AUTH_RE.search(body))
        elif validator == "ssh":
            return bool(_SSH_KEY_RE.search(body))
        elif validator == "docker":
            return bool(_DOCKER_AUTH_RE.search(body) or _DOCKER_CREDSSTORE_RE.search(body))
        elif validator == "aws":
            return bool(_AWS_KEY_RE.search(body) or _AWS_SECRET_RE.search(body))
        elif validator == "aws_config":
            return "aws_access_key" in body.lower() or "[default]" in body.lower()
        elif validator == "kubeconfig":
            return bool(_KUBECONFIG_RE.search(body))
        elif validator == "pkglock":
            return '"lockfileVersion"' in body and '"packages"' in body
        elif validator == "yarnlock":
            return "__metadata:" in body or "yarn lockfile v1" in body.lower()
        elif validator == "composer":
            return bool(_COMPOSER_AUTH_RE.search(body))
        return False

    def _build_detail(self, url: str, description: str, validator: str,
                       body: str, severity: str) -> str:
        extras = []

        if validator == "har":
            has_cookies = bool(_HAR_COOKIES_RE.search(body))
            extras.append(
                "The HAR file contains full request/response data for all browser sessions, "
                "including authentication cookies, auth headers, and POST body data. "
            )
            if has_cookies:
                extras.append("Cookie data detected in the HAR file. ")

        elif validator == "tfstate":
            has_secrets = bool(_TF_SECRET_RE.search(body))
            extras.append(
                "Terraform state files contain complete infrastructure inventory, "
                "including database passwords, API keys, cloud resource IDs, and "
                "IAM role configurations. "
            )
            if has_secrets:
                extras.append("Sensitive values (password/secret/key) detected in state. ")

        elif validator == "npmrc":
            has_token = bool(_NPMRC_TOKEN_VALUE_RE.search(body))
            extras.append(
                "The .npmrc file may contain auth tokens for private npm registries. "
            )
            if has_token:
                extras.append("An _authToken value is present. ")

        elif validator == "ssh":
            extras.append(
                "An SSH private key is publicly accessible. This enables attackers to "
                "authenticate as the key's owner to any server that accepts this key. "
            )

        elif validator == "docker":
            extras.append(
                "Docker config.json contains base64-encoded registry authentication "
                "credentials. Attackers can pull and push to your Docker registries. "
            )

        elif validator == "aws":
            has_access_key = bool(_AWS_KEY_RE.search(body))
            extras.append(
                "AWS credential files contain access key IDs and secret keys that "
                "allow full AWS API access within the associated account's permissions. "
            )
            if has_access_key:
                extras.append("AWS access key ID pattern detected. ")

        elif validator == "kubeconfig":
            has_token = bool(_KUBECONFIG_TOKEN_RE.search(body))
            extras.append(
                "Kubernetes kubeconfig files contain cluster API server URLs, "
                "TLS certificates, and authentication tokens granting cluster access. "
            )
            if has_token:
                extras.append("Authentication token detected in kubeconfig. ")

        elif validator == "pkglock":
            has_token = bool(_PKGLOCK_GIT_TOKEN_RE.search(body))
            extras.append("package-lock.json exposes dependency graph and versions. ")
            if has_token:
                extras.append(
                    "Embedded git+https:// URL with credentials detected in package-lock.json. "
                )

        fix_map = {
            "har":        "Delete HAR files; never commit or deploy them; use --no-cookies flag when exporting.",
            "tfstate":    "Store Terraform state in a remote backend (S3+encryption, Terraform Cloud); never commit state files.",
            "npmrc":      "Use CI/CD environment variables for npm tokens; add .npmrc to .gitignore.",
            "ssh":        "Remove the key from the web root; regenerate the key pair; audit authorized_keys on all servers.",
            "docker":     "Rotate registry credentials; use short-lived tokens; restrict config.json to CI runners only.",
            "aws":        "Rotate AWS credentials immediately; use IAM roles for EC2/Lambda instead of static keys.",
            "aws_config": "Avoid storing AWS configuration in web-accessible directories.",
            "kubeconfig": "Rotate cluster tokens; use short-lived service account tokens; restrict kubeconfig to CI/CD only.",
            "pkglock":    "Audit package-lock.json for embedded credentials; use npm token scoping.",
            "yarnlock":   "Audit yarn.lock for embedded credentials.",
            "composer":   "Rotate OAuth tokens; use environment variables via COMPOSER_AUTH env var instead of auth.json.",
        }

        fix = fix_map.get(validator, "Remove this file from public web access.")
        return (
            f"The file {url} is publicly accessible ({description}). "
            + "".join(extras)
            + f"Fix: {fix}"
        )
