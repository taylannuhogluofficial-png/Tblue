"""
Credential Exposure Scanner.

Sensitive files that accidentally ship to production expose credentials,
database connection strings, and infrastructure secrets:

  1. .env / .env.local / .env.production — environment variable files with
     DB passwords, API keys, and service credentials.

  2. wp-config.php.bak / wp-config.php~ / wp-config.php.old — WordPress
     database credentials in backup files.

  3. .git/config — exposes remote URLs (may contain tokens or credentials
     embedded in URLs like https://user:token@github.com/...).

  4. .htpasswd — HTTP Basic Auth credential file.

  5. config.php.bak, settings.py.bak, database.yml — common backup
     extensions that expose application configuration.

  6. .DS_Store — reveals directory structure on macOS development machines.

  7. phpinfo() output at common paths — reveals loaded extensions, PHP
     configuration, and server environment.

Read-only: only HEAD/GET requests to well-known sensitive paths.

CWE-312: Cleartext Storage of Sensitive Information
CWE-215: Insertion of Sensitive Information Into Debugging Code
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_PATHS = [
    # Environment files
    ("/.env", "FAIL", "env-file"),
    ("/.env.local", "FAIL", "env-file"),
    ("/.env.production", "FAIL", "env-file"),
    ("/.env.development", "WARN", "env-file"),
    ("/.env.backup", "FAIL", "env-file"),
    # WordPress
    ("/wp-config.php.bak", "FAIL", "wp-config-backup"),
    ("/wp-config.php~", "FAIL", "wp-config-backup"),
    ("/wp-config.php.old", "FAIL", "wp-config-backup"),
    # Git
    ("/.git/config", "FAIL", "git-config"),
    ("/.gitconfig", "WARN", "git-config"),
    # Auth files
    ("/.htpasswd", "FAIL", "htpasswd"),
    ("/.htpasswd.bak", "FAIL", "htpasswd"),
    # Config backups
    ("/config.php.bak", "FAIL", "config-backup"),
    ("/config.php~", "FAIL", "config-backup"),
    ("/settings.py.bak", "WARN", "config-backup"),
    ("/database.yml", "WARN", "database-config"),
    ("/database.yml.bak", "FAIL", "database-config"),
    ("/config/database.yml", "WARN", "database-config"),
    # macOS artifacts
    ("/.DS_Store", "WARN", "ds-store"),
    # PHP info
    ("/phpinfo.php", "FAIL", "phpinfo"),
    ("/info.php", "WARN", "phpinfo"),
    ("/php_info.php", "WARN", "phpinfo"),
    # Other common sensitive files
    ("/credentials.json", "FAIL", "credentials-file"),
    ("/secrets.json", "FAIL", "credentials-file"),
    ("/aws-credentials", "FAIL", "credentials-file"),
    ("/.aws/credentials", "FAIL", "credentials-file"),
]

_ENV_VALUE_RE = re.compile(
    r'(?:password|secret|key|token|db_pass|database_url)\s*=\s*[^\s]{3,}',
    re.I
)
_PHPINFO_RE = re.compile(r'phpinfo\(\)|PHP\s+Version\s+\d+\.\d+', re.I)
_GIT_REMOTE_RE = re.compile(r'url\s*=\s*https?://[^\s]+', re.I)


def _check_sensitive_path(http, base_origin: str, path: str, severity: str, file_type: str) -> Optional[Dict]:
    url = urljoin(base_origin, path)
    resp = http.get(url)
    if resp is None or resp.status_code in (404, 410, 403, 401):
        return None

    if resp.status_code not in (200, 206, 301, 302):
        return None

    body = (resp.text or "")[:4096]

    # Validate content matches expected sensitive file type
    if file_type == "env-file":
        if not _ENV_VALUE_RE.search(body) and "=" not in body[:200]:
            return None
    elif file_type == "phpinfo":
        if not _PHPINFO_RE.search(body):
            return None
    elif file_type == "git-config":
        if "[core]" not in body and "[remote" not in body:
            return None

    return {
        "type": f"credential-exposure-{file_type}",
        "status": severity,
        "path": path,
        "detail": (
            f"Sensitive file accessible at {url} (HTTP {resp.status_code}).\n\n"
            f"File type: {file_type}. This file may contain credentials, API keys, "
            f"or configuration data that should never be publicly accessible.\n\n"
            f"Fix: block access to this path via web server configuration (deny in "
            f"nginx/Apache), move the file outside the webroot, or remove it entirely "
            f"from the deployment."
        ),
    }


class CredentialExposureScanner(BaseScanner):
    """Checks for publicly accessible sensitive files: .env, git config, config backups."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Credential Exposure — target unreachable", "PASS",
                detail="No response; credential exposure check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        for path, severity, file_type in _SENSITIVE_PATHS:
            f = _check_sensitive_path(self.http, base_origin, path, severity, file_type)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                if severity == "FAIL":
                    log_fail(logger, f"Credential Exposure — {f['type']} at {f['path']}")
                else:
                    log_warn(logger, f"Credential Exposure — {f['type']} at {f['path']}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Credential Exposure — no exposed sensitive files for {url}")
            self.results.append(self._result(
                url, "Credential Exposure — no sensitive files exposed", "PASS",
                detail="No .env, backup config files, .git/config, or other sensitive paths accessible."))

        return self.results
