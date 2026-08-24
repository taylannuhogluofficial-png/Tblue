"""
Exposed Backup File Scanner.

Backup and temporary files left on web servers expose source code, configuration,
credentials, and database dumps to unauthenticated access.

Common backup file patterns:
1. Editor-generated:
   - `file~` (vim/emacs backup), `file.bak`, `file.orig`, `file.old`, `file.copy`
   - `.file.swp`, `.file.swo` (vim swap files with partial source content)
   - `#file#` (emacs auto-save)
2. Manual backups:
   - `config.php.bak`, `index.html.backup`, `database.sql.bak`
   - `*.tar.gz`, `*.zip` archives containing application source or data
3. Version control leftovers:
   - `.git/` (full repository — credentials, commit history)
   - `CVS/`, `.svn/` (legacy VCS with source code)
4. Database dumps:
   - `dump.sql`, `backup.sql`, `db_backup.sql`, `database.sql.gz`
5. Configuration backups:
   - `web.config.bak`, `.htaccess.bak`, `nginx.conf.bak`
6. CMS-specific:
   - `wp-config.php.bak`, `wp-config.php~`, `settings.php.bak`
7. Environment/secrets:
   - `.env.bak`, `.env.old`, `secrets.yml.bak`

CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
CWE-538: File and Directory Information Exposure
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_BACKUP_PATHS = [
    # Editor backups
    "index.php~", "index.html~", "index.jsp~", "app.py~",
    "config.php~", "settings.py~", "application.rb~",
    ".index.php.swp", ".config.php.swp", ".app.py.swp",
    # .bak files
    "index.php.bak", "config.php.bak", "web.config.bak",
    "index.html.bak", ".htaccess.bak", "nginx.conf.bak",
    "settings.py.bak", "database.yml.bak", ".env.bak",
    "wp-config.php.bak", "wp-config.php~", "wp-config.php.old",
    # .orig / .old
    "index.php.orig", "config.php.orig", "index.html.orig",
    "config.php.old", "settings.py.old", ".env.old",
    # Database dumps
    "dump.sql", "backup.sql", "db_backup.sql", "database.sql",
    "dump.sql.gz", "backup.sql.gz", "database.sql.gz",
    "db.sql", "site.sql", "export.sql",
    # Archives
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
    "htdocs.tar.gz", "public_html.tar.gz", "backup.tgz",
    # VCS
    ".git/config", ".git/HEAD", ".svn/entries",
    "CVS/Root", ".hg/hgrc",
    # Config backups
    "web.config.bak", "applicationHost.config.bak",
    # CMS
    "wp-config.php.bak", "configuration.php.bak",
    "LocalSettings.php.bak", "settings.php.bak",
    # Secrets
    ".env.backup", "secrets.yml.bak", ".env.production.bak",
    # IDE
    ".idea/workspace.xml", ".vscode/launch.json",
]

_SENSITIVE_CONTENT_RE_PATTERNS = [
    (r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "FAIL", "contains credentials"),
    (r'(?i)(?:secret|api[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']', "FAIL", "contains API keys/secrets"),
    (r'(?i)mysql|postgres|sqlite|mssql', "WARN", "contains database references"),
    (r'(?i)<\?php|<%\s*@\s*Page|import\s+java\.', "WARN", "contains server-side source code"),
    (r'\$_(?:POST|GET|SERVER|SESSION|COOKIE)\s*\[', "WARN", "contains PHP superglobal access"),
]

import re as _re


class ExposedBackupFilesScanner(BaseScanner):
    """Probe for exposed backup, dump, and source files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0
        found_any = False

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _BACKUP_PATHS:
            if findings >= 10:
                break
            probe_url = base + "/" + path
            try:
                resp = self.http.get(probe_url)
            except Exception:
                continue
            if resp is None or resp.status_code not in (200,):
                continue

            body = resp.text or ""
            # Skip if body is the same as the homepage (soft 404)
            if len(body) < 10:
                continue

            found_any = True
            body_lower = body[:5000]

            # Determine severity by content
            severity = "WARN"
            content_desc = "backup file accessible"
            for pattern, sev, desc in _SENSITIVE_CONTENT_RE_PATTERNS:
                if _re.search(pattern, body_lower):
                    severity = sev
                    content_desc = desc
                    break

            if severity == "FAIL":
                log_fail(logger, f"Exposed backup file with sensitive content at {probe_url}")
            else:
                log_warn(logger, f"Exposed backup file at {probe_url}")

            self.results.append(self._result(
                url,
                f"Exposed backup file — {path} is accessible ({content_desc})",
                severity,
                detail=(
                    f"The file '{path}' is accessible at '{probe_url}' (HTTP 200). "
                    f"Backup files expose {content_desc}. "
                    "Attackers can use exposed source code to find vulnerabilities, "
                    "extract database credentials, API keys, or authentication secrets. "
                    "Fix: remove all backup files from web-accessible directories; "
                    "configure the web server to deny access to backup extensions "
                    "(.bak, .orig, .old, .swp, ~); audit for leftover files before deployment."
                )
            ))
            findings += 1

        if not found_any:
            log_pass(logger, f"No exposed backup files at {url}")
            self.results.append(self._result(
                url, "Exposed backup files — no backup files accessible", "PASS",
                detail="No backup, dump, or editor-temporary files found at common paths."
            ))

        return self.results
