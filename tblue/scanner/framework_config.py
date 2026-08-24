"""
Framework Configuration File and Log File Exposure Scanner.

Many web frameworks write sensitive configuration and log files to paths that,
when accidentally accessible via HTTP, expose database credentials, API keys,
session secrets, and full application stack traces.

This scanner extends info_disclosure.py's basic file probing to cover
framework-specific configuration files and application log files not already
checked by other scanners.

Files covered:

  Log files (with content validation):
    /storage/logs/laravel.log        — Laravel (PHP)
    /logs/error.log                  — Generic application
    /app/logs/error.log              — Java EE
    /log/error.log                   — Various
    /tmp/debug.log                   — Debug artifacts
    /debug.log                       — PHP Symfony debug log
    /application.log                 — Generic
    /server.log                      — Servlet containers
    /catalina.out                    — Apache Tomcat
    /var/log/app/app.log             — Linux deploy

  Framework config files (with content validation):
    /application.properties          — Spring Boot (Java)
    /application.yml                 — Spring Boot (Java) / generic
    /appsettings.json                — ASP.NET Core
    /appsettings.Development.json    — ASP.NET Core dev settings
    /config/database.yml             — Ruby on Rails
    /config/secrets.yml              — Ruby on Rails
    /config/master.key               — Rails 5.2+ encryption key
    /config/credentials.yml.enc      — Rails 5.2+ encrypted credentials
    /config/database.php             — Laravel (PHP)
    /config/app.php                  — Laravel application config
    /config/mail.php                 — Laravel mail config
    /local_settings.py               — Django local settings
    /settings.py                     — Django settings
    /web.config                      — ASP.NET / IIS
    /config.xml                      — Various Java apps
    /hibernate.cfg.xml               — Hibernate ORM
    /persistence.xml                 — JPA / Java EE
    /datasource.properties           — JDBC datasource

Content validation prevents false positives: each file type must match
format-specific patterns before being flagged.

Professional equivalents: Detectify "Log File Exposure" and
"Config File Exposure", Acunetix "Sensitive Files", Qualys WAS "Config Files".

CWE-312: Cleartext Storage of Sensitive Information
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-538: Insertion of Sensitive Information into Externally-Accessible File
CWE-532: Insertion of Sensitive Information into Log File
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail

logger = get_logger(__name__)

# --- Log file content validators ---

# Application log signatures (stack traces, SQL, session tokens)
_LOG_STACKTRACE_RE = re.compile(
    r'(?:Exception|Traceback|at\s+\w+\.\w+\(|#\d+\s+/\S+\.php|'
    r'Caused by:|Error:\s+\w+Error|SQLSTATE\[|ORA-\d+|'
    r'\[ERROR\]|\[CRITICAL\]|Exception in thread)',
    re.I,
)
_LOG_SQL_RE = re.compile(
    r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|DROP TABLE|'
    r'execute query|sql error|mysql error|pg_query|sqlite|PDOException)',
    re.I,
)
_LOG_AUTH_TOKEN_RE = re.compile(
    r'(?:Authorization:\s*Bearer\s+\S{10,}|'
    r'session[_-]id[:=]\s*[a-zA-Z0-9+/=]{16,}|'
    r'token[:=]\s*[a-zA-Z0-9\-_.]{20,}|'
    r'password[:=]\s*\S{4,})',
    re.I,
)
_HTTP_LOG_RE = re.compile(
    r'(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[|'
    r'"(?:GET|POST|PUT|DELETE|HEAD)\s+/)',
    re.I,
)

def _is_log_content(body: str) -> bool:
    return bool(
        _LOG_STACKTRACE_RE.search(body) or
        _LOG_SQL_RE.search(body) or
        _LOG_AUTH_TOKEN_RE.search(body) or
        _HTTP_LOG_RE.search(body)
    )


# --- Framework config file validators ---

# Spring Boot application.properties / application.yml
_SPRING_PROPS_RE = re.compile(
    r'(?:spring\.datasource\.|spring\.security\.|spring\.mail\.|'
    r'spring\.redis\.|server\.port\s*=\s*\d+|'
    r'spring\.application\.name)',
    re.I,
)
_SPRING_DB_RE = re.compile(
    r'(?:datasource\s*:\s*\n|url\s*:\s*jdbc:|password\s*:\s*\S+|'
    r'spring\.datasource\.password\s*=)',
    re.I,
)

# ASP.NET Core appsettings.json
_APPSETTINGS_RE = re.compile(
    r'(?:"ConnectionStrings"\s*:\s*\{|"AllowedHosts"\s*:\s*"|'
    r'"Logging"\s*:\s*\{)',
    re.I,
)
_APPSETTINGS_CRED_RE = re.compile(
    r'(?:"DefaultConnection"\s*:\s*"[^"]*(?:Server=|Data Source=|password=)|'
    r'"[^"]*(?:ApiKey|SecretKey|ConnectionString)"\s*:\s*"[^"]{5,}")',
    re.I,
)

# Ruby on Rails config/database.yml
_RAILS_DB_YML_RE = re.compile(
    r'(?:adapter:\s*(?:mysql2|postgresql|sqlite3|sqlserver)|'
    r'database:\s+\w+|username:\s+\w+)',
    re.I,
)
_RAILS_PASSWORD_RE = re.compile(r'password:\s*\S+', re.I)

# Rails config/secrets.yml
_RAILS_SECRETS_RE = re.compile(
    r'(?:secret_key_base:\s*[a-f0-9]{64,}|'
    r'development:|production:|test:)',
    re.I,
)

# Rails master.key (hex string, 64 chars)
_RAILS_MASTER_KEY_RE = re.compile(r'^[a-f0-9]{32,}\s*$', re.I | re.M)

# Laravel config/database.php
_LARAVEL_DB_PHP_RE = re.compile(
    r"(?:'driver'\s*=>\s*'(?:mysql|pgsql|sqlite|sqlsrv)'|"
    r"'host'\s*=>\s*env\('DB_HOST'|'host'\s*=>\s*'localhost')",
    re.I,
)

# Django settings.py / local_settings.py
_DJANGO_SETTINGS_RE = re.compile(
    r'(?:DATABASES\s*=\s*\{|SECRET_KEY\s*=\s*[\'"]|INSTALLED_APPS\s*=\s*\[|'
    r'DJANGO_SETTINGS_MODULE)',
    re.I,
)
_DJANGO_SECRET_RE = re.compile(r"SECRET_KEY\s*=\s*['\"][^'\"]{10,}['\"]", re.I)

# web.config (ASP.NET / IIS)
_WEBCONFIG_RE = re.compile(
    r'(?:<connectionStrings>|<appSettings>|<configuration>|'
    r'<system\.web>)',
    re.I,
)
_WEBCONFIG_CRED_RE = re.compile(
    r'(?:connectionString="[^"]*(?:password=|Password=)[^"]+"|'
    r'key="[^"]*(?:Password|ApiKey|Secret|Token)[^"]*"\s*value="[^"]{4,}")',
    re.I,
)

# Hibernate config
_HIBERNATE_RE = re.compile(
    r'(?:<hibernate-configuration>|hibernate\.connection\.url|'
    r'hibernate\.connection\.password)',
    re.I,
)

# JPA persistence.xml
_JPA_RE = re.compile(
    r'(?:<persistence[^>]*xmlns|<persistence-unit|javax\.persistence\.)',
    re.I,
)

# Generic datasource / JDBC
_JDBC_RE = re.compile(
    r'(?:jdbc:[a-z]+://|dataSource\.password\s*=|'
    r'db\.password\s*=)',
    re.I,
)


def _is_framework_config(path: str, body: str) -> bool:
    """Return True if body matches the expected framework config format for this path."""
    low = path.lower()
    if "application.properties" in low:
        return bool(_SPRING_PROPS_RE.search(body) or _SPRING_DB_RE.search(body))
    elif "application.yml" in low or "application.yaml" in low:
        return bool(_SPRING_PROPS_RE.search(body) or _SPRING_DB_RE.search(body)
                    or _RAILS_DB_YML_RE.search(body))
    elif "appsettings" in low and low.endswith(".json"):
        return bool(_APPSETTINGS_RE.search(body))
    elif "database.yml" in low:
        return bool(_RAILS_DB_YML_RE.search(body))
    elif "secrets.yml" in low:
        return bool(_RAILS_SECRETS_RE.search(body))
    elif "master.key" in low:
        return bool(_RAILS_MASTER_KEY_RE.search(body))
    elif "credentials.yml.enc" in low:
        return len(body.strip()) > 10  # Any non-empty encrypted blob
    elif "database.php" in low:
        return bool(_LARAVEL_DB_PHP_RE.search(body))
    elif "settings.py" in low or "local_settings.py" in low:
        return bool(_DJANGO_SETTINGS_RE.search(body))
    elif "web.config" in low:
        return bool(_WEBCONFIG_RE.search(body))
    elif "hibernate.cfg.xml" in low:
        return bool(_HIBERNATE_RE.search(body))
    elif "persistence.xml" in low:
        return bool(_JPA_RE.search(body))
    elif ".properties" in low:
        return bool(_JDBC_RE.search(body) or _SPRING_PROPS_RE.search(body))
    elif "config.xml" in low:
        return bool(_HIBERNATE_RE.search(body) or "<configuration>" in body.lower())
    elif "app.php" in low or "mail.php" in low:
        return bool(_LARAVEL_DB_PHP_RE.search(body) or "return [" in body)
    return False


def _has_sensitive_creds(path: str, body: str) -> bool:
    """Return True if the config content contains actual credential values."""
    low = path.lower()
    if "application" in low:
        return bool(_SPRING_DB_RE.search(body) or _APPSETTINGS_CRED_RE.search(body))
    elif "database.yml" in low:
        return bool(_RAILS_PASSWORD_RE.search(body))
    elif "secrets.yml" in low:
        return bool(re.search(r'secret_key_base:\s*[a-f0-9]{20,}', body, re.I))
    elif "settings.py" in low:
        return bool(_DJANGO_SECRET_RE.search(body))
    elif "web.config" in low:
        return bool(_WEBCONFIG_CRED_RE.search(body))
    elif ".properties" in low:
        return bool(re.search(r'(?:password|secret|key)\s*=\s*\S{4,}', body, re.I))
    return False


# Probe definitions: (path, description, category, severity)
_LOG_PROBES: List[Tuple[str, str]] = [
    ("/storage/logs/laravel.log",  "Laravel application log"),
    ("/logs/error.log",            "Application error log"),
    ("/log/error.log",             "Application error log"),
    ("/app/logs/error.log",        "Java app error log"),
    ("/debug.log",                 "Debug log file"),
    ("/tmp/debug.log",             "Debug artifact log"),
    ("/application.log",           "Application log"),
    ("/server.log",                "Server log"),
    ("/catalina.out",              "Tomcat catalina log"),
    ("/var/log/app/app.log",       "System app log"),
    ("/logs/application.log",      "Application log (/logs/)"),
    ("/error.log",                 "Error log (root)"),
]

_CONFIG_PROBES: List[Tuple[str, str]] = [
    ("/application.properties",         "Spring Boot application.properties"),
    ("/application.yml",                "Spring Boot / application YAML"),
    ("/application.yaml",               "Application YAML config"),
    ("/appsettings.json",               "ASP.NET Core appsettings.json"),
    ("/appsettings.Development.json",   "ASP.NET Core development settings"),
    ("/config/database.yml",            "Rails database.yml"),
    ("/config/secrets.yml",             "Rails secrets.yml"),
    ("/config/master.key",              "Rails master.key (encryption key)"),
    ("/config/credentials.yml.enc",     "Rails encrypted credentials"),
    ("/config/database.php",            "Laravel database config"),
    ("/config/app.php",                 "Laravel application config"),
    ("/config/mail.php",                "Laravel mail config"),
    ("/local_settings.py",              "Django local settings"),
    ("/settings.py",                    "Django settings"),
    ("/web.config",                     "ASP.NET web.config"),
    ("/config.xml",                     "Application XML config"),
    ("/hibernate.cfg.xml",              "Hibernate ORM config"),
    ("/WEB-INF/web.xml",               "Java EE web descriptor"),
    ("/META-INF/persistence.xml",       "JPA persistence config"),
    ("/datasource.properties",          "JDBC datasource properties"),
]


class FrameworkConfigScanner(BaseScanner):
    """Detect exposed framework configuration files and application log files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Framework config — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        found_any = False

        # Probe log files
        for path, description in _LOG_PROBES:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r is None or r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if len(body) < 10:
                    continue
                if not _is_log_content(body):
                    continue

                has_auth = bool(_LOG_AUTH_TOKEN_RE.search(body))
                has_sql = bool(_LOG_SQL_RE.search(body))
                severity = "FAIL"
                detail = self._log_detail(probe_url, description, has_auth, has_sql)
                log_fail(logger, f"Log file exposed: {probe_url}")
                self.results.append(self._result(
                    probe_url,
                    f"Framework config — {description} publicly accessible",
                    severity,
                    detail=detail,
                ))
                found_any = True

            except Exception:
                continue

        # Probe framework config files
        for path, description in _CONFIG_PROBES:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r is None or r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if len(body) < 5:
                    continue
                if not _is_framework_config(path, body):
                    continue

                has_creds = _has_sensitive_creds(path, body)
                severity = "FAIL"
                detail = self._config_detail(probe_url, description, path, has_creds, body)
                log_fail(logger, f"Framework config exposed: {probe_url}")
                self.results.append(self._result(
                    probe_url,
                    f"Framework config — {description} publicly accessible",
                    severity,
                    detail=detail,
                ))
                found_any = True

            except Exception:
                continue

        if not found_any:
            log_pass(logger, f"No framework config or log files exposed on {base}")
            self.results.append(self._result(
                url,
                "Framework config — no configuration files or log files exposed",
                "PASS",
                detail=(
                    "Probed for Spring Boot application.properties/yml, ASP.NET appsettings.json, "
                    "Rails database.yml/secrets.yml/master.key, Laravel config files, "
                    "Django settings.py, Hibernate configs, JPA persistence.xml, "
                    "and application log files (error.log, laravel.log, catalina.out). "
                    "None were publicly accessible. "
                    "Fix: configure your web server to deny access to /config/, /logs/, "
                    "and all non-web-served file paths; never place config files in the web root."
                )
            ))

        return self.results

    def _log_detail(self, url: str, description: str, has_auth: bool, has_sql: bool) -> str:
        extras = []
        if has_auth:
            extras.append("Authentication tokens or session IDs detected in log entries. ")
        if has_sql:
            extras.append("SQL queries or database errors present in log content. ")
        if not extras:
            extras.append("Stack traces or application errors present in log file. ")
        return (
            f"Application log file is publicly accessible at {url} ({description}). "
            + "".join(extras)
            + "Log files may contain stack traces exposing internal paths and class names, "
            "SQL queries revealing database schema, authentication tokens from captured "
            "request headers, and PII from request/response logging. "
            "Fix: store log files outside the web root (e.g., /var/log/app/) and restrict "
            "web server access to /storage/logs/ and similar directories. "
            "Rotate and purge logs regularly. CWE-532."
        )

    def _config_detail(self, url: str, description: str, path: str,
                        has_creds: bool, body: str) -> str:
        cred_msg = ""
        if has_creds:
            cred_msg = "CRITICAL: Active credentials or secrets detected in the config file. Rotate immediately. "

        fix_map = {
            "application.properties": "Never place Spring Boot config in the web root; use environment variable injection for secrets.",
            "application.yml": "Use Spring Cloud Config or Kubernetes Secrets for production secrets rather than YAML files.",
            "appsettings": "Store connection strings in Azure Key Vault or environment variables rather than appsettings.json.",
            "database.yml": "The Rails database.yml should never be web-accessible; ensure config/ is blocked in your server config.",
            "secrets.yml": "Rails secrets.yml contains the master encryption key — rotate secret_key_base and all derived secrets.",
            "master.key": "The Rails master.key decrypts all credentials.yml.enc secrets — rotate all secrets immediately.",
            "settings.py": "Django SECRET_KEY and database passwords must not be in web-accessible files — use environment variables.",
            "web.config": "web.config may contain database connection strings with passwords — restrict access via IIS configuration.",
            "hibernate": "Hibernate config contains JDBC URLs and database passwords — never expose in web root.",
            "persistence.xml": "JPA persistence.xml contains datasource configuration — restrict access to META-INF/.",
            "laravel": "Laravel config files may expose database, mail, and API credentials — protect config/ with server rules.",
        }

        fix = "Remove this file from the web root or configure your web server to deny access."
        path_lower = path.lower()
        for key, msg in fix_map.items():
            if key in path_lower:
                fix = msg
                break

        return (
            f"Framework configuration file is publicly accessible at {url} ({description}). "
            + cred_msg
            + f"Fix: {fix} "
            "CWE-312, CWE-200, CWE-538."
        )
