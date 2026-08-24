"""Debug Endpoint Exposure scanner — passive detection of debug/diagnostic interfaces in production."""
import re
from .base import BaseScanner

_DEE_ANY_RE = re.compile(
    r'(?:/_debug|/__debug__|django\.conf\.settings|DJANGO_DEBUG|'
    r'DEBUG\s*=\s*True|Werkzeug\s+Debugger|Interactive\s+Console|'
    r'debugtoolbar|debug-toolbar|djdt|flask\.debugger|'
    r'Traceback\s+\(most\s+recent\s+call\s+last\)|'
    r'DebugKit|laravel-debugbar|APP_DEBUG|telescope|ignition)',
    re.I,
)

_DEE_DJANGO_DEBUG_RE = re.compile(
    r'(?:DJANGO_DEBUG\s*=\s*True|DEBUG\s*=\s*True[^a-zA-Z]|'
    r'django\.conf\.settings.*DEBUG|'
    r'<dt>Request\s+Method\s*:</dt>.*<dt>Request\s+URL\s*:</dt>)',
    re.I | re.S,
)

_DEE_WERKZEUG_RE = re.compile(
    r'(?:Werkzeug\s+Debugger|Interactive\s+Console|'
    r'debugger\.js\?s=|__debugger__\?cmd=|'
    r'The\s+debugger\s+caught\s+an\s+exception)',
    re.I,
)

_DEE_DJANGO_TOOLBAR_RE = re.compile(
    r'(?:djdt\.|django-debug-toolbar|debugtoolbar|'
    r'id=["\']djDebug["\']|class=["\']djdt)',
    re.I,
)

_DEE_LARAVEL_DEBUG_RE = re.compile(
    r'(?:laravel-debugbar|APP_DEBUG\s*=\s*true|'
    r'telescope\.laravel|ignition\.spatie|'
    r'Whoops!.*Laravel|laravel\.log)',
    re.I | re.S,
)

_DEE_TRACEBACK_RE = re.compile(
    r'Traceback\s+\(most\s+recent\s+call\s+last\)[\s\S]{0,2000}?(?:Error|Exception|DoesNotExist|NotFound|Invalid)[\s:,]',
    re.I,
)

_DEE_DEBUG_HEADER_RE = re.compile(
    r'(?:X-Debug-Token|X-DebugKit|X-Debug-Info|X-Powered-By:\s*PHP/[0-9])',
    re.I,
)


class DebugEndpointExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "debug_endpoint_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _DEE_ANY_RE.search(body) and not _DEE_ANY_RE.search(headers_str) and not _DEE_ANY_RE.search(url):
            return [self._result(url, "debug_endpoint_not_used", "PASS")]

        findings = []

        if _DEE_DJANGO_DEBUG_RE.search(body):
            findings.append(self._result(
                url, "debug_endpoint_django_debug_page", "FAIL",
                detail="Django DEBUG=True error page detected in production — reveals full stack trace, local variable values at each frame, Django settings (SECRET_KEY, DATABASES, ALLOWED_HOSTS), SQL queries executed, and installed app list; provides attacker complete server-side context for targeted exploitation.",
            ))

        if _DEE_WERKZEUG_RE.search(body):
            findings.append(self._result(
                url, "debug_endpoint_werkzeug_debugger", "FAIL",
                detail="Werkzeug Interactive Debugger active in production — provides browser-accessible Python REPL with full server process access; attacker can execute arbitrary OS commands, read /etc/passwd, access database, and exfiltrate secrets without any authentication.",
            ))

        if _DEE_DJANGO_TOOLBAR_RE.search(body):
            findings.append(self._result(
                url, "debug_endpoint_django_toolbar", "WARN",
                detail="Django Debug Toolbar present in production response — exposes SQL query log (with parameter values), template rendering timeline, cache hit/miss statistics, signal list, and request/response headers; leaks internal query patterns and application structure.",
            ))

        if _DEE_LARAVEL_DEBUG_RE.search(body):
            findings.append(self._result(
                url, "debug_endpoint_laravel_debug", "FAIL",
                detail="Laravel debug interface (Debugbar/Telescope/Ignition/Whoops) active in production — Ignition provides a solution suggestion interface that can execute arbitrary PHP; Telescope logs all requests, queries, exceptions, and queued jobs; Whoops exposes full exception context with local variables.",
            ))

        if _DEE_TRACEBACK_RE.search(body):
            findings.append(self._result(
                url, "debug_endpoint_stack_trace_exposed", "FAIL",
                detail="Full stack trace exposed in production response — reveals server file paths, framework/library versions, function call chain with argument values, and source code excerpts; enables targeted CVE lookup and path-based exploitation.",
            ))

        if _DEE_DEBUG_HEADER_RE.search(headers_str):
            findings.append(self._result(
                url, "debug_endpoint_debug_header", "WARN",
                detail="Debug header in HTTP response (X-Debug-Token, X-DebugKit, or PHP version via X-Powered-By) — reveals profiler session token allowing access to Symfony profiler data, or precise PHP version enabling version-specific exploit selection.",
            ))

        return findings or [self._result(url, "debug_endpoint_safe", "PASS")]
