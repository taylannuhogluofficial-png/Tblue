"""Form action security — javascript:/data: actions, external domain, HTTP on HTTPS, missing CSRF token."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_FORM_RE = re.compile(r'<form\b[^>]*>.*?</form>', re.I | re.S)
_ACTION_ATTR_RE = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.I)

_JS_ACTION_RE = re.compile(r'^javascript\s*:', re.I)
_DATA_ACTION_RE = re.compile(r'^data\s*:', re.I)
_PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type\s*=\s*["\']password["\']', re.I)
_CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name\s*=\s*["\'](?:csrf[^"\']*|_token|authenticity_token)["\']', re.I
)

_DETAILS = {
    'form_action_javascript_xss':  'Form action="javascript:..." triggers arbitrary JS on submit (XSS via form action)',
    'form_action_data_uri':        'Form action="data:..." may render HTML/JS in browser (XSS via data URI)',
    'form_action_http_on_https':   'Form on HTTPS page posts to HTTP URL — credentials/PII in cleartext, vulnerable to MITM',
    'form_action_external_domain': 'Form posts to external domain — verify intent; may exfiltrate user data to third-party',
    'form_action_csrf_missing':    'Login/password form has no CSRF token hidden field — susceptible to cross-site request forgery',
}


def _is_external(action: str, page_host: str) -> bool:
    if not action or action.startswith('#') or action.startswith('?'):
        return False
    if _JS_ACTION_RE.match(action) or _DATA_ACTION_RE.match(action):
        return False
    try:
        parsed = urlparse(action)
        if parsed.scheme in ('http', 'https') and parsed.netloc:
            return parsed.netloc != page_host
    except Exception:
        pass
    return False


def _check_form(form_html: str, page_url: str, page_host: str) -> list:
    """Inspect a full <form>...</form> HTML string and return a list of {type, status} dicts."""
    findings = []
    page_scheme = urlparse(page_url).scheme

    action_m = _ACTION_ATTR_RE.search(form_html)
    action = action_m.group(1).strip() if action_m else ''

    if _JS_ACTION_RE.match(action):
        findings.append({'type': 'form_action_javascript_xss', 'status': 'FAIL'})
    elif _DATA_ACTION_RE.match(action):
        findings.append({'type': 'form_action_data_uri', 'status': 'FAIL'})
    elif action and page_scheme == 'https' and action.startswith('http://'):
        findings.append({'type': 'form_action_http_on_https', 'status': 'FAIL'})
    elif _is_external(action, page_host):
        findings.append({'type': 'form_action_external_domain', 'status': 'WARN'})

    if _PASSWORD_INPUT_RE.search(form_html) and not _CSRF_INPUT_RE.search(form_html):
        findings.append({'type': 'form_action_csrf_missing', 'status': 'WARN'})

    return findings


class FormActionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, 'form_action_no_response', 'PASS', detail='No response')]

        body = resp.text or ''
        parsed = urlparse(url)
        page_host = parsed.netloc

        forms = list(_FORM_RE.finditer(body))
        if not forms:
            return [self._result(url, 'form_action_no_forms', 'PASS',
                                 detail='No HTML forms found on this page')]

        results = []
        seen = set()
        for m in forms:
            for finding in _check_form(m.group(0), url, page_host):
                ftype = finding['type']
                if ftype not in seen:
                    seen.add(ftype)
                    results.append(self._result(url, ftype, finding['status'],
                                                detail=_DETAILS.get(ftype, '')))

        return results or [self._result(url, 'form_action_clean', 'PASS',
                                        detail=f'Checked {len(forms)} form(s) — no issues found')]
