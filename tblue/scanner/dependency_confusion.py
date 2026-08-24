"""Dependency confusion — scoped internal npm packages in HTML/JS and exposed manifest files."""
import re
import json as _json
from urllib.parse import urlparse
from .base import BaseScanner

_SCOPED_IMPORT_RE = re.compile(
    r'(?:from\s+["\']|require\s*\(\s*["\']|import\s*\(\s*["\'])'
    r'(@[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)',
    re.I,
)
_SCRIPT_SRC_SCOPED_RE = re.compile(
    r'<script\b[^>]*\bsrc=["\']([^"\']*/@[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+[^"\']*)["\']',
    re.I,
)
_PKG_NAME_RE = re.compile(r'"name"\s*:\s*"(@[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)"', re.I)

_INTERNAL_ORG_RE = re.compile(
    r'@(internal|private|corp|company|myapp|myorg|enterprise|backend|frontend|'
    r'infra|platform|shared|common|mono|repo|lib|utils|core|app)',
    re.I,
)

# Internal package name heuristics for non-scoped manifests
_INTERNAL_PKG_NAME_RE = re.compile(
    r'(?:^|\b)(internal|private|corp|company|enterprise)-[a-z0-9_\-]+',
    re.I | re.M,
)

_JS_PATHS = [
    "/js/app.js",
    "/static/js/main.js",
    "/assets/js/bundle.js",
    "/dist/bundle.js",
    "/bundle.js",
]

_MANIFEST_PATHS = [
    ("/package.json", "npm"),
    ("/requirements.txt", "pip"),
    ("/Pipfile", "pip"),
    ("/Gemfile", "gem"),
    ("/Gemfile.lock", "gem"),
    ("/composer.json", "composer"),
    ("/go.mod", "go"),
]


def _extract_scoped_packages(body: str) -> list:
    pkgs = set()
    for m in _SCOPED_IMPORT_RE.finditer(body):
        pkgs.add(m.group(1))
    for m in _SCRIPT_SRC_SCOPED_RE.finditer(body):
        pkgs.add(m.group(1))
    for m in _PKG_NAME_RE.finditer(body):
        pkgs.add(m.group(1))
    return list(pkgs)


def _check_packages_for_confusion(packages: list, url: str) -> list:
    findings = []
    internal_pkgs = [p for p in packages if _INTERNAL_ORG_RE.match(p)]
    if internal_pkgs:
        findings.append({
            "type": "dependency_confusion_internal_scope",
            "status": "FAIL",
            "url": url,
            "detail": (
                f"Internal-scoped npm packages exposed in client-side JS: "
                f"{', '.join(internal_pkgs[:5])} — if not on npmjs.com, "
                f"an attacker can register them and achieve RCE via dependency confusion"
            ),
        })
    elif packages:
        findings.append({
            "type": "dependency_confusion_scoped_packages",
            "status": "WARN",
            "url": url,
            "detail": (
                f"Scoped npm packages found in client-side JS: "
                f"{', '.join(list(packages)[:5])} — verify they are published publicly"
            ),
        })
    return findings


def _check_manifest_exposure(http, origin: str) -> list:
    """Probe for exposed dependency manifest files that reveal internal package names."""
    findings = []
    for path, ecosystem in _MANIFEST_PATHS:
        try:
            r = http.get(origin + path)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""

            manifest_url = origin + path

            # For package.json: parse JSON and check dependencies for scoped internal names
            if path == "/package.json":
                try:
                    data = _json.loads(body)
                    all_deps = {}
                    for section in ("dependencies", "devDependencies", "peerDependencies"):
                        all_deps.update(data.get(section, {}))
                    internal = [k for k in all_deps if _INTERNAL_ORG_RE.match(k)]
                    if internal:
                        findings.append({
                            "type": "dependency_confusion_manifest_internal_packages",
                            "status": "FAIL",
                            "url": manifest_url,
                            "detail": (
                                f"Exposed package.json reveals internal-scoped npm packages: "
                                f"{', '.join(internal[:5])} — dependency confusion attack vector"
                            ),
                        })
                        return findings
                    elif all_deps:
                        findings.append({
                            "type": "dependency_confusion_manifest_exposed",
                            "status": "WARN",
                            "url": manifest_url,
                            "detail": "package.json is publicly accessible — dependency names exposed for recon",
                        })
                        return findings
                except (_json.JSONDecodeError, AttributeError):
                    pass

            # For text-based manifests: check for internal-sounding package names
            elif _INTERNAL_PKG_NAME_RE.search(body):
                findings.append({
                    "type": "dependency_confusion_manifest_internal_packages",
                    "status": "WARN",
                    "url": manifest_url,
                    "detail": (
                        f"Exposed {path.lstrip('/')} reveals internal package names "
                        f"— potential dependency confusion target"
                    ),
                })
                return findings
            else:
                findings.append({
                    "type": "dependency_confusion_manifest_exposed",
                    "status": "WARN",
                    "url": manifest_url,
                    "detail": f"{path.lstrip('/')} is publicly accessible — dependency list exposed for attacker recon",
                })
                return findings

        except Exception:
            pass
    return findings


class DependencyConfusionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        all_packages: set = set()

        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "dependency_confusion_no_response", "PASS",
                                 detail="No response")]

        for pkg in _extract_scoped_packages(resp.text):
            all_packages.add(pkg)

        for path in _JS_PATHS:
            r = self.http.get(origin + path)
            if r and r.status_code == 200:
                for pkg in _extract_scoped_packages(r.text):
                    all_packages.add(pkg)

        for f in _check_packages_for_confusion(list(all_packages), url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_manifest_exposure(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "dependency_confusion_clean", "PASS",
                                        detail="No dependency confusion indicators found"))
        return results
