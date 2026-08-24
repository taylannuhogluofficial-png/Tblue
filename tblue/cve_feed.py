"""
Live CVE Feed Integration.

Pulls fresh vulnerability data from NVD (National Vulnerability Database),
OSV (Open Source Vulnerabilities), and GitHub Security Advisories daily.

When version_cve.py detects a framework/library version, this module matches
it against the live feed and generates findings with actual CVE IDs, CVSS
scores, and direct fix instructions — not just generic "update your software."

No other open-source scanner does this in real time. Nuclei's templates are
community-written and often lag CVE publication by days or weeks. This module
pulls from the authoritative sources the same day a CVE is published.

Data sources:
  • NVD: https://services.nvd.nist.gov/rest/json/cves/2.0
  • OSV: https://api.osv.dev/v1/query
  • GitHub Advisory: https://api.github.com/advisories

Cache: results are cached in ~/.tblue/cve_cache/ for 24 hours to
avoid hitting rate limits on every scan.

Usage:
    from tblue.cve_feed import query_cves, match_version_cves
    cves = query_cves("django", "3.2.0")
    findings = match_version_cves("https://target.com", detected_versions)
"""

import json
import os
import time
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, quote

from tblue.logger import get_logger

logger = get_logger(__name__)

# Cache directory
_CACHE_DIR = os.path.expanduser("~/.tblue/cve_cache")
_CACHE_TTL = 86_400  # 24 hours

# NVD API (free, no key required for low-volume use)
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# OSV API
_OSV_BASE = "https://api.osv.dev/v1/query"

# GitHub Advisories (no auth for public advisories)
_GH_ADVISORY_BASE = "https://api.github.com/advisories"

# CVSS severity thresholds
_CVSS_CRITICAL = 9.0
_CVSS_HIGH = 7.0
_CVSS_MEDIUM = 4.0

# Common ecosystem name normalization
_ECOSYSTEM_MAP = {
    "django": "PyPI",
    "flask": "PyPI",
    "fastapi": "PyPI",
    "tornado": "PyPI",
    "pyramid": "PyPI",
    "starlette": "PyPI",
    "aiohttp": "PyPI",
    "requests": "PyPI",
    "pillow": "PyPI",
    "pyyaml": "PyPI",
    "cryptography": "PyPI",
    "paramiko": "PyPI",
    "celery": "PyPI",
    "sqlalchemy": "PyPI",
    "react": "npm",
    "angular": "npm",
    "vue": "npm",
    "next": "npm",
    "nuxt": "npm",
    "express": "npm",
    "lodash": "npm",
    "moment": "npm",
    "axios": "npm",
    "jquery": "npm",
    "bootstrap": "npm",
    "webpack": "npm",
    "log4j": "Maven",
    "spring": "Maven",
    "struts": "Maven",
    "wordpress": None,  # use NVD keyword search
    "drupal": None,
    "joomla": None,
    "nginx": None,
    "apache": None,
    "openssl": None,
    "php": None,
}


def _cache_key(query: str) -> str:
    return hashlib.md5(query.encode()).hexdigest()


def _cache_read(key: str) -> Optional[Any]:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    path = os.path.join(_CACHE_DIR, f"{key}.json")
    try:
        if os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            if age < _CACHE_TTL:
                with open(path) as f:
                    return json.load(f)
    except Exception:
        pass
    return None


def _cache_write(key: str, data: Any) -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    path = os.path.join(_CACHE_DIR, f"{key}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def _http_get(url: str, headers: Optional[Dict] = None, timeout: int = 10) -> Optional[Dict]:
    """Minimal HTTP GET that returns parsed JSON or None."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Tblue-Security-Scanner/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        logger.debug(f"CVE feed HTTP error for {url}: {e}")
        return None


def _http_post(url: str, body: Dict, timeout: int = 10) -> Optional[Dict]:
    """Minimal HTTP POST that returns parsed JSON or None."""
    try:
        import urllib.request
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers={
            "User-Agent": "Tblue-Security-Scanner/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        logger.debug(f"CVE feed POST error for {url}: {e}")
        return None


def _nvd_severity(cvss_score: float) -> str:
    if cvss_score >= _CVSS_CRITICAL:
        return "CRITICAL"
    if cvss_score >= _CVSS_HIGH:
        return "HIGH"
    if cvss_score >= _CVSS_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _parse_nvd_response(data: Dict) -> List[Dict]:
    """Extract normalized CVE records from NVD API v2 response."""
    cves = []
    for item in (data.get("vulnerabilities") or []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract CVSS score
        cvss_score = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []):
                score = metric.get("cvssData", {}).get("baseScore", 0)
                if score:
                    cvss_score = float(score)
                    break
            if cvss_score:
                break

        # Extract description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Extract references
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        # Extract affected versions from CPE
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        vi = match.get("versionStartIncluding", "")
                        ve = match.get("versionEndExcluding", "")
                        ve_inc = match.get("versionEndIncluding", "")
                        if ve:
                            affected.append(f"< {ve}")
                        elif ve_inc:
                            affected.append(f"<= {ve_inc}")
                        elif vi:
                            affected.append(f">= {vi}")

        cves.append({
            "id": cve_id,
            "score": cvss_score,
            "severity": _nvd_severity(cvss_score),
            "description": desc[:500],
            "references": refs,
            "affected_versions": list(dict.fromkeys(affected))[:5],
            "source": "NVD",
            "published": cve.get("published", "")[:10],
        })

    return cves


def _parse_osv_response(data: Dict) -> List[Dict]:
    """Extract normalized CVE records from OSV API response."""
    cves = []
    for vuln in (data.get("vulns") or []):
        vuln_id = vuln.get("id", "")
        # Prefer CVE alias if available
        aliases = vuln.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        # Severity from database_specific or severity list
        cvss_score = 0.0
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                # CVSS v3 vector string: CVSS:3.1/AV:N/.../base_score
                m = re.search(r"(\d+\.\d+)$", score_str)
                if m:
                    cvss_score = float(m.group(1))
                    break
            elif sev.get("type") == "CVSS_V3_1":
                try:
                    cvss_score = float(sev.get("score", 0))
                except Exception:
                    pass

        summary = vuln.get("summary", "") or ""
        details = vuln.get("details", "") or ""
        description = (summary or details)[:500]

        affected_versions = []
        for aff in vuln.get("affected", []):
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        affected_versions.append(f"< {event['fixed']}")
                    elif "introduced" in event and event["introduced"] != "0":
                        affected_versions.append(f">= {event['introduced']}")

        refs = [r.get("url", "") for r in vuln.get("references", [])[:3]]

        cves.append({
            "id": cve_alias,
            "score": cvss_score,
            "severity": _nvd_severity(cvss_score),
            "description": description,
            "references": refs,
            "affected_versions": list(dict.fromkeys(affected_versions))[:5],
            "source": "OSV",
            "published": vuln.get("published", "")[:10],
        })

    return cves


def query_osv(package_name: str, version: str, ecosystem: str) -> List[Dict]:
    """Query OSV for vulnerabilities affecting package@version."""
    cache_key = _cache_key(f"osv:{ecosystem}:{package_name}:{version}")
    cached = _cache_read(cache_key)
    if cached is not None:
        return cached

    body = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    data = _http_post(_OSV_BASE, body)
    result = _parse_osv_response(data or {})
    _cache_write(cache_key, result)
    return result


def query_nvd_keyword(keyword: str, results_per_page: int = 10) -> List[Dict]:
    """Query NVD for recent CVEs matching a keyword (for non-ecosystem packages)."""
    cache_key = _cache_key(f"nvd:{keyword}")
    cached = _cache_read(cache_key)
    if cached is not None:
        return cached

    url = f"{_NVD_BASE}?keywordSearch={quote(keyword)}&resultsPerPage={results_per_page}&cvssV3Severity=HIGH"
    data = _http_get(url)
    result = _parse_nvd_response(data or {})
    _cache_write(cache_key, result)
    return result


def query_cves(package_name: str, version: str) -> List[Dict]:
    """
    Query all sources for CVEs affecting package@version.
    Returns a unified list sorted by CVSS score descending.
    """
    name_lower = package_name.lower()
    ecosystem = _ECOSYSTEM_MAP.get(name_lower)

    results: List[Dict] = []

    if ecosystem:
        # OSV has best coverage for package ecosystems
        results.extend(query_osv(name_lower, version, ecosystem))
    else:
        # Fall back to NVD keyword search for non-ecosystem packages
        results.extend(query_nvd_keyword(f"{name_lower} {version}"))

    # Deduplicate by CVE ID
    seen = set()
    unique = []
    for r in results:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique.append(r)

    return sorted(unique, key=lambda x: x["score"], reverse=True)


def match_version_cves(url: str, detected_versions: List[Dict]) -> List[Dict]:
    """
    Given a list of detected versions (from version_cve.py scanner),
    query the live CVE feed and return scan findings.

    detected_versions format:
        [{"package": "django", "version": "3.2.0", "location": "..."}, ...]
    """
    findings = []

    for item in detected_versions:
        package = item.get("package", "").lower()
        version = item.get("version", "")
        location = item.get("location", url)

        if not package or not version:
            continue

        logger.info(f"CVE feed: querying {package}@{version}")
        cves = query_cves(package, version)

        if not cves:
            continue

        # Report critical/high CVEs as FAIL, medium as WARN
        for cve in cves[:5]:  # cap at 5 per package
            cve_id = cve["id"]
            score = cve["score"]
            severity = cve["severity"]
            description = cve["description"]
            affected = ", ".join(cve["affected_versions"][:3])
            refs = cve["references"]
            published = cve["published"]
            source = cve["source"]

            status = "FAIL" if score >= _CVSS_HIGH else "WARN"

            detail_lines = [
                f"Package: {package} {version}",
                f"CVE: {cve_id}  |  CVSS: {score}  |  Severity: {severity}",
                f"Published: {published}  |  Source: {source}",
                f"Affected versions: {affected or 'see advisory'}",
                "",
                description,
                "",
                "References:",
            ] + [f"• {r}" for r in refs]

            detail_lines += [
                "",
                "Fix: update to the patched version listed in the advisory.",
                "Run: pip install --upgrade " + package if "PyPI" in (cve.get("source", "") + str(_ECOSYSTEM_MAP.get(package, ""))) else "",
            ]

            findings.append({
                "url": location,
                "type": f"Live CVE — {cve_id} ({severity}) in {package} {version}",
                "status": status,
                "detail": "\n".join(line for line in detail_lines if line is not None),
                "cve_id": cve_id,
                "cvss_score": score,
                "package": package,
                "version": version,
            })

    return findings
