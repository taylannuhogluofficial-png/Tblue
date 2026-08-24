"""
SIEM-native export formats for Tblue.

Supports:
  cef      — Common Event Format (ArcSight, most SIEMs)
  leef     — Log Event Extended Format (IBM QRadar)
  elastic  — Elastic Common Schema NDJSON (Elastic Security / SIEM)
  sentinel — Microsoft Sentinel / Azure Monitor JSON array

Usage (CLI):
  python -m tblue -u https://example.com --siem elastic -o report.ndjson
  python -m tblue -u https://example.com --siem cef -o findings.cef

Usage (Python):
  from tblue.report.siem import generate
  generate(target, all_results, "findings.cef", fmt="cef", scan_score=score)
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from tblue import __version__
from tblue.scoring import classify_severity

_VENDOR  = "Tblue"
_PRODUCT = "Tblue"

# CEF integer severity (0-10)
_CEF_SEV: Dict[str, int] = {
    "critical": 10,
    "high":     8,
    "medium":   6,
    "low":      4,
    "info":     1,
}

# Elastic ECS severity integer (0-100)
_ECS_SEV: Dict[str, int] = {
    "critical": 99,
    "high":     73,
    "medium":   47,
    "low":      21,
    "info":     1,
}

# ECS event.type by status
_ECS_TYPE: Dict[str, str] = {
    "FAIL": "denied",
    "WARN": "info",
    "PASS": "allowed",
}


def generate(
    target: str,
    all_results: Dict[str, List[Dict[str, Any]]],
    output_path: str,
    fmt: str = "elastic",
    scan_score=None,
) -> None:
    """Write SIEM-format findings to output_path.

    fmt: one of 'cef', 'leef', 'elastic', 'sentinel'
    """
    fmt = fmt.lower().strip()
    flat = _flatten(target, all_results)

    if fmt == "cef":
        content = _to_cef(flat)
    elif fmt == "leef":
        content = _to_leef(flat)
    elif fmt == "elastic":
        content = _to_elastic_ndjson(flat, scan_score)
    elif fmt == "sentinel":
        content = _to_sentinel_json(flat, scan_score)
    else:
        raise ValueError(f"Unknown SIEM format: {fmt!r}. Choose: cef, leef, elastic, sentinel")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")



def _flatten(
    target: str,
    all_results: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Return all non-PASS findings as a flat list with severity injected."""
    out = []
    for module, results in all_results.items():
        for r in results:
            status = r.get("status", "PASS")
            if status == "PASS":
                continue
            rtype = r.get("type", "")
            sev   = classify_severity(rtype, status)
            out.append({
                "module":   module,
                "type":     rtype,
                "status":   status,
                "severity": sev,
                "url":      r.get("url", target),
                "detail":   r.get("detail", ""),
            })
    return out


def _cef_escape(s: str) -> str:
    """Escape special characters for CEF extension values."""
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _leef_escape(s: str) -> str:
    """LEEF tab-separated values must not contain tabs or newlines."""
    return s.replace("\t", " ").replace("\n", " ").replace("\r", "")


# ── CEF ───────────────────────────────────────────────────────────────────────

def _to_cef(flat: List[Dict[str, Any]]) -> str:
    """
    CEF:Version|Device Vendor|Device Product|Device Version|
        Signature ID|Name|Severity|Extension
    """
    lines = []
    ts = _now_iso()
    for f in flat:
        sig_id  = _cef_slug(f["type"])
        name    = _cef_escape(f["type"])
        sev_num = _CEF_SEV.get(f["severity"], 5)
        ext = (
            f"rt={ts} "
            f"dst={_cef_escape(f['url'])} "
            f"cat={f['module']} "
            f"cs1={f['status']} "
            f"cs1Label=Status "
            f"cs2={f['severity'].upper()} "
            f"cs2Label=Severity "
            f"msg={_cef_escape(f['detail'][:512])}"
        )
        line = (
            f"CEF:0|{_VENDOR}|{_PRODUCT}|{__version__}|"
            f"{sig_id}|{name}|{sev_num}|{ext}"
        )
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


def _cef_slug(rtype: str) -> str:
    slug = rtype.upper()
    for ch in " —–-.,()[]{}/:":
        slug = slug.replace(ch, "_")
    return slug[:32].strip("_")


# ── LEEF ─────────────────────────────────────────────────────────────────────

def _to_leef(flat: List[Dict[str, Any]]) -> str:
    """
    LEEF:Version|Vendor|Product|Version|EventID|attr=val\tattr=val...
    """
    lines = []
    ts = _now_iso()
    for f in flat:
        event_id = _cef_slug(f["type"])
        attrs = "\t".join([
            f"devTime={ts}",
            "devTimeFormat=ISO 8601",
            f"cat={_leef_escape(f['module'])}",
            f"dstURL={_leef_escape(f['url'])}",
            f"severity={f['severity'].upper()}",
            f"status={f['status']}",
            f"ruleName={_leef_escape(f['type'][:128])}",
            f"msg={_leef_escape(f['detail'][:512])}",
        ])
        line = f"LEEF:1.0|{_VENDOR}|{_PRODUCT}|{__version__}|{event_id}|{attrs}"
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


# ── Elastic NDJSON (ECS) ──────────────────────────────────────────────────────

def _to_elastic_ndjson(flat: List[Dict[str, Any]], scan_score=None) -> str:
    """
    Newline-delimited JSON following Elastic Common Schema (ECS 8.x).
    Each finding is one JSON object per line.
    """
    ts = _now_iso()
    lines = []
    for f in flat:
        doc = {
            "@timestamp":       ts,
            "event": {
                "kind":     "alert",
                "category": ["web"],
                "type":     [_ECS_TYPE.get(f["status"], "info")],
                "severity": _ECS_SEV.get(f["severity"], 21),
                "outcome":  "failure" if f["status"] == "FAIL" else "unknown",
                "module":   f["module"],
                "dataset":  f"tblue.{f['module']}",
            },
            "rule": {
                "name":      f["type"],
                "category":  f["module"],
                "id":        _cef_slug(f["type"]),
            },
            "url": {
                "full": f["url"],
            },
            "message":  f["detail"] or f["type"],
            "labels": {
                "status":   f["status"],
                "severity": f["severity"],
            },
            "observer": {
                "product": _PRODUCT,
                "vendor":  _VENDOR,
                "version": __version__,
            },
            "tags": ["tblue", "web-security", f["severity"]],
        }
        if scan_score is not None:
            doc["labels"]["security_score"] = str(scan_score.score)
            doc["labels"]["security_grade"] = scan_score.grade
        lines.append(json.dumps(doc, separators=(",", ":")))
    return "\n".join(lines) + ("\n" if lines else "")


# ── Microsoft Sentinel / Azure Monitor ────────────────────────────────────────

def _to_sentinel_json(flat: List[Dict[str, Any]], scan_score=None) -> str:
    """
    JSON array compatible with Azure Monitor Log Analytics custom table ingest.
    Field names follow Azure Monitor naming conventions (PascalCase).
    """
    ts = _now_iso()
    records = []
    for f in flat:
        rec: Dict[str, Any] = {
            "TimeGenerated": ts,
            "SourceSystem":  _VENDOR,
            "Product":       _PRODUCT,
            "ProductVersion": __version__,
            "URL":           f["url"],
            "RuleName":      f["type"],
            "Category":      f["module"],
            "Status":        f["status"],
            "Severity":      f["severity"].upper(),
            "Detail":        f["detail"][:1024],
            "EventID":       _cef_slug(f["type"]),
        }
        if scan_score is not None:
            rec["SecurityScore"] = scan_score.score
            rec["SecurityGrade"] = scan_score.grade
        records.append(rec)
    return json.dumps(records, indent=2)
