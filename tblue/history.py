"""
Scan history and trend tracking for Tblue.

Stores scan results under ~/.tblue/history/<sanitised-domain>/.
On each scan, loads the most recent previous snapshot and computes a diff:
  - Score change (up / down / same)
  - New issues that weren't in the last scan
  - Resolved issues (were failing, now passing)
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tblue.scoring import ScanScore

_HISTORY_ROOT = Path.home() / ".tblue" / "history"

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _domain_dir(target: str) -> Path:
    """Return the history directory for a target URL."""
    # Strip scheme, extract host, sanitise for filesystem
    host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    safe = _SAFE_NAME_RE.sub("_", host)
    return _HISTORY_ROOT / safe


def save_snapshot(
    target: str,
    all_results: Dict[str, List[Dict[str, Any]]],
    scan_score: ScanScore,
) -> Path:
    """
    Save the current scan as a JSON snapshot.
    Returns the path of the written file.
    """
    history_dir = _domain_dir(target)
    history_dir.mkdir(parents=True, exist_ok=True)

    ts       = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = history_dir / f"{ts}.json"

    payload = {
        "target":     target,
        "scanned_at": datetime.now().isoformat(),
        "score":      scan_score.score,
        "grade":      scan_score.grade,
        "breakdown":  scan_score.breakdown,
        "deductions": scan_score.deductions,
        "results":    all_results,
    }

    with open(filename, "w") as f:
        json.dump(payload, f, indent=2)

    return filename


def load_score_history(target: str, max_count: int = 12) -> List[Dict[str, Any]]:
    """
    Load the last max_count scan snapshots for sparkline chart rendering.
    Returns list of dicts with 'scanned_at', 'score', 'grade' — oldest first.
    """
    history_dir = _domain_dir(target)
    if not history_dir.exists():
        return []

    snapshots = sorted(history_dir.glob("*.json"))
    result = []
    for path in snapshots[-max_count:]:
        try:
            with open(path) as f:
                data = json.load(f)
            result.append({
                "scanned_at": data.get("scanned_at", ""),
                "score":      data.get("score", 0),
                "grade":      data.get("grade", "?"),
            })
        except Exception:
            continue
    return result


def load_previous_snapshot(target: str) -> Optional[Dict[str, Any]]:
    """
    Load the most recent previous scan snapshot for this target.
    Returns None if no history exists.
    """
    history_dir = _domain_dir(target)
    if not history_dir.exists():
        return None

    snapshots = sorted(history_dir.glob("*.json"))
    if not snapshots:
        return None

    latest = snapshots[-1]
    try:
        with open(latest) as f:
            return json.load(f)
    except Exception:
        return None


# ── Diff computation ──────────────────────────────────────────────────────────

def _result_key(r: Dict[str, Any]) -> str:
    """Stable identity key for a result — ignores URL so page-level changes don't noise the diff."""
    return r.get("type", "")


def compute_diff(
    current_results: Dict[str, List[Dict[str, Any]]],
    current_score: ScanScore,
    previous: Optional[Dict[str, Any]],
) -> "ScanDiff":
    """
    Compare current scan against previous snapshot.
    Returns a ScanDiff describing what changed.
    """
    if previous is None:
        return ScanDiff(is_first_scan=True)

    prev_score = previous.get("score", 0)
    score_delta = current_score.score - prev_score

    # Build sets of (type, status) pairs for each scan
    def _failing(results_dict: Dict) -> Dict[str, str]:
        """Map result_key → status for non-PASS results."""
        out = {}
        for module_results in results_dict.values():
            for r in module_results:
                if r.get("status") in ("FAIL", "WARN"):
                    key = _result_key(r)
                    if key:
                        out[key] = r.get("status", "WARN")
        return out

    prev_results = previous.get("results", {})
    curr_failing  = _failing(current_results)
    prev_failing  = _failing(prev_results)

    new_issues      = {k: v for k, v in curr_failing.items() if k not in prev_failing}
    resolved_issues = {k: v for k, v in prev_failing.items() if k not in curr_failing}
    worsened        = {
        k: (prev_failing[k], curr_failing[k])
        for k in curr_failing
        if k in prev_failing and prev_failing[k] == "WARN" and curr_failing[k] == "FAIL"
    }

    return ScanDiff(
        is_first_scan    = False,
        score_delta      = score_delta,
        prev_score       = prev_score,
        prev_grade       = previous.get("grade", "?"),
        new_issues       = new_issues,
        resolved_issues  = resolved_issues,
        worsened_issues  = worsened,
        prev_scanned_at  = previous.get("scanned_at", ""),
    )


class ScanDiff:
    """Result of comparing current scan to a previous snapshot."""

    def __init__(
        self,
        is_first_scan:   bool = False,
        score_delta:     int  = 0,
        prev_score:      int  = 0,
        prev_grade:      str  = "",
        new_issues:      Optional[Dict[str, str]] = None,
        resolved_issues: Optional[Dict[str, str]] = None,
        worsened_issues: Optional[Dict] = None,
        prev_scanned_at: str = "",
    ) -> None:
        self.is_first_scan   = is_first_scan
        self.score_delta     = score_delta
        self.prev_score      = prev_score
        self.prev_grade      = prev_grade
        self.new_issues      = new_issues or {}
        self.resolved_issues = resolved_issues or {}
        self.worsened_issues = worsened_issues or {}
        self.prev_scanned_at = prev_scanned_at

    @property
    def has_changes(self) -> bool:
        return bool(self.new_issues or self.resolved_issues or self.worsened_issues or self.score_delta != 0)
