"""
JSON report export for Tblue.
Allows programmatic use of scan results.
"""

import json
from datetime import datetime

from tblue import __version__


def generate(target, all_results, output_path, scan_score=None):
    """Export all scan results as JSON."""

    summary: dict = {
        "passed":  _count(all_results, "PASS"),
        "failed":  _count(all_results, "FAIL"),
        "warned":  _count(all_results, "WARN"),
    }

    if scan_score is not None:
        summary["score"] = {
            "value":          scan_score.score,
            "grade":          scan_score.grade,
            "total_deducted": scan_score.total_deducted,
            "breakdown": {
                sev: {
                    "count":      scan_score.breakdown[sev],
                    "deductions": scan_score.deductions[sev],
                }
                for sev in scan_score.breakdown
            },
        }

    output = {
        "tblue_version": __version__,
        "target":            target,
        "scanned_at":        datetime.now().isoformat(),
        "summary":           summary,
        "results":           all_results,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


def _count(all_results, status):
    return sum(
        1 for v in all_results.values()
        for r in v
        if r.get("status") == status
    )
