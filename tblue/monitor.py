"""
Continuous Monitoring Mode.

Runs Tblue on a schedule and alerts only when something changes.
This turns Tblue from a one-shot tool into a security service.

What it does:
  • Scans the target on every tick (interval configurable, default 6 hours)
  • Compares results to the previous scan using the history system
  • Alerts ONLY on new findings (not re-alerts on existing known issues)
  • Sends alerts to Slack / Teams / Discord / webhook (reuses notify.py)
  • Writes a diff report when new issues are detected
  • Exit 0 if nothing changed; exit 2 if new critical/high findings

The key insight: security state changes on deploys, config changes, and
dependency updates — not on a random Tuesday. Continuous monitoring catches
the deploy that accidentally removed your CSP header, the npm update that
introduced a vulnerable package, or the S3 bucket that got un-privatized.

Usage:
    python -m tblue --monitor --interval 6h -u https://yoursite.com
    python -m tblue --monitor --interval 1h -u https://yoursite.com --notify slack:https://hooks.slack.com/...

Daemon mode:
    Runs in-process with sleep intervals. For production use, wrap in
    systemd, supervisord, or a Docker container with restart=always.
"""

import time
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable

from tblue.logger import get_logger, log_head

logger = get_logger(__name__)


def parse_interval(interval_str: str) -> int:
    """Parse interval string like '6h', '30m', '1d' into seconds."""
    interval_str = interval_str.strip().lower()
    if interval_str.endswith("d"):
        return int(interval_str[:-1]) * 86_400
    if interval_str.endswith("h"):
        return int(interval_str[:-1]) * 3_600
    if interval_str.endswith("m"):
        return int(interval_str[:-1]) * 60
    if interval_str.endswith("s"):
        return int(interval_str[:-1])
    # Bare integer = seconds
    return int(interval_str)


def _count_by_status(results: Dict[str, List]) -> Dict[str, int]:
    counts: Dict[str, int] = {"FAIL": 0, "WARN": 0, "PASS": 0}
    for findings in results.values():
        for f in findings:
            status = f.get("status", "")
            if status in counts:
                counts[status] += 1
    return counts


def _extract_new_findings(current: Dict[str, List], previous_snapshot: Optional[Dict]) -> List[Dict]:
    """Return findings that are in current but not in the previous snapshot."""
    if not previous_snapshot:
        return []

    prev_types = set()
    for module_results in previous_snapshot.get("results", {}).values():
        for f in module_results:
            if f.get("status") in ("FAIL", "WARN"):
                prev_types.add(f.get("type", ""))

    new_findings = []
    for findings in current.values():
        for f in findings:
            if f.get("status") in ("FAIL", "WARN") and f.get("type", "") not in prev_types:
                new_findings.append(f)

    return new_findings


def _build_alert_message(
    target: str,
    new_findings: List[Dict],
    counts: Dict[str, int],
    scan_score,
) -> str:
    """Build a concise alert message for notifications."""
    fails = [f for f in new_findings if f.get("status") == "FAIL"]
    warns = [f for f in new_findings if f.get("status") == "WARN"]

    score_str = f"{scan_score.score}/100 ({scan_score.grade})" if scan_score else "N/A"

    lines = [
        f"🚨 Tblue: {len(new_findings)} NEW finding(s) on {target}",
        f"Score: {score_str}  |  Total: {counts['FAIL']} FAIL, {counts['WARN']} WARN",
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    if fails:
        lines.append(f"🔴 NEW CRITICAL/HIGH ({len(fails)}):")
        for f in fails[:5]:
            lines.append(f"  • {f.get('type', 'Unknown')}")
        if len(fails) > 5:
            lines.append(f"  ... and {len(fails) - 5} more")

    if warns:
        lines.append(f"🟡 NEW WARNINGS ({len(warns)}):")
        for f in warns[:3]:
            lines.append(f"  • {f.get('type', 'Unknown')}")
        if len(warns) > 3:
            lines.append(f"  ... and {len(warns) - 3} more")

    return "\n".join(lines)


def _build_clear_message(target: str, counts: Dict[str, int], scan_score) -> str:
    """Build a message when no new findings are detected."""
    score_str = f"{scan_score.score}/100 ({scan_score.grade})" if scan_score else "N/A"
    return (
        f"✅ Tblue: No new findings on {target}\n"
        f"Score: {score_str}  |  "
        f"{counts['FAIL']} FAIL, {counts['WARN']} WARN  |  "
        f"{datetime.now().strftime('%H:%M:%S')}"
    )


class MonitorSession:
    """
    Continuous monitoring loop.

    Call run() to start; it will loop indefinitely (or until stop()).
    """

    def __init__(
        self,
        target: str,
        interval_seconds: int,
        scan_fn: Callable,
        notify_fn: Optional[Callable] = None,
        alert_on_new_only: bool = True,
        alert_on_clear: bool = False,
        max_iterations: Optional[int] = None,
    ):
        self.target = target
        self.interval = interval_seconds
        self.scan_fn = scan_fn
        self.notify_fn = notify_fn
        self.alert_on_new_only = alert_on_new_only
        self.alert_on_clear = alert_on_clear
        self.max_iterations = max_iterations
        self._stop = False
        self._iteration = 0
        self.last_scan_time: Optional[datetime] = None
        self.consecutive_clean = 0

    def stop(self):
        self._stop = True

    def run(self) -> int:
        """Run the monitoring loop. Returns exit code."""
        log_head(logger, f"Starting continuous monitoring: {self.target} every {self.interval}s")

        # Handle SIGINT/SIGTERM gracefully
        def _signal_handler(sig, frame):
            logger.info("Monitor: received stop signal, finishing current scan...")
            self.stop()
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        exit_code = 0

        while not self._stop:
            self._iteration += 1
            now = datetime.now()

            log_head(logger, f"Monitor iteration #{self._iteration} — {now.strftime('%Y-%m-%d %H:%M:%S')}")

            # Run the scan
            try:
                result = self.scan_fn(self.target)
            except Exception as e:
                logger.error(f"Monitor: scan failed: {e}")
                result = None

            self.last_scan_time = now

            if result:
                all_results = result.get("all_results", {})
                scan_score = result.get("scan_score")
                previous_snapshot = result.get("previous_snapshot")

                counts = _count_by_status(all_results)
                new_findings = _extract_new_findings(all_results, previous_snapshot)

                if new_findings:
                    self.consecutive_clean = 0
                    exit_code = 2 if any(f.get("status") == "FAIL" for f in new_findings) else exit_code

                    log_head(logger, f"Monitor: {len(new_findings)} NEW finding(s) detected!")

                    if self.notify_fn:
                        msg = _build_alert_message(self.target, new_findings, counts, scan_score)
                        try:
                            self.notify_fn(msg)
                        except Exception as e:
                            logger.error(f"Monitor: notification failed: {e}")
                else:
                    self.consecutive_clean += 1
                    logger.info(f"Monitor: no new findings (clean streak: {self.consecutive_clean})")

                    if self.alert_on_clear and self.notify_fn and self.consecutive_clean == 1:
                        msg = _build_clear_message(self.target, counts, scan_score)
                        try:
                            self.notify_fn(msg)
                        except Exception as e:
                            logger.error(f"Monitor: clear notification failed: {e}")

            if self.max_iterations and self._iteration >= self.max_iterations:
                logger.info(f"Monitor: reached max_iterations={self.max_iterations}, stopping.")
                break

            if not self._stop:
                next_run = now + timedelta(seconds=self.interval)
                logger.info(f"Monitor: next scan at {next_run.strftime('%H:%M:%S')} (sleeping {self.interval}s)")
                # Interruptible sleep
                for _ in range(self.interval):
                    if self._stop:
                        break
                    time.sleep(1)

        log_head(logger, f"Monitor stopped after {self._iteration} iteration(s).")
        return exit_code
