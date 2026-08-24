"""Tests for the continuous monitoring module."""

import time
from unittest.mock import MagicMock, patch, call

import pytest

from tblue.monitor import (
    parse_interval,
    _count_by_status,
    _extract_new_findings,
    _build_alert_message,
    _build_clear_message,
    MonitorSession,
)


# ── parse_interval ─────────────────────────────────────────────────────────────

class TestParseInterval:
    def test_hours(self):
        assert parse_interval("6h") == 21_600

    def test_minutes(self):
        assert parse_interval("30m") == 1_800

    def test_days(self):
        assert parse_interval("1d") == 86_400

    def test_seconds_suffix(self):
        assert parse_interval("120s") == 120

    def test_bare_integer(self):
        assert parse_interval("3600") == 3600

    def test_strips_whitespace(self):
        assert parse_interval("  2h  ") == 7_200


# ── _count_by_status ───────────────────────────────────────────────────────────

class TestCountByStatus:
    def test_empty(self):
        counts = _count_by_status({})
        assert counts == {"FAIL": 0, "WARN": 0, "PASS": 0}

    def test_mixed(self):
        results = {
            "headers": [
                {"status": "FAIL", "type": "Missing CSP"},
                {"status": "WARN", "type": "Missing HSTS"},
            ],
            "ssl": [
                {"status": "PASS", "type": "SSL valid"},
            ],
        }
        counts = _count_by_status(results)
        assert counts["FAIL"] == 1
        assert counts["WARN"] == 1
        assert counts["PASS"] == 1


# ── _extract_new_findings ──────────────────────────────────────────────────────

class TestExtractNewFindings:
    def test_no_previous_returns_empty(self):
        current = {"headers": [{"status": "FAIL", "type": "Missing CSP"}]}
        assert _extract_new_findings(current, None) == []

    def test_same_findings_returns_empty(self):
        current = {"headers": [{"status": "FAIL", "type": "Missing CSP"}]}
        previous = {"results": {"headers": [{"status": "FAIL", "type": "Missing CSP"}]}}
        assert _extract_new_findings(current, previous) == []

    def test_new_finding_detected(self):
        current = {
            "headers": [
                {"status": "FAIL", "type": "Missing CSP"},
                {"status": "FAIL", "type": "NEW: Missing HSTS"},
            ]
        }
        previous = {"results": {"headers": [{"status": "FAIL", "type": "Missing CSP"}]}}
        new = _extract_new_findings(current, previous)
        assert len(new) == 1
        assert new[0]["type"] == "NEW: Missing HSTS"

    def test_resolved_finding_not_in_new(self):
        """A finding that disappeared is not counted as 'new'."""
        current = {"headers": [{"status": "PASS", "type": "CSP present"}]}
        previous = {"results": {"headers": [{"status": "FAIL", "type": "Missing CSP"}]}}
        new = _extract_new_findings(current, previous)
        assert new == []

    def test_pass_findings_not_included(self):
        """PASS findings are never returned as 'new'."""
        current = {"headers": [{"status": "PASS", "type": "SSL valid"}]}
        previous = {"results": {}}
        new = _extract_new_findings(current, previous)
        assert new == []


# ── _build_alert_message ───────────────────────────────────────────────────────

class TestBuildAlertMessage:
    def _score(self, score=75, grade="B"):
        s = MagicMock()
        s.score = score
        s.grade = grade
        return s

    def test_contains_target(self):
        findings = [{"status": "FAIL", "type": "Missing CSP"}]
        msg = _build_alert_message("https://example.com", findings, {"FAIL": 1, "WARN": 0}, self._score())
        assert "https://example.com" in msg

    def test_fail_findings_listed(self):
        findings = [{"status": "FAIL", "type": "SQL Injection risk"}]
        msg = _build_alert_message("https://t.com", findings, {"FAIL": 1, "WARN": 0}, self._score())
        assert "SQL Injection risk" in msg

    def test_warn_findings_listed(self):
        findings = [{"status": "WARN", "type": "Missing HSTS preload"}]
        msg = _build_alert_message("https://t.com", findings, {"FAIL": 0, "WARN": 1}, self._score())
        assert "Missing HSTS preload" in msg

    def test_score_included(self):
        msg = _build_alert_message("https://t.com", [], {"FAIL": 0, "WARN": 0}, self._score(82, "A"))
        assert "82/100" in msg
        assert "(A)" in msg

    def test_no_score_obj(self):
        msg = _build_alert_message("https://t.com", [], {"FAIL": 0, "WARN": 0}, None)
        assert "N/A" in msg

    def test_truncated_at_five_fails(self):
        findings = [{"status": "FAIL", "type": f"Issue #{i}"} for i in range(10)]
        msg = _build_alert_message("https://t.com", findings, {"FAIL": 10, "WARN": 0}, self._score())
        assert "5 more" in msg


# ── _build_clear_message ───────────────────────────────────────────────────────

class TestBuildClearMessage:
    def _score(self):
        s = MagicMock()
        s.score = 90
        s.grade = "A"
        return s

    def test_contains_target(self):
        msg = _build_clear_message("https://example.com", {"FAIL": 0, "WARN": 0}, self._score())
        assert "https://example.com" in msg

    def test_no_new_findings_phrase(self):
        msg = _build_clear_message("https://t.com", {"FAIL": 0, "WARN": 0}, self._score())
        assert "No new findings" in msg


# ── MonitorSession ─────────────────────────────────────────────────────────────

class TestMonitorSession:
    def _make_result(self, has_new=False):
        if has_new:
            results = {"headers": [{"status": "FAIL", "type": "NEW Missing CSP"}]}
            previous = {"results": {}}
        else:
            results = {"headers": [{"status": "PASS", "type": "CSP present"}]}
            previous = {"results": {"headers": [{"status": "PASS", "type": "CSP present"}]}}

        score = MagicMock()
        score.score = 80
        score.grade = "B"
        return {"all_results": results, "scan_score": score, "previous_snapshot": previous}

    def test_run_single_iteration(self):
        """max_iterations=1 runs the scan fn once and exits."""
        scan_fn = MagicMock(return_value=self._make_result(has_new=False))
        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=scan_fn,
            max_iterations=1,
        )
        exit_code = session.run()
        assert scan_fn.call_count == 1
        assert exit_code == 0

    def test_exit_code_2_on_new_fail(self):
        """New FAIL finding → exit code 2."""
        scan_fn = MagicMock(return_value=self._make_result(has_new=True))
        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=scan_fn,
            max_iterations=1,
        )
        exit_code = session.run()
        assert exit_code == 2

    def test_notify_called_on_new_findings(self):
        """Notify function is called when new findings are found."""
        scan_fn = MagicMock(return_value=self._make_result(has_new=True))
        notify_fn = MagicMock()
        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=scan_fn,
            notify_fn=notify_fn,
            max_iterations=1,
        )
        session.run()
        assert notify_fn.call_count == 1
        msg = notify_fn.call_args[0][0]
        assert "NEW Missing CSP" in msg

    def test_notify_not_called_when_clean(self):
        """Notify function is NOT called when no new findings."""
        scan_fn = MagicMock(return_value=self._make_result(has_new=False))
        notify_fn = MagicMock()
        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=scan_fn,
            notify_fn=notify_fn,
            max_iterations=1,
        )
        session.run()
        assert notify_fn.call_count == 0

    def test_scan_error_does_not_crash(self):
        """Exception in scan_fn is caught and the loop continues."""
        def _failing_scan(t):
            raise RuntimeError("network error")

        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=_failing_scan,
            max_iterations=1,
        )
        exit_code = session.run()
        assert exit_code == 0  # no crash, no new findings → 0

    def test_stop_exits_loop(self):
        """Calling stop() exits the loop after the current iteration."""
        call_count = 0

        def _scan_fn(t):
            nonlocal call_count
            call_count += 1
            return self._make_result(has_new=False)

        session = MonitorSession(
            target="https://example.com",
            interval_seconds=3600,
            scan_fn=_scan_fn,
            max_iterations=3,
        )
        # stop after first iteration
        original_run = session.run

        def _patched_sleep(n):
            session.stop()

        with patch("time.sleep", side_effect=_patched_sleep):
            session.run()

        assert call_count == 1

    def test_consecutive_clean_increments(self):
        """consecutive_clean counter increments on clean scans."""
        scan_fn = MagicMock(return_value=self._make_result(has_new=False))
        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=scan_fn,
            max_iterations=2,
        )
        with patch("time.sleep"):
            session.run()
        assert session.consecutive_clean == 2

    def test_clear_alert_sent_on_first_clean_after_issue(self):
        """alert_on_clear=True sends notification on the first clean scan."""
        # First call returns findings, second returns clean
        results_seq = [self._make_result(has_new=True), self._make_result(has_new=False)]
        scan_fn = MagicMock(side_effect=results_seq)
        notify_fn = MagicMock()
        session = MonitorSession(
            target="https://example.com",
            interval_seconds=60,
            scan_fn=scan_fn,
            notify_fn=notify_fn,
            alert_on_clear=True,
            max_iterations=2,
        )
        with patch("time.sleep"):
            session.run()
        # Called once for new finding, once for clear
        assert notify_fn.call_count == 2
