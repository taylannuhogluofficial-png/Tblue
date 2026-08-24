"""
Tests for scan history and trend diff computation.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from tblue.history import (
    compute_diff,
    save_snapshot,
    load_previous_snapshot,
    ScanDiff,
)
from tblue.scoring import score_results


def _make_score(results):
    return score_results(results)


# ── compute_diff ──────────────────────────────────────────────────────────────

def test_first_scan_diff():
    results = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "u"}]}
    score   = _make_score(results)
    diff    = compute_diff(results, score, previous=None)
    assert diff.is_first_scan is True


def test_score_improvement_detected():
    prev_snapshot = {
        "score": 60, "grade": "C", "results": {
            "ssl": [{"type": "SSL / HTTPS", "status": "FAIL", "url": "u"}]
        }
    }
    results = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "u"}]}
    score   = _make_score(results)
    diff    = compute_diff(results, score, prev_snapshot)
    assert diff.score_delta > 0
    assert not diff.is_first_scan


def test_score_regression_detected():
    prev_snapshot = {
        "score": 100, "grade": "A+", "results": {
            "ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "u"}]
        }
    }
    results = {
        "ssl": [
            {"type": "SSL / HTTPS", "status": "FAIL", "url": "u"},
            {"type": "Info disclosure — .env file", "status": "FAIL", "url": "u"},
        ]
    }
    score = _make_score(results)
    diff  = compute_diff(results, score, prev_snapshot)
    assert diff.score_delta < 0


def test_new_issue_detected():
    prev_snapshot = {
        "score": 100, "grade": "A+", "results": {}
    }
    results = {"csp": [{"type": "CSP — missing", "status": "FAIL", "url": "u"}]}
    score   = _make_score(results)
    diff    = compute_diff(results, score, prev_snapshot)
    assert "CSP — missing" in diff.new_issues


def test_resolved_issue_detected():
    prev_snapshot = {
        "score": 80, "grade": "A", "results": {
            "csp": [{"type": "CSP — missing", "status": "FAIL", "url": "u"}]
        }
    }
    results = {"csp": [{"type": "CSP — missing", "status": "PASS", "url": "u"}]}
    score   = _make_score(results)
    diff    = compute_diff(results, score, prev_snapshot)
    assert "CSP — missing" in diff.resolved_issues


def test_no_changes_has_no_changes():
    state = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "u"}]}
    score = _make_score(state)
    prev  = {"score": score.score, "grade": score.grade, "results": state}
    diff  = compute_diff(state, score, prev)
    assert not diff.has_changes


def test_worsened_issue_detected():
    prev_snapshot = {
        "score": 90, "grade": "A+", "results": {
            "csp": [{"type": "CSP — missing", "status": "WARN", "url": "u"}]
        }
    }
    results = {"csp": [{"type": "CSP — missing", "status": "FAIL", "url": "u"}]}
    score   = _make_score(results)
    diff    = compute_diff(results, score, prev_snapshot)
    assert "CSP — missing" in diff.worsened_issues


# ── save / load snapshot ──────────────────────────────────────────────────────

def test_save_and_reload_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("tblue.history._HISTORY_ROOT", tmp_path / "history")

    results = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "https://example.com"}]}
    score   = _make_score(results)

    saved = save_snapshot("https://example.com", results, score)
    assert saved.exists()

    loaded = load_previous_snapshot("https://example.com")
    assert loaded is not None
    assert loaded["score"] == score.score
    assert loaded["grade"] == score.grade


def test_load_returns_none_if_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr("tblue.history._HISTORY_ROOT", tmp_path / "empty")
    result = load_previous_snapshot("https://example.com")
    assert result is None


def test_snapshot_contains_results(tmp_path, monkeypatch):
    monkeypatch.setattr("tblue.history._HISTORY_ROOT", tmp_path / "history")
    results = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "u"}]}
    score   = _make_score(results)
    save_snapshot("https://example.com", results, score)

    loaded = load_previous_snapshot("https://example.com")
    assert "ssl" in loaded["results"]
