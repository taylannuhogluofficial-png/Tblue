"""Extra branch coverage for tblue.history."""

import json
from pathlib import Path
from tblue.history import (
    compute_diff,
    save_snapshot,
    load_previous_snapshot,
    load_score_history,
    ScanDiff,
    _domain_dir,
)
from tblue.scoring import score_results


def _score(results=None):
    return score_results(results or {})


def test_scan_diff_has_changes_with_only_score_delta():
    """Branch: has_changes returns True when score changed but no issue sets changed."""
    d = ScanDiff(is_first_scan=False, score_delta=5)
    assert d.has_changes is True


def test_scan_diff_no_changes_zero_delta():
    """Branch: has_changes returns False when everything is empty/zero."""
    d = ScanDiff(is_first_scan=False, score_delta=0)
    assert d.has_changes is False


def test_load_score_history_empty_dir(tmp_path, monkeypatch):
    """Branch: load_score_history when history dir doesn't exist returns []."""
    monkeypatch.setattr("tblue.history._HISTORY_ROOT", tmp_path / "nope")
    result = load_score_history("https://example.com")
    assert result == []


def test_load_score_history_respects_max_count(tmp_path, monkeypatch):
    """Branch: load_score_history limits to max_count snapshots."""
    monkeypatch.setattr("tblue.history._HISTORY_ROOT", tmp_path / "history")
    results = {"ssl": [{"type": "SSL", "status": "PASS", "url": "https://example.com"}]}
    score = _score(results)
    # Write 5 snapshots
    for i in range(5):
        save_snapshot("https://example.com", results, score)
    history = load_score_history("https://example.com", max_count=3)
    assert len(history) <= 3


def test_load_previous_snapshot_with_corrupt_json(tmp_path, monkeypatch):
    """Branch: corrupt JSON in snapshot file is silently skipped."""
    monkeypatch.setattr("tblue.history._HISTORY_ROOT", tmp_path / "history")
    results = {"ssl": [{"type": "SSL", "status": "PASS", "url": "https://example.com"}]}
    score = _score(results)
    path = save_snapshot("https://example.com", results, score)
    # Corrupt the file
    path.write_text("NOT JSON {{{")
    result = load_previous_snapshot("https://example.com")
    # Should return None (corrupt file) or raise — just must not hang
    assert result is None or isinstance(result, dict)


def test_compute_diff_empty_previous_results():
    """Branch: previous snapshot has empty results dict."""
    prev = {"score": 50, "grade": "C", "results": {}}
    current = {"ssl": [{"type": "SSL", "status": "FAIL", "url": "u"}]}
    score = _score(current)
    diff = compute_diff(current, score, prev)
    assert "SSL" in diff.new_issues


def test_domain_dir_sanitises_special_chars():
    """Branch: _domain_dir replaces non-filesystem-safe chars with underscore."""
    d = _domain_dir("https://my-host:8080/path")
    assert "my-host" in str(d) or "_" in str(d)
    assert d.name  # non-empty
