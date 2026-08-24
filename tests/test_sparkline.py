"""Tests for score-trend sparkline and load_score_history."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from tblue.report.html import _sparkline_section


# ── _sparkline_section ────────────────────────────────────────────────────────

def _entry(score, grade="B", ts="2026-01-01T12:00:00"):
    return {"score": score, "grade": grade, "scanned_at": ts}


def test_sparkline_empty_returns_empty():
    assert _sparkline_section([]) == ""


def test_sparkline_single_point_returns_empty():
    assert _sparkline_section([_entry(80)]) == ""


def test_sparkline_two_points_returns_svg():
    result = _sparkline_section([_entry(70, "B", "2026-01-01T10:00:00"),
                                  _entry(80, "B", "2026-01-02T10:00:00")])
    assert "<svg" in result
    assert "polyline" in result
    assert "polygon" in result


def test_sparkline_green_for_high_score():
    history = [_entry(80, "A", "2026-01-01T00:00:00"),
               _entry(90, "A+", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "#27ae60" in result


def test_sparkline_yellow_for_medium_score():
    history = [_entry(60, "C", "2026-01-01T00:00:00"),
               _entry(65, "C", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "#d68910" in result


def test_sparkline_red_for_low_score():
    history = [_entry(30, "F", "2026-01-01T00:00:00"),
               _entry(40, "F", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "#c0392b" in result


def test_sparkline_shows_current_score():
    history = [_entry(55, "C", "2026-01-01T00:00:00"),
               _entry(72, "C", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "72" in result


def test_sparkline_shows_grade():
    history = [_entry(85, "A", "2026-01-01T00:00:00"),
               _entry(88, "A", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "(A)" in result


def test_sparkline_positive_delta():
    history = [_entry(60, "C", "2026-01-01T00:00:00"),
               _entry(80, "B", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "+20" in result


def test_sparkline_negative_delta():
    history = [_entry(80, "B", "2026-01-01T00:00:00"),
               _entry(60, "C", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "-20" in result


def test_sparkline_zero_delta():
    history = [_entry(75, "B", "2026-01-01T00:00:00"),
               _entry(75, "B", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "±0" in result


def test_sparkline_twelve_points():
    history = [_entry(50 + i * 3, "B", f"2026-01-{i+1:02d}T00:00:00")
               for i in range(12)]
    result = _sparkline_section(history)
    assert "<svg" in result
    assert "2026-01-12" in result


def test_sparkline_labels_include_date():
    history = [_entry(70, "B", "2025-06-15T08:30:00"),
               _entry(75, "B", "2025-06-16T08:30:00")]
    result = _sparkline_section(history)
    assert "2025-06-15" in result
    assert "2025-06-16" in result


def test_sparkline_section_title_in_output():
    history = [_entry(70, "B", "2026-01-01T00:00:00"),
               _entry(75, "B", "2026-01-02T00:00:00")]
    result = _sparkline_section(history)
    assert "Score trend" in result


# ── load_score_history ────────────────────────────────────────────────────────

def test_load_score_history_no_dir():
    from tblue.history import load_score_history
    with patch("tblue.history._HISTORY_ROOT", Path(tempfile.mkdtemp()) / "nonexistent"):
        result = load_score_history("https://example.com")
    assert result == []


def test_load_score_history_empty_dir():
    from tblue.history import load_score_history
    with tempfile.TemporaryDirectory() as d:
        fake_root = Path(d)
        with patch("tblue.history._HISTORY_ROOT", fake_root):
            result = load_score_history("https://example.com")
    assert result == []


def test_load_score_history_returns_entries():
    from tblue.history import load_score_history
    with tempfile.TemporaryDirectory() as d:
        fake_root = Path(d)
        domain_dir = fake_root / "example.com"
        domain_dir.mkdir(parents=True)
        for i in range(3):
            snap = {
                "scanned_at": f"2026-01-0{i+1}T10:00:00",
                "score": 70 + i * 5,
                "grade": "B",
            }
            (domain_dir / f"2026-01-0{i+1}_10-00-00.json").write_text(json.dumps(snap))

        with patch("tblue.history._HISTORY_ROOT", fake_root):
            result = load_score_history("https://example.com")

    assert len(result) == 3
    assert result[0]["score"] == 70
    assert result[2]["score"] == 80


def test_load_score_history_max_count():
    from tblue.history import load_score_history
    with tempfile.TemporaryDirectory() as d:
        fake_root = Path(d)
        domain_dir = fake_root / "example.com"
        domain_dir.mkdir(parents=True)
        for i in range(15):
            snap = {"scanned_at": f"2026-01-{i+1:02d}T10:00:00", "score": 60 + i, "grade": "C"}
            (domain_dir / f"snap_{i:02d}.json").write_text(json.dumps(snap))

        with patch("tblue.history._HISTORY_ROOT", fake_root):
            result = load_score_history("https://example.com", max_count=5)

    assert len(result) == 5


def test_load_score_history_skips_corrupt_file():
    from tblue.history import load_score_history
    with tempfile.TemporaryDirectory() as d:
        fake_root = Path(d)
        domain_dir = fake_root / "example.com"
        domain_dir.mkdir(parents=True)
        (domain_dir / "aaa.json").write_text("not valid json {{{")
        snap = {"scanned_at": "2026-01-02T10:00:00", "score": 75, "grade": "B"}
        (domain_dir / "bbb.json").write_text(json.dumps(snap))

        with patch("tblue.history._HISTORY_ROOT", fake_root):
            result = load_score_history("https://example.com")

    assert len(result) == 1
    assert result[0]["score"] == 75
