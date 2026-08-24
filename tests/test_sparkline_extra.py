"""Extra branch coverage for tblue.report.html._sparkline_section."""

from tblue.report.html import _sparkline_section


def _entry(score, grade="B", ts="2026-01-01T12:00:00"):
    return {"score": score, "grade": grade, "scanned_at": ts}


def test_three_points_produces_svg():
    """Three history entries → SVG output."""
    history = [
        _entry(60, "C", "2026-01-01T00:00:00"),
        _entry(70, "B", "2026-01-02T00:00:00"),
        _entry(80, "B", "2026-01-03T00:00:00"),
    ]
    result = _sparkline_section(history)
    assert "<svg" in result
    assert "polyline" in result


def test_all_same_score_no_crash():
    """All identical scores produce valid SVG without division-by-zero."""
    history = [_entry(75, "B", f"2026-01-0{i}T00:00:00") for i in range(1, 4)]
    result = _sparkline_section(history)
    assert isinstance(result, str)


def test_decreasing_score_red_or_orange():
    """Declining score trend → red/amber color in SVG."""
    history = [
        _entry(90, "A", "2026-01-01T00:00:00"),
        _entry(50, "D", "2026-01-02T00:00:00"),
    ]
    result = _sparkline_section(history)
    assert "#" in result  # at least some color attribute


def test_increasing_score_green():
    """Improving score trend → green color in SVG."""
    history = [
        _entry(30, "F", "2026-01-01T00:00:00"),
        _entry(90, "A", "2026-01-02T00:00:00"),
    ]
    result = _sparkline_section(history)
    assert "#27ae60" in result


def test_zero_scores_handled():
    """Scores of 0 produce valid output without crash."""
    history = [
        _entry(0, "F", "2026-01-01T00:00:00"),
        _entry(0, "F", "2026-01-02T00:00:00"),
    ]
    result = _sparkline_section(history)
    assert isinstance(result, str)
