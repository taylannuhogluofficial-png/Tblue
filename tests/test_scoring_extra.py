"""Extra branch coverage for tblue.scoring."""

from tblue.scoring import (
    classify_severity, deduction_for, score_results, ScanScore,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
)


def test_classify_critical_fail():
    """Known critical type on FAIL maps to CRITICAL severity."""
    sev = classify_severity("ssl / https", "FAIL")
    assert sev == CRITICAL


def test_classify_high_fail():
    """CSP missing on FAIL maps to HIGH severity."""
    sev = classify_severity("csp — missing", "FAIL")
    assert sev == HIGH


def test_classify_medium_warn():
    """samesite on WARN maps to LOW (WARN version of medium rule)."""
    sev = classify_severity("samesite", "WARN")
    assert sev in (MEDIUM, LOW)


def test_classify_unknown_type_returns_info():
    """Unknown finding type with PASS status returns INFO."""
    sev = classify_severity("totally-unknown-xyz-1234", "PASS")
    assert sev == INFO


def test_deduction_for_critical_fail():
    """Critical FAIL deducts 20 points."""
    d = deduction_for(CRITICAL, "FAIL")
    assert d == 20


def test_deduction_for_high_warn():
    """High WARN deducts 5 points."""
    d = deduction_for(HIGH, "WARN")
    assert d == 5


def test_score_results_empty_returns_100():
    """No findings → score is 100."""
    scan_score = score_results({})
    assert scan_score.score == 100


def test_score_results_critical_fail_deducts():
    """Critical FAIL finding deducts from score."""
    all_results = {"ssl": [{"status": "FAIL", "type": "ssl / https", "url": "https://example.com"}]}
    scan_score = score_results(all_results)
    assert scan_score.score < 100


def test_score_results_grade_assigned():
    """score_results always assigns a grade string."""
    scan_score = score_results({})
    assert isinstance(scan_score.grade, str)
    assert len(scan_score.grade) > 0


def test_score_clamped_at_zero():
    """Score cannot go below 0 even with many FAIL findings."""
    many_fails = [{"status": "FAIL", "type": "ssl / https", "url": "https://example.com"}] * 20
    scan_score = score_results({"mod": many_fails})
    assert scan_score.score >= 0
