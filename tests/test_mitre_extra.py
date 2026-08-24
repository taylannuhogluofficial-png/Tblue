"""Extra branch coverage for tblue.mitre."""

from tblue.mitre import get_techniques


def test_known_xss_finding_returns_techniques():
    """XSS finding type maps to at least one ATT&CK technique."""
    result = get_techniques("xss — reflected")
    assert isinstance(result, list)
    assert len(result) >= 1
    for t in result:
        assert "id" in t
        assert "name" in t
        assert "tactic" in t


def test_unknown_finding_returns_empty():
    """Completely unknown finding type returns an empty list."""
    result = get_techniques("totally_unknown_xyz_finding_type_zzz")
    assert isinstance(result, list)
    assert result == []


def test_open_redirect_finding_returns_techniques():
    """Open redirect finding maps to at least one technique."""
    result = get_techniques("open redirect parameter detected")
    assert isinstance(result, list)
    assert len(result) >= 1


def test_port_exposure_finding_returns_techniques():
    """Port exposure finding maps to at least one technique."""
    result = get_techniques("open ports — 3306/MySQL")
    assert isinstance(result, list)
    assert len(result) >= 1


def test_techniques_have_url_field():
    """Each returned technique includes a url field pointing to attack.mitre.org."""
    result = get_techniques("csp missing")
    assert isinstance(result, list)
    for t in result:
        assert "url" in t
        assert "attack.mitre.org" in t["url"]


def test_deduplication_prevents_duplicate_technique_ids():
    """Technique IDs are deduplicated even when multiple rules match."""
    result = get_techniques("xss unsafe inline csp missing unsafe eval")
    ids = [t["id"] for t in result]
    assert len(ids) == len(set(ids)), "Duplicate technique IDs found"
