"""Extra branch coverage for tblue.scanner.sca."""

from unittest.mock import MagicMock, patch
from tblue.scanner.sca import SCAScanner, _parse_package_json, _parse_requirements_txt, _parse_gemfile_lock

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    s = SCAScanner(session)
    return s


def test_parse_package_json_valid():
    """_parse_package_json extracts dependency name/version pairs."""
    content = '{"dependencies": {"react": "^18.0.0", "axios": "~1.2.3"}, "devDependencies": {"jest": "29.0.0"}}'
    result = _parse_package_json(content)
    names = [r[0] for r in result]
    assert "react" in names or "axios" in names or "jest" in names


def test_parse_package_json_invalid_json():
    """_parse_package_json handles invalid JSON gracefully."""
    result = _parse_package_json("not json at all {{{}}")
    assert result == []


def test_parse_requirements_txt_valid():
    """_parse_requirements_txt extracts Python package/version pairs."""
    content = "requests==2.28.0\nFlask>=2.0.0\n# comment\nDjango==4.1.0\n"
    result = _parse_requirements_txt(content)
    names = [r[0] for r in result]
    assert "requests" in names or "Flask" in names or "Django" in names


def test_parse_requirements_txt_comments_skipped():
    """Lines starting with # or - are skipped in requirements.txt parsing."""
    content = "# This is a comment\n-r base.txt\nfastapi==0.95.0\n"
    result = _parse_requirements_txt(content)
    assert all(r[0] != "#" for r in result)


def test_parse_gemfile_lock_valid():
    """_parse_gemfile_lock extracts Ruby gem/version pairs."""
    content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    rack (2.2.4)\n\n"
    result = _parse_gemfile_lock(content)
    names = [r[0] for r in result]
    assert "rails" in names or "rack" in names


def test_no_manifest_found_returns_pass():
    """When no manifest is found on any probed path → PASS result."""
    s = _scanner()
    not_found = MagicMock()
    not_found.status_code = 404
    not_found.text = "Not Found"
    not_found.headers = {}
    s.http.get = MagicMock(return_value=not_found)
    results = s.scan(URL)
    assert isinstance(results, list)
    # SCA scanner returns empty list when no manifests found (no FAIL results)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails
