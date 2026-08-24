"""Extra branch coverage for tblue.config."""

import argparse
import tempfile
from pathlib import Path
from tblue.config import load, apply, _manual_toml, _validate


def _write_toml(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".toml", delete=False, mode="w")
    f.write(content)
    f.close()
    return Path(f.name)


def _default_args():
    ns = argparse.Namespace()
    ns.url        = None
    ns.depth      = 2
    ns.output     = "tblue_report.html"
    ns.skip       = ""
    ns.only       = ""
    ns.timeout    = 10
    ns.retries    = 2
    ns.no_history = False
    ns.fail_below = None
    ns.json       = False
    ns.sarif      = False
    ns.verbose    = False
    return ns


def test_load_empty_toml_returns_empty_dict():
    """Covers parsing an empty TOML file."""
    p = _write_toml("")
    result = load(str(p))
    assert result == {}


def test_load_multiple_valid_keys():
    """Covers loading multiple valid config keys at once."""
    p = _write_toml(
        'url = "https://example.com"\n'
        'depth = 3\n'
        'timeout = 15\n'
        'verbose = true\n'
    )
    result = load(str(p))
    assert result["url"] == "https://example.com"
    assert result["depth"] == 3
    assert result["timeout"] == 15
    assert result["verbose"] is True


def test_manual_toml_strips_inline_comments():
    """Covers the comment-stripping branch in _manual_toml."""
    p = _write_toml('timeout = 20  # this is a comment\n')
    result = _manual_toml(p)
    assert result.get("timeout") == 20


def test_apply_does_not_overwrite_user_set_value():
    """Covers that apply() respects CLI values already set by the user."""
    args = _default_args()
    args.depth = 5  # user explicitly set this
    config = {"depth": 1}
    apply(config, args)
    # depth=5 is not the default (2), so config should not override it
    assert args.depth == 5


def test_apply_sets_url_when_args_url_is_none():
    """Covers the url-from-config branch in apply()."""
    args = _default_args()
    config = {"url": "https://configured-site.com"}
    apply(config, args)
    assert args.url == "https://configured-site.com"


def test_validate_rejects_wrong_type():
    """Covers the type-validation branch that drops invalid values."""
    result = _validate({"depth": "not-an-int", "url": "https://example.com"})
    # depth should be dropped because it's not an int; url should be kept
    assert "depth" not in result
    assert result.get("url") == "https://example.com"


def test_load_unknown_schema_keys_ignored():
    """Unknown keys (not in _SCHEMA) are silently dropped by _validate."""
    p = _write_toml("unknown_key_xyz = \"should-be-dropped\"\n")
    result = load(str(p))
    assert "unknown_key_xyz" not in result
