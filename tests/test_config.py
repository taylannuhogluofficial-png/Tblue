"""Tests for .tblue.toml config file loader."""

import argparse
import tempfile
from pathlib import Path
from tblue.config import load, apply, _manual_toml


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


# ── load() ────────────────────────────────────────────────────────────────────

def test_load_nonexistent_returns_empty():
    result = load("/nonexistent/path/config.toml")
    assert result == {}


def test_load_url():
    p = _write_toml('url = "https://example.com"\n')
    result = load(str(p))
    assert result["url"] == "https://example.com"


def test_load_integer():
    p = _write_toml("fail_below = 80\n")
    result = load(str(p))
    assert result["fail_below"] == 80


def test_load_boolean_false():
    p = _write_toml("no_history = false\n")
    result = load(str(p))
    assert result["no_history"] is False


def test_load_boolean_true():
    p = _write_toml("sarif = true\n")
    result = load(str(p))
    assert result["sarif"] is True


def test_load_string_with_hash_comment():
    p = _write_toml('skip = "xss,dom" # skip slow modules\n')
    result = load(str(p))
    assert result["skip"] == "xss,dom"


def test_unknown_keys_ignored():
    p = _write_toml('unknown_key = "value"\nurl = "https://example.com"\n')
    result = load(str(p))
    assert "unknown_key" not in result
    assert "url" in result


# ── apply() ───────────────────────────────────────────────────────────────────

def test_apply_sets_url():
    args = _default_args()
    apply({"url": "https://example.com"}, args)
    assert args.url == "https://example.com"


def test_apply_does_not_override_explicit_cli():
    args = _default_args()
    args.depth = 5  # user explicitly set this
    apply({"depth": 3}, args)
    assert args.depth == 5  # config should not override


def test_apply_fills_default_with_config():
    args = _default_args()
    apply({"depth": 3}, args)
    assert args.depth == 3


def test_apply_fail_below():
    args = _default_args()
    apply({"fail_below": 75}, args)
    assert args.fail_below == 75


def test_apply_sarif():
    args = _default_args()
    apply({"sarif": True}, args)
    assert args.sarif is True


# ── _manual_toml ──────────────────────────────────────────────────────────────

def test_manual_toml_parses_all_types():
    p = _write_toml(
        'url = "https://example.com"\n'
        "depth = 3\n"
        "verbose = true\n"
        "no_history = false\n"
    )
    result = _manual_toml(p)
    assert result["url"] == "https://example.com"
    assert result["depth"] == 3
    assert result["verbose"] is True
    assert result["no_history"] is False


def test_manual_toml_ignores_comments():
    p = _write_toml("# this is a comment\ndepth = 2\n")
    result = _manual_toml(p)
    assert result == {"depth": 2}


def test_manual_toml_ignores_section_headers():
    p = _write_toml("[settings]\ndepth = 4\n")
    result = _manual_toml(p)
    assert result == {"depth": 4}
