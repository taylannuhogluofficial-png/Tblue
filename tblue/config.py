"""
Config file loader for Tblue.

Reads `.tblue.toml` from the current working directory (or a path
specified by --config). CLI arguments always override config file values.

Supported keys (all optional):
  url         = "https://yoursite.com"
  depth       = 2
  fail_below  = 80
  skip        = "xss,dom"
  only        = ""
  timeout     = 10
  retries     = 2
  no_history  = false
  output      = "report.html"
  json        = false
  sarif       = false
  verbose     = false

Example .tblue.toml:
  url        = "https://example.com"
  fail_below = 80
  skip       = "xss,dom,mixed"
  output     = "security-report.html"
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional

from tblue.constants import DEFAULT_TIMEOUT, DEFAULT_DEPTH, DEFAULT_USER_AGENT

# Legacy dict kept for any imports that still reference it
DEFAULT_CONFIG = {
    "timeout":    DEFAULT_TIMEOUT,
    "depth":      DEFAULT_DEPTH,
    "user_agent": DEFAULT_USER_AGENT,
}

_DEFAULT_NAME = ".tblue.toml"

# All valid keys and their expected Python types
_SCHEMA: Dict[str, type] = {
    "url":        str,
    "depth":      int,
    "fail_below": int,
    "skip":       str,
    "only":       str,
    "timeout":    int,
    "retries":    int,
    "no_history": bool,
    "output":     str,
    "json":       bool,
    "sarif":      bool,
    "verbose":    bool,
}

# Argparse default values — used to detect "not set by user"
_ARG_DEFAULTS = {
    "depth":      2,
    "output":     "tblue_report.html",
    "skip":       "",
    "only":       "",
    "timeout":    10,
    "retries":    2,
    "no_history": False,
    "fail_below": None,
    "json":       False,
    "sarif":      False,
    "verbose":    False,
}


def load(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a config file and return a flat dict of validated settings.

    Args:
        path: explicit file path; if None, searches for .tblue.toml in cwd.

    Returns:
        Dict of settings. Missing keys are simply absent.
    """
    config_path = _find(path)
    if config_path is None:
        return {}
    try:
        return _parse_toml(config_path)
    except Exception as e:
        print(f"[tblue] Warning: could not read config {config_path}: {e}",
              file=sys.stderr)
        return {}


def apply(config: Dict[str, Any], args) -> None:
    """
    Merge config into an argparse Namespace.
    CLI arguments take priority — only fill in keys still at their defaults.
    """
    for key, value in config.items():
        arg_key = key.replace("-", "_")
        if not hasattr(args, arg_key):
            continue
        current = getattr(args, arg_key)
        default = _ARG_DEFAULTS.get(arg_key)
        if current == default:
            setattr(args, arg_key, value)

    if "url" in config and getattr(args, "url", None) is None:
        args.url = config["url"]


def _find(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    candidate = Path.cwd() / _DEFAULT_NAME
    return candidate if candidate.exists() else None


def _parse_toml(path: Path) -> Dict[str, Any]:
    try:
        if sys.version_info >= (3, 11):
            import tomllib
            with open(path, "rb") as f:
                raw = tomllib.load(f)
        else:
            try:
                import tomli  # type: ignore
                with open(path, "rb") as f:
                    raw = tomli.load(f)
            except ImportError:
                raw = _manual_toml(path)
    except Exception:
        raw = _manual_toml(path)
    return _validate(raw)


def _manual_toml(path: Path) -> Dict[str, Any]:
    """Minimal TOML parser — flat key = value pairs only."""
    result: Dict[str, Any] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                continue
            key, _, raw_val = line.partition("=")
            key     = key.strip()
            raw_val = raw_val.strip()
            if "#" in raw_val and not raw_val.startswith('"'):
                raw_val = raw_val[:raw_val.index("#")].strip()
            if (raw_val.startswith('"') and raw_val.endswith('"')) or \
               (raw_val.startswith("'") and raw_val.endswith("'")):
                result[key] = raw_val[1:-1]
            elif raw_val.lower() == "true":
                result[key] = True
            elif raw_val.lower() == "false":
                result[key] = False
            else:
                try:
                    result[key] = int(raw_val)
                except ValueError:
                    result[key] = raw_val
    return result


def _validate(raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, expected_type in _SCHEMA.items():
        if key not in raw:
            continue
        val = raw[key]
        try:
            out[key] = expected_type(val)
        except (ValueError, TypeError):
            print(f"[tblue] Warning: config key '{key}' = '{val}' "
                  f"(expected {expected_type.__name__})", file=sys.stderr)
    return out
