"""
Tblue — Open source blue-team security scanner.
"""

__version__ = "1.0.1"
__author__  = "Taylan Nuhoğlu"
__license__ = "MIT"

# ── Import banner ──────────────────────────────────────────────────────────────
import sys as _sys
import os  as _os


def _print_import_banner() -> None:
    _R   = "\033[0m"
    _B   = "\033[1m"
    _C   = "\033[96m"
    _G   = "\033[92m"
    _Y   = "\033[93m"
    _BL  = "\033[94m"
    _DIM = "\033[2m"
    _W   = "\033[97m"

    logo_lines = [
        f"{_C}{_B}████████╗ ██████╗  ██╗      ██╗   ██╗ ███████╗{_R}",
        f"{_C}{_B}╚══██╔══╝ ██╔══██╗ ██║      ██║   ██║ ██╔════╝{_R}",
        f"{_C}{_B}   ██║    ██████╔╝ ██║      ██║   ██║ █████╗  {_R}",
        f"{_C}{_B}   ██║    ██╔══██╗ ██║      ██║   ██║ ██╔══╝  {_R}",
        f"{_C}{_B}   ██║    ██████╔╝ ███████╗ ╚██████╔╝ ███████╗{_R}",
        f"{_C}{_B}   ╚═╝    ╚═════╝  ╚══════╝  ╚═════╝  ╚══════╝{_R}",
    ]

    tags = "  ".join([
        f"{_G}◆ Blue-team{_R}",
        f"{_BL}◆ Passive / read-only{_R}",
        f"{_Y}◆ 614 scanners{_R}",
        f"{_C}◆ Open-source · MIT{_R}",
    ])

    print()
    for line in logo_lines:
        print(f"  {line}")
    print()
    print(f"  {tags}")
    print(f"  {_DIM}{'─' * 78}{_R}")
    print(f"  {_DIM}v{__version__}  ·  {__author__}  ·  tblue -u <url>  ·  github.com/taylannuhogluofficial-png/Tblue{_R}")
    print()


def _should_show_banner() -> bool:
    if _os.environ.get("TBLUE_NO_BANNER") == "1":
        return False
    if "pytest" in _sys.modules or _os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    if _os.environ.get("CI") or _os.environ.get("GITHUB_ACTIONS"):
        return False
    # CLI entry-point has its own banner; don't double-print
    if _sys.argv and _sys.argv[0].endswith(("__main__.py", "tblue")):
        return False
    # Don't pollute stdout when used as a library or in a pipe
    if not hasattr(_sys.stdout, "isatty") or not _sys.stdout.isatty():
        return False
    return True


if _should_show_banner():
    _print_import_banner()
