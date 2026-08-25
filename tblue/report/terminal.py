"""
Terminal output — rich box-drawing UI for the Tblue CLI.
"""

import shutil
from typing import List, TYPE_CHECKING
from tblue.constants import RED, GREEN, YELLOW, BLUE, BOLD, RESET, VERSION
from tblue.logger import get_logger

if TYPE_CHECKING:
    from tblue.scoring import ScanScore, ScanDiff

logger = get_logger(__name__)

# ── Palette ───────────────────────────────────────────────────────────────────
_C   = "\033[96m"    # cyan
_M   = "\033[95m"    # magenta
_W   = "\033[97m"    # bright white
_ORG = "\033[33m"    # orange / amber
_DIM = "\033[2m"
_UL  = "\033[4m"

_SEV_COLOR = {
    "critical": RED,
    "high":     _ORG,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     _DIM,
}
_SEV_DOT = {
    "critical": f"{RED}●{RESET}",
    "high":     f"{_ORG}●{RESET}",
    "medium":   f"{YELLOW}●{RESET}",
    "low":      f"{BLUE}●{RESET}",
    "info":     f"{_DIM}○{RESET}",
}
_GRADE_COLOR = {
    "A+": GREEN, "A": GREEN,
    "B":  BLUE,
    "C":  YELLOW,
    "D":  _ORG,
    "F":  RED,
}

# ── Box helpers ───────────────────────────────────────────────────────────────

def _tw() -> int:
    return min(shutil.get_terminal_size((80, 24)).columns, 110)


def _strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _vis(s: str) -> int:
    return len(_strip_ansi(s))


def _box_top(w: int, color: str = _C) -> str:
    return f"{color}╭{'─' * (w - 2)}╮{RESET}"

def _box_mid(w: int, color: str = _C) -> str:
    return f"{color}├{'─' * (w - 2)}┤{RESET}"

def _box_bot(w: int, color: str = _C) -> str:
    return f"{color}╰{'─' * (w - 2)}╯{RESET}"

def _box_row(text: str, w: int, color: str = _C) -> str:
    inner = w - 4
    pad   = max(0, inner - _vis(text))
    return f"{color}│{RESET} {text}{' ' * pad} {color}│{RESET}"

def _center(text: str, w: int) -> str:
    pad = max(0, (w - 2 - _vis(text)) // 2)
    return " " * pad + text

def _bar(filled: int, total: int, width: int = 20) -> str:
    if total == 0:
        pct = 0
    else:
        pct = filled / total
    done  = round(pct * width)
    rest  = width - done
    color = GREEN if pct >= 0.8 else (YELLOW if pct >= 0.5 else RED)
    return f"{color}{'█' * done}{_DIM}{'░' * rest}{RESET}"

# ── Banner ────────────────────────────────────────────────────────────────────

# Full logo — fits when terminal is ≥ 92 cols wide
_LOGO_FULL = [
    "████████╗ ██████╗  ██╗      ██╗   ██╗ ███████╗",
    "╚══██╔══╝ ██╔══██╗ ██║      ██║   ██║ ██╔════╝",
    "   ██║    ██████╔╝ ██║      ██║   ██║ █████╗  ",
    "   ██║    ██╔══██╗ ██║      ██║   ██║ ██╔══╝  ",
    "   ██║    ██████╔╝ ███████╗ ╚██████╔╝ ███████╗",
    "   ╚═╝    ╚═════╝  ╚══════╝  ╚═════╝  ╚══════╝",
]

# Compact logo — fits at 80 cols
_LOGO_COMPACT = [
    "╔╦╗╔╗ ╦  ╦ ╦╔═╗",
    " ║ ╠╩╗║  ║ ║║╣ ",
    " ╩ ╚═╝╩═╝╚═╝╚═╝",
]

# Category short-names for the coverage row
_CATEGORY_PILLS = [
    "headers", "cookies", "tls", "csp", "cors", "auth",
    "oauth", "csrf", "injection", "xss", "ssrf", "secrets",
    "api", "graphql", "cloud", "dns", "supply-chain",
]


def print_banner(target: str, depth: int, output: str, modules: List[str]) -> None:
    w  = _tw()
    nc = len(modules)

    print()
    print(_box_top(w, _C))

    # ── Logo row ────────────────────────────────────────────────────────────
    logo_inner = w - 4
    if logo_inner >= len(_LOGO_FULL[0]):
        # Wide terminal — full ASCII art logo
        print(_box_row("", w))
        for line in _LOGO_FULL:
            pad = max(0, (logo_inner - len(line)) // 2)
            print(_box_row(f"{_C}{BOLD}{' ' * pad}{line}{RESET}", w))
        print(_box_row("", w))
        subtitle = f"{_DIM}Passive blue-team security scanner  ·  {nc} modules  ·  v{VERSION}{RESET}"
        print(_box_row(_center(subtitle, w), w))
        print(_box_row("", w))
    else:
        # Narrow terminal — compact logo + inline text
        logo_w   = len(_LOGO_COMPACT[0])
        title_lines = [
            f"{BOLD}{_W}Tblue{RESET}",
            f"{_DIM}Blue-team scanner{RESET}",
            f"{_DIM}v{VERSION}{RESET}",
            "",
            f"{_C}◆{RESET} {nc} scanners",
            f"{_C}◆{RESET} Passive / read-only",
        ]
        rows = max(len(_LOGO_COMPACT), len(title_lines))
        print(_box_row("", w))
        for i in range(rows):
            ll = f"{_C}{BOLD}{_LOGO_COMPACT[i]}{RESET}" if i < len(_LOGO_COMPACT) else " " * logo_w
            tl = title_lines[i] if i < len(title_lines) else ""
            print(_box_row(f"  {ll}    {tl}", w))
        print(_box_row("", w))

    # ── Divider + target info ───────────────────────────────────────────────
    print(_box_mid(w, _C))
    print(_box_row("", w))

    target_label  = f"{_DIM}  Target   {RESET}"
    target_value  = f"{BOLD}{_W}{target}{RESET}"
    print(_box_row(f"{target_label}{target_value}", w))

    output_label  = f"{_DIM}  Output   {RESET}"
    output_value  = f"{_C}{output}{RESET}" if output else f"{_DIM}terminal only{RESET}"
    workers_note  = f"{_DIM}  ·  50 workers{RESET}"
    print(_box_row(f"{output_label}{output_value}{workers_note}", w))

    # Coverage pills — fit as many as possible on one row
    coverage_label = f"  {_DIM}Coverage  {RESET}"
    label_vis = _vis(coverage_label)
    avail     = w - 4 - label_vis - 2
    pill_str  = ""
    for cat in _CATEGORY_PILLS:
        token = f"{_DIM}[{RESET}{_C}{cat}{RESET}{_DIM}]{RESET} "
        if _vis(pill_str) + len(cat) + 3 > avail:
            pill_str += f"{_DIM}…{RESET}"
            break
        pill_str += token
    print(_box_row(f"{coverage_label}{pill_str}", w))

    print(_box_row("", w))
    print(_box_bot(w, _C))
    print()


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(passed: int, warned: int, failed: int, elapsed: float) -> None:
    w     = _tw()
    total = passed + warned + failed

    elapsed_str = f"{elapsed:.1f}s" if elapsed < 60 else f"{int(elapsed // 60)}m {int(elapsed % 60)}s"

    print(_box_top(w, BLUE))
    print(_box_row(_center(f"{BOLD}Scan Complete  {_DIM}{elapsed_str}{RESET}", w), w, BLUE))
    print(_box_mid(w, BLUE))
    print(_box_row("", w, BLUE))

    bar_pass = _bar(passed, total)
    bar_warn = _bar(warned, total)
    bar_fail = _bar(failed, total)

    pct_p = f"{passed / total * 100:.0f}%" if total else "—"
    pct_w = f"{warned / total * 100:.0f}%" if total else "—"
    pct_f = f"{failed / total * 100:.0f}%" if total else "—"

    print(_box_row(f"  {GREEN}✔  Passed{RESET}  {passed:>4}  {_DIM}({pct_p}){RESET}  {bar_pass}", w, BLUE))
    print(_box_row(f"  {YELLOW}⚑  Warned{RESET}  {warned:>4}  {_DIM}({pct_w}){RESET}  {bar_warn}", w, BLUE))
    print(_box_row(f"  {RED}✖  Failed{RESET}  {failed:>4}  {_DIM}({pct_f}){RESET}  {bar_fail}", w, BLUE))

    print(_box_row("", w, BLUE))
    print(_box_bot(w, BLUE))
    print()


# ── Score ─────────────────────────────────────────────────────────────────────

def print_score(scan_score: "ScanScore") -> None:
    from tblue.scoring import SEVERITY_ORDER, SEVERITY_LABELS

    score = scan_score.score
    grade = scan_score.grade
    gc    = _GRADE_COLOR.get(grade, RESET)
    w     = _tw()

    filled = round(score / 5)
    gauge  = _bar(filled, 20, 20)

    print(_box_top(w, gc))
    print(_box_row("", w, gc))

    grade_block   = f"{gc}{BOLD} {grade} {RESET}"
    score_display = f"{gc}{BOLD}{score:>3}/100{RESET}"
    header = f"  {grade_block}  Security Score {score_display}   {gauge}"
    print(_box_row(header, w, gc))

    print(_box_row("", w, gc))
    print(_box_mid(w, gc))

    total_issues = sum(scan_score.breakdown[s] for s in SEVERITY_ORDER)
    for sev in SEVERITY_ORDER:
        count  = scan_score.breakdown[sev]
        deduct = scan_score.deductions[sev]
        color  = _SEV_COLOR.get(sev, RESET)
        dot    = _SEV_DOT.get(sev, "  ")
        label  = SEVERITY_LABELS[sev].ljust(10)
        bar    = _bar(count, max(total_issues, 1), 14)
        pts    = f"  {RED}−{deduct} pts{RESET}" if deduct else ""
        print(_box_row(f"  {dot} {color}{label}{RESET}  {count:>3}  {bar}{pts}", w, gc))

    top = scan_score.top_issues
    if top:
        print(_box_mid(w, gc))
        print(_box_row(f"  {BOLD}Top issues to fix:{RESET}", w, gc))
        for i, issue in enumerate(top[:5], 1):
            sev     = issue.get("severity", "medium")
            dot     = _SEV_DOT.get(sev, "  ")
            rtype   = issue.get("type", "")
            url     = issue.get("url", "")
            short_u = (url[:46] + "…") if len(url) > 46 else url
            tag     = f"{RED}FAIL{RESET}" if issue.get("status") == "FAIL" else f"{YELLOW}WARN{RESET}"
            print(_box_row(f"  {i}. {dot} [{tag}] {rtype}", w, gc))
            if short_u:
                print(_box_row(f"       {_DIM}{short_u}{RESET}", w, gc))

    print(_box_row("", w, gc))
    print(_box_bot(w, gc))
    print()


# ── Trend ─────────────────────────────────────────────────────────────────────

def print_trend(scan_diff: "ScanDiff") -> None:
    w = _tw()

    if scan_diff.is_first_scan:
        print(_box_top(w, BLUE))
        print(_box_row(f"  {BLUE}ℹ  First scan — baseline saved. Run again to track changes.{RESET}", w, BLUE))
        print(_box_bot(w, BLUE))
        print()
        return

    if not scan_diff.has_changes:
        print(_box_top(w, GREEN))
        print(_box_row(f"  {GREEN}✔  No changes since last scan ({scan_diff.prev_scanned_at[:10]}).{RESET}", w, GREEN))
        print(_box_bot(w, GREEN))
        print()
        return

    delta        = scan_diff.score_delta
    arrow_color  = GREEN if delta > 0 else (RED if delta < 0 else YELLOW)
    arrow_sym    = "▲" if delta > 0 else ("▼" if delta < 0 else "→")
    arrow        = f"{arrow_color}{arrow_sym} {'+' if delta > 0 else ''}{delta} pts{RESET}"
    border_color = GREEN if delta >= 0 else RED
    prev         = scan_diff.prev_score
    curr         = prev + delta

    print(_box_top(w, border_color))
    print(_box_row(_center(f"{BOLD}Trend vs {scan_diff.prev_scanned_at[:10]}{RESET}", w), w, border_color))
    print(_box_mid(w, border_color))
    print(_box_row(f"  Score  {_DIM}{prev}{RESET} → {BOLD}{curr}{RESET}   {arrow}", w, border_color))

    if scan_diff.new_issues:
        print(_box_mid(w, border_color))
        print(_box_row(f"  {RED}▸ New issues ({len(scan_diff.new_issues)}){RESET}", w, border_color))
        for key, status in list(scan_diff.new_issues.items())[:4]:
            tag = f"{RED}FAIL{RESET}" if status == "FAIL" else f"{YELLOW}WARN{RESET}"
            print(_box_row(f"    [{tag}] {key[:58]}", w, border_color))

    if scan_diff.resolved_issues:
        print(_box_mid(w, border_color))
        print(_box_row(f"  {GREEN}▸ Resolved ({len(scan_diff.resolved_issues)}){RESET}", w, border_color))
        for key in list(scan_diff.resolved_issues.keys())[:4]:
            print(_box_row(f"    {GREEN}✔{RESET} {key[:60]}", w, border_color))

    if scan_diff.worsened_issues:
        print(_box_mid(w, border_color))
        print(_box_row(f"  {RED}▸ Worsened WARN → FAIL ({len(scan_diff.worsened_issues)}){RESET}", w, border_color))
        for key in list(scan_diff.worsened_issues.keys())[:3]:
            print(_box_row(f"    {RED}↑{RESET} {key[:60]}", w, border_color))

    print(_box_bot(w, border_color))
    print()


# ── CI Gate ───────────────────────────────────────────────────────────────────

def print_severity_gate(scan_score: "ScanScore", floor: str, offending: dict) -> None:
    """Render the --fail-on gate: which severities tripped it, and why."""
    from tblue.scoring import SEVERITY_LABELS

    passed = not offending
    w      = _tw()
    bc     = GREEN if passed else RED

    print(_box_top(w, bc))
    print(_box_row(_center(f"{BOLD}Severity Gate{RESET}", w), w, bc))
    print(_box_mid(w, bc))
    print(_box_row(f"  {_DIM}Fail on{RESET}  {SEVERITY_LABELS.get(floor, floor)} or worse", w, bc))
    print(_box_mid(w, bc))

    if passed:
        print(_box_row(
            f"  {GREEN}{BOLD}\u2714  PASSED{RESET}  \u2014  nothing at {floor} or above   exit 0", w, bc))
    else:
        for sev, count in offending.items():
            color = _SEV_COLOR.get(sev, RESET)
            label = SEVERITY_LABELS.get(sev, sev)
            print(_box_row(f"    {color}\u25cf{RESET} {label:<14} {count}", w, bc))
        total = sum(offending.values())
        print(_box_mid(w, bc))
        print(_box_row(
            f"  {RED}{BOLD}\u2716  FAILED{RESET}  \u2014  {total} finding(s) at {floor} or above   exit 1", w, bc))

    print(_box_bot(w, bc))
    print()


def print_ci_gate(scan_score: "ScanScore", threshold: int) -> None:
    score  = scan_score.score
    grade  = scan_score.grade
    gc     = _GRADE_COLOR.get(grade, RESET)
    passed = score >= threshold
    w      = _tw()
    bc     = GREEN if passed else RED

    print(_box_top(w, bc))
    print(_box_row(_center(f"{BOLD}CI / CD Gate{RESET}", w), w, bc))
    print(_box_mid(w, bc))
    print(_box_row(f"  {_DIM}Threshold{RESET}  {threshold:>3}/100  {_bar(threshold, 100, 20)}", w, bc))
    print(_box_row(f"  {_DIM}Score    {RESET}  {gc}{BOLD}{score:>3}/100{RESET}  {_bar(score, 100, 20)}", w, bc))
    print(_box_mid(w, bc))

    if passed:
        verdict = f"{GREEN}{BOLD}✔  PASSED{RESET}  —  score {gc}{score}{RESET} ≥ {threshold}   exit 0"
    else:
        deficit = threshold - score
        verdict = f"{RED}{BOLD}✖  FAILED{RESET}  —  score {gc}{score}{RESET} < {threshold}   need {deficit} more point(s)   exit 1"

    print(_box_row(f"  {verdict}", w, bc))
    print(_box_bot(w, bc))
    print()
