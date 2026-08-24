#!/usr/bin/env python3
"""Demo simulation — prints realistic tblue output for GIF recording."""
import sys, time

def p(s="", end="\n", delay=0):
    print(s, end=end, flush=True)
    if delay:
        time.sleep(delay)

CYAN  = "\033[96m\033[1m"
RESET = "\033[0m"
DIM   = "\033[2m"
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
BOLD  = "\033[1m"

logo = f"""
{CYAN}  ████████╗ ██████╗  ██╗      ██╗   ██╗ ███████╗{RESET}
{CYAN}  ╚══██╔══╝ ██╔══██╗ ██║      ██║   ██║ ██╔════╝{RESET}
{CYAN}     ██║    ██████╔╝ ██║      ██║   ██║ █████╗  {RESET}
{CYAN}     ██║    ██╔══██╗ ██║      ██║   ██║ ██╔══╝  {RESET}
{CYAN}     ██║    ██████╔╝ ███████╗ ╚██████╔╝ ███████╗{RESET}
{CYAN}     ╚═╝    ╚═════╝  ╚══════╝  ╚═════╝  ╚══════╝{RESET}

  {GRN}◆ Blue-team{RESET}  {CYAN}◆ Passive{RESET}  {YEL}◆ 614 scanners{RESET}  {CYAN}◆ Open-source · MIT{RESET}
  {DIM}──────────────────────────────────────────────────────────────────{RESET}"""

p(logo)
time.sleep(0.4)

p(f"\n  Scanning {BOLD}https://example.com{RESET} — 614 modules · 50 workers · depth 3")
p(f"  {DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
p()
time.sleep(0.6)

rows = [
    ("FAIL", "hsts_missing",       "HSTS not set — site reachable over plain HTTP"),
    ("FAIL", "csp_missing",        "Content-Security-Policy absent — no XSS defence"),
    ("FAIL", "spf_missing",        "SPF record not found — domain open to spoofing"),
    ("FAIL", "dot_env_exposed",    "/.env returned 200 — credentials exposed"),
    ("WARN", "cors_wildcard",      "CORS Access-Control-Allow-Origin: * on /api"),
    ("WARN", "csp_unsafe_inline",  "unsafe-inline in script-src negates CSP"),
    ("WARN", "xss_reflected",      "XSS marker reflected (HTML-encoded) in /search"),
    ("PASS", "ssl_https",          "TLS 1.3 active, valid certificate chain"),
    ("PASS", "x_frame_options",    "X-Frame-Options: SAMEORIGIN present"),
    ("PASS", "hpkp_absent",        "HPKP not used — no pinning risk"),
    ("PASS", "no_server_header",   "Server header suppressed"),
]

for status, key, desc in rows:
    col = RED if status == "FAIL" else YEL if status == "WARN" else GRN
    key_padded = key.ljust(24)
    p(f"  [{col}{status}{RESET}]  {DIM}{key_padded}{RESET}  {desc}", delay=0.18)

p()
time.sleep(0.5)
p(f"  {DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
p(f"\n  Grade: {RED}{BOLD}D{RESET}  ·  Score: {RED}{BOLD}41/100{RESET}  ·  "
  f"{RED}4 FAIL{RESET} · {YEL}3 WARN{RESET} · {GRN}4 PASS{RESET}")
p(f"\n  Report saved: {DIM}example_com_20260823_091542.html{RESET}\n")
