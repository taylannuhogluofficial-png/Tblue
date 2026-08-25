# Usage

## Basic scan

```bash
tblue -u https://yoursite.com
```

Runs the 582 passive modules. GET and HEAD only — nothing is submitted,
no payloads are sent, and it is safe against production.

---

## Scan tiers

This is the most important thing to know before using Tblue. Modules are split
by **what they actually send**, measured against an instrumented server rather
than assumed from their names.

| Tier | Flag | Modules | What it sends |
|------|------|---------|---------------|
| Passive | *(default)* | 582 | GET/HEAD only. Safe against production. |
| Probe | `--probe` | 12 | Crafted but side-effect-free requests — GraphQL introspection, CORS reflection, TLS cipher negotiation, DNS enumeration. |
| Intrusive | `--active` | 20 | Authentication attempts, password-reset and registration submissions, injection payloads, port scans. |

`--active` implies `--probe`.

> **The intrusive tier has real consequences.** It can lock accounts out, email
> password resets to real users, create records, and trip WAFs. Only use it on
> systems you own.

A default scan is enforced read-only: every default module is run against an
instrumented server by `tests/test_passive_by_default.py`, and any that issues a
POST/PUT/PATCH/DELETE, or a GET carrying a traversal / XXE / CRLF / injection
payload, fails the test suite until it is moved into a gated tier.

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target URL (your own site only) | — |
| `-o`, `--output` | HTML report output path | `tblue_report.html` |
| `--json` | Also export JSON report | `off` |
| `--sarif` | Also export SARIF report (GitHub Security tab) | `off` |
| `--sigma` | Also export Sigma detection rules (.yaml) for SIEM ingestion | `off` |
| `--splunk` | Also export Splunk SPL correlation searches (.spl) | `off` |
| `--sentinel` | Also export Microsoft Sentinel KQL analytics rules (.json) | `off` |
| `--playbook` | Print remediation playbook: terminal \| markdown | — |
| `--siem` | Export SIEM-native findings: cef (ArcSight), leef (QRadar), elastic (Elastic SIEM), sentinel (Azure Sentinel) | — |
| `--cookie` | Session cookie(s) to inject: 'sessionid=abc; csrftoken=xyz' | — |
| `--header` | Custom HTTP header, repeatable: 'X-API-Key: secret' | — |
| `--bearer` | Bearer token: sets Authorization: Bearer <TOKEN> | — |
| `--auth` | HTTP Basic auth credentials: 'username:password' | — |
| `--targets` | File with one target URL per line (runs full scan on each) | — |
| `--notify` | Send scan summary to webhook, repeatable: slack:https://... \| teams:https://... \| discord:https://... \| webhook:https://... | — |
| `--soar` | Send scan to SOAR/incident platform, repeatable: jira:https://company.atlassian.net/PROJECT \| pagerduty:https://events.pagerduty.com/... \| thehive:https://thehive.company.com \| servicenow:https://company.service-now.com | — |
| `--skip` | Modules to skip (comma-separated) | — |
| `--only` | Run only these modules (comma-separated) | — |
| `--verbose` | Enable debug logging | `off` |
| `--timeout` | Request timeout in seconds | `8` |
| `--retries` | Retry attempts per request | `3` |
| `--version` | Print the version and exit | — |
| `--no-history` | Skip saving/comparing scan history | `off` |
| `--fail-below` | Exit code 1 if score < N (CI/CD gate). Range: 0-100. | — |
| `--fail-on` | Exit code 1 if any finding is at or above SEVERITY (critical\|high\|medium\|low). Catches a missing CSP or HSTS that an aggregate score would still let through. Combine with --fail-below; either one failing fails the build. | — |
| `--config` | Path to .tblue.toml config file (default: .tblue.toml in cwd) | — |
| `--ai-key` | Anthropic API key for AI-powered attack chain analysis (or set ANTHROPIC_API_KEY env var) | — |
| `--ai-model` | Claude model for AI analysis (default: claude-sonnet-4-6) | `claude-sonnet-4-6` |
| `--ai` | Send findings to Anthropic for AI attack-chain analysis. Opt-in: nothing is transmitted without this flag (or --ai-key). | `off` |
| `--no-ai` | Disable AI analysis even if ANTHROPIC_API_KEY is set | `off` |
| `--stride` | Generate STRIDE threat model (JSON + Markdown) from scan findings | `off` |
| `--poc` | Generate Proof-of-Concept curl commands for all FAIL/WARN findings (JSON + Markdown) | `off` |
| `--probe` | Also run side-effect-free probes: GraphQL introspection, CORS origin reflection, TLS cipher negotiation, DNS enumeration. Sends crafted requests but modifies nothing. | `off` |
| `--active` | Run every probe INCLUDING intrusive ones: authentication attempts, password-reset and registration submissions, injection payloads and port scans. These can lock accounts out, email real users and trip WAFs. Implies --probe. Own the target before using this. | `off` |
| `--dashboard` | Open a live browser dashboard that streams scan results in real time | `off` |
| `--browser` | Enable Playwright browser-based scanning (DOM XSS, SPA routes, storage audit). Requires: pip install playwright && playwright install chromium | `off` |
| `--monitor` | Continuous monitoring mode: scan on a schedule and alert only on new findings | `off` |
| `--interval` | Monitoring interval (e.g. 30m, 6h, 1d). Default: 6h. Requires --monitor | `6h` |
| `--workers` | Parallel scanner workers (default: 50). Set to 1 for sequential. | `50` |

---

## CI gates

Two independent gates. Either one failing exits 1.

```bash
# Fail on any high-severity finding — a missing CSP, no HSTS, no framing protection
tblue -u https://yoursite.com --fail-on high

# Fail if the overall score regresses
tblue -u https://yoursite.com --fail-below 80

# Both
tblue -u https://yoursite.com --fail-on critical --fail-below 85
```

`--fail-on` gates on the findings, `--fail-below` on the aggregate score. Prefer
`--fail-on` when a specific misconfiguration must never merge: a site missing
Content-Security-Policy entirely still scores in the 80s once its other checks
pass, so `--fail-below 80` exits 0 while the header is absent.

Exit codes: `0` clean, `1` a gate tripped, `2` scan error.

See the README for the GitHub Action.

---

## Authenticated scans

```bash
tblue -u https://yoursite.com --bearer "$TOKEN"
tblue -u https://yoursite.com --cookie "sessionid=abc; csrftoken=xyz"
tblue -u https://yoursite.com --header "X-API-Key: $KEY"
tblue -u https://yoursite.com --auth "user:password"
```

These values go **only** to the target host and its subdomains — never to the
third-party lookup services some scanners use (crt.sh, OSV, NVD), and they are
stripped if the target redirects to another host.

---

## Examples

```bash
# Save the report somewhere specific
tblue -u https://yoursite.com -o my_report.html

# Also export JSON
tblue -u https://yoursite.com --json

# Headers and CSP only
tblue -u https://yoursite.com --only headers,csp

# Skip the DNS checks
tblue -u https://yoursite.com --skip dns_caa

# Shallow crawl — faster on large sites
tblue -u https://yoursite.com -d 1

# SARIF for the GitHub Security tab
tblue -u https://yoursite.com --sarif

# Include the probe tier, but not the intrusive one
tblue -u https://yoursite.com --probe
```

`--only` refuses to start if every module you named sits behind a gate, rather
than scanning nothing and reporting a clean result.

---

## Output

- Colored terminal output, pass / warn / fail per check, with a 0-100 score and A-F grade
- An HTML report at your output path
- A trend against the previous scan of the same target (`--no-history` to disable)

Other formats: `--json`, `--sarif`, `--sigma`, `--splunk`, `--sentinel`,
`--siem cef|leef|elastic|sentinel`. See the README table.

---

## Important

Only scan websites you own or have explicit written permission to test.
