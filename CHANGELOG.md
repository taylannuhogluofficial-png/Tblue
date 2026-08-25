# Changelog

All notable changes to Tblue are documented here.

## [2.0.0] — 2026-08-24

Security and correctness release. Default scan behaviour changes, hence the
major version. Both 1.0.0 and 1.0.1 are yanked from PyPI.

### Security

- **Credentials no longer leak to third parties.** `--bearer`, `--auth`,
  `--cookie` and `--header` values were attached to a shared session that
  enrichment scanners also used to reach crt.sh, AlienVault OTX, OSV and NVD,
  so target credentials were transmitted to those services. Requests to any
  host other than the target (or its subdomains) now go through a session with
  no auth, no cookies and no user-supplied headers.
- **Proof-of-Concept commands are shell-quoted.** A crawled or redirect-supplied
  URL containing shell metacharacters could execute if a user copy-pasted the
  generated `curl` command. All substituted values pass through `shlex.quote`.
- **Report output is HTML-escaped.** Findings carry text harvested from the
  scanned site (banners, headers, error pages); none of it was escaped before
  being written into the HTML report.

### Changed (breaking)

- **Default scans are now genuinely passive, and it is enforced.** 31 modules
  that send uninvited traffic no longer run without `--active`. The list was
  built by measurement, not by name: every scanner was run against an
  instrumented server and any that issued POST/PUT/PATCH/DELETE, or a GET
  carrying a traversal / XXE / CRLF / injection payload, was moved. Several
  were named "passive" while sending payloads (`xxe_passive`,
  `log_injection_passive`).

  Measured on a depth-1 scan, before and after:

  | | requests | POST/PATCH | attack payloads |
  |---|---|---|---|
  | before | 1664 | 205 | 104 |
  | after  | 1219 |   0 |   0 |

  The stub the test scans with answers API-shaped paths as JSON, because
  several scanners only send a payload once they believe the service exists;
  an HTML-only stub let `xxe_injection` look passive while it was not.

  Previously a plain `tblue -u` submitted login attempts, password-reset and
  account-registration requests, XXE and traversal strings, and port scans;
  `--active` then ran five modules a second time.

  **Impact:** default runs no longer report exposed databases (MySQL,
  PostgreSQL, MongoDB, Elasticsearch, Redis, Memcached), exposed SSH/Telnet/FTP,
  GraphQL introspection, or injection findings that require sending a payload.
  Pass `--active` to restore them. The split is 583 passive plus 31 opt-in
  active (12 probe, 20 intrusive). `tests/test_passive_by_default.py` reproduces the measurement and
  fails if a default scanner starts sending traffic.

- **Scan tiers.** The opt-in scanners are split rather than lumped together.
  `--probe` runs the 12 that send crafted but side-effect-free requests
  (GraphQL introspection, CORS reflection, TLS cipher negotiation, DNS
  enumeration). The split is 582 passive, 12 probe, 20 intrusive. `--active` additionally runs the 20 intrusive ones that submit
  authentication attempts, password resets, registrations, injection payloads
  and port scans. `--active` implies `--probe`.

- **Renamed two misleading modules.** `xxe_passive` and `log_injection_passive`
  send XXE and CRLF payloads and were passive in name only. They are now
  `xxe_probe` and `log_injection_probe`, and both sit in the intrusive tier.
- **AI analysis is opt-in.** Findings were sent to Anthropic whenever
  `ANTHROPIC_API_KEY` was present in the environment. It now requires an
  explicit `--ai` or `--ai-key`; `--no-ai` is retained.

### Fixed

- **`--only` could silently scan nothing.** Naming a module that had moved to a
  gated tier (`--only xss`) resolved to an empty module list, printed
  "0 modules", exited 0 and wrote a clean, empty report — a security tool
  reporting no findings when it ran no checks. It now refuses to start and says
  which flag is needed, and mixed selections warn while running the rest.
- **Every opt-in scanner silently failed.** `all_results` was keyed only from
  the passive module list, so all 32 gated modules raised `KeyError`, which the
  dispatch loop swallowed as "active scanner error". `--probe` and `--active`
  appeared to run while discarding every finding.
- **The version was hardcoded in two places.** `tblue/constants.py` carried its
  own `VERSION = "1.0.0"` and a matching User-Agent, so the terminal banner and
  every outbound request advertised 1.0.0 for the whole of 1.0.1. It now derives
  from `tblue.__version__`.
- `--stride` crashed with `TypeError: Object of type ScanScore is not JSON
  serializable`, aborting the scan before `--poc` could run and exiting 1 after
  all scanners had succeeded.
- Three MITRE ATT&CK mappings were wrong: T1430 is a Mobile technique absent
  from Enterprise, T1596.005 carried its parent's name, and T1598.002 was
  labelled with T1598.001's name. Five further IDs appeared under two spellings.
- PyYAML was imported at module scope but never declared as a dependency, so a
  clean `pip install tblue` produced a CLI that failed on import.

### Documentation

- README no longer claims "no data sent anywhere". It now states which
  third-party services are contacted, what they receive, and that some default
  checks POST to login endpoints or send XXE payloads.
- SCANNERS.md claimed to document all 614 scanners while containing 405
  entries.

## [1.0.1] — 2026-08-24

### Fixed
- **Packaging:** `pyyaml` was imported at module scope by the Sigma report writer but
  never declared as a dependency, so a clean `pip install tblue` produced a CLI that
  died with `ModuleNotFoundError: No module named 'yaml'` before printing anything.
  It is now declared in both `pyproject.toml` and `requirements.txt`.
- **HTML report injection:** finding fields (`url`, `detail`, `fix`, `evidence`) were
  interpolated into the HTML report unescaped. A hostile or compromised scan target
  could inject arbitrary markup or script into the report an analyst later opens from
  `file://`. All user-controlled content is now escaped via `html.escape(..., quote=True)`.
- **PoC shell injection:** generated `curl` proof-of-concept commands interpolated
  crawled, redirect-influenceable URLs into shell pipelines without quoting. Every
  substituted value is now passed through `shlex.quote`.
- **Test output:** `-p no:terminal` in `setup.cfg` suppressed pytest's reporter, so
  collection errors and failures printed a green `0/0 passed` summary and went
  unnoticed. Removed — this is what allowed the packaging bug above to ship.
- Banner no longer writes to stdout when it is not a TTY, so importing `tblue` as a
  library or piping CLI output is no longer polluted with ANSI escape codes.

### Changed
- Removed the redundant `setup.py`; packaging metadata now lives solely in `pyproject.toml`.
- `.gitignore` no longer blanket-ignores `*.html` and `*.json` (it previously risked
  silently excluding source and fixture files); it now targets `tblue_report*` outputs.
- Dropped the stale `.coverage` artifact from version control.
- README disclaimer now states that `--active` sends probing requests, rather than
  describing the tool as unconditionally passive.
- Removed 605 lint findings (unused imports, empty f-strings, duplicate imports).

## [1.0.0] — 2026-08-13

### Added
- 614 unique passive security scanners across 40+ categories
- Parallel execution via ThreadPoolExecutor (50 workers default)
- Response caching layer — shared fetch prevents redundant requests per scan
- Live ASCII terminal reporter with box-drawing progress list
- HTML report generation with severity breakdown
- JSON, SARIF, SIEM, Sigma, Splunk SPL, Microsoft Sentinel KQL output formats
- Browser-powered scanning via Playwright (`--browser` flag)
- Site crawler with configurable depth (`-d` / `--depth N`)
- Live browser dashboard with Server-Sent Events streaming (`--dashboard`)
- AI-powered findings analysis (`--ai-key` / `--ai-model`, disable with `--no-ai`)
- SOAR / webhook notification on findings (`--soar FORMAT:URL`)
- Monitor mode — continuous scanning on interval (`--monitor`)
- STRIDE threat model report
- PoC report generation
- History / diff mode — compare scan results across runs
- Compliance reports: PCI DSS, HIPAA, SOC 2, NIST CSF, ISO 27001
- SBOM scanner
- MITRE ATT&CK mapping
- CVE correlation against live NVD + OSV feeds
- `tblue` CLI command (installed via `pip install tblue`)
- `python -m tblue` entry point

### Scanner categories
Critical injection, XSS, SSRF, CSRF, authentication, session, OAuth/SAML/OIDC,
JWT, CORS, CSP, cookies, TLS, DNS, headers, supply chain, secrets, GraphQL,
API security, cloud infrastructure, browser APIs, JavaScript/prototype,
CSS, DOM, web components, privacy, service workers, WebSockets, email,
file uploads, compliance.

### Security policy
Blue-team only — passive read-only analysis of sites you own.
No exploitation, no brute-force, no payload sending.
