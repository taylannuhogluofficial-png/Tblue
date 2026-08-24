# Changelog

All notable changes to Tblue are documented here.

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
