# Changelog

All notable changes to Tblue are documented here.

## [1.0.0] — 2026-08-13

### Added
- 614 unique passive security scanners across 40+ categories
- Parallel execution via ThreadPoolExecutor (50 workers default)
- Response caching layer — shared fetch prevents redundant requests per scan
- Live ASCII terminal reporter with box-drawing progress list
- HTML report generation with severity breakdown
- JSON, SARIF, SIEM, Sigma, Splunk SPL, Microsoft Sentinel KQL output formats
- Browser-powered scanning via Playwright (`--browser` flag)
- Site crawler with configurable depth (`--crawl --depth N`)
- Live browser dashboard with Server-Sent Events streaming (`--dashboard`)
- AI-powered findings analysis (`--ai-analysis`)
- SOAR / webhook notification on findings (`--soar-target`)
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
