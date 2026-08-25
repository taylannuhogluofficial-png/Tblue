> ## 🔧 In maintenance — a quick heads-up before you scan
>
> Thanks for checking out Tblue! An external review turned up some real issues,
> and I'd rather be upfront about them than stay quiet while I fix things.
>
> Parts of this README promise more than the code currently delivers. I'm
> rewriting both to match. Until that lands:
>
> - **Please skip `--cookie`, `--header`, `--bearer` and `--auth` for now.**
>   Those values currently get passed along to third-party lookup services.
>   If you've already run an authenticated scan on 1.0.0 or 1.0.1, please
>   rotate those credentials — sorry about that one.
> - **The default scan does more probing than the docs suggest.** Point it at
>   a staging site rather than production for now.
> - **The PyPI releases are yanked on purpose** — not a mistake, just keeping
>   the broken build out of people's hands until the fix ships.
>
> Fixes are in progress. Issues and PRs very welcome if you spot anything else.<div align="center">

```
████████╗ ██████╗  ██╗      ██╗   ██╗ ███████╗
╚══██╔══╝ ██╔══██╗ ██║      ██║   ██║ ██╔════╝
   ██║    ██████╔╝ ██║      ██║   ██║ █████╗
   ██║    ██╔══██╗ ██║      ██║   ██║ ██╔══╝
   ██║    ██████╔╝ ███████╗ ╚██████╔╝ ███████╗
   ╚═╝    ╚═════╝  ╚══════╝  ╚═════╝  ╚══════╝
```

**614 passive blue-team security scanners. Runs on your machine. No accounts. No data sent anywhere.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Scanners](https://img.shields.io/badge/scanners-614-cyan?style=flat-square)](#what-it-checks)
[![MCP Ready](https://img.shields.io/badge/MCP-ready-purple?style=flat-square)](#use-as-an-ai-plugin-mcp)
[![PyPI](https://img.shields.io/pypi/v/tblue?style=flat-square&color=blue)](https://pypi.org/project/tblue/)
[![Tests](https://img.shields.io/badge/tests-6692%20passing-brightgreen?style=flat-square)](#)

</div>

---

Tblue is a free, open-source security scanner for website owners. You point it at your site and it tells you what looks wrong — no security background required. It runs completely on your machine, sends no data to third parties, and requires no account or API key.

**It is blue-team only.** Every scanner reads HTTP responses, headers, cookies, JavaScript files, and page content. Nothing is modified. Nothing is brute-forced. No credentials are ever tested against your application.

---

## Quick demo

![Tblue terminal demo](demo.gif)

```
$ tblue -u https://example.com

  Scanning https://example.com — 614 modules · 50 workers · depth 3
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [FAIL] hsts_missing          HSTS not set — site reachable over plain HTTP
  [FAIL] csp_missing           Content-Security-Policy absent — no XSS defence
  [FAIL] x_frame_options       X-Frame-Options missing — clickjacking possible
  [FAIL] mixed_content         Page loads HTTP resources over HTTPS
  [WARN] cors_wildcard         CORS wildcard on /api — any origin can read responses
  [WARN] spf_softfail          SPF uses ~all (softfail) — upgrade to -all
  [WARN] dmarc_none            DMARC p=none — domain can be spoofed in phishing
  [WARN] cookie_samesite       Session cookie missing SameSite attribute
  [INFO] server_banner         Server: nginx/1.24.0 — version fingerprint exposed
  [PASS] tls_version           TLS 1.3 · certificate valid · no weak ciphers
  [PASS] js_secrets            No API keys or secrets found in JavaScript bundles
  [PASS] cookie_secure         Cookies — HttpOnly and Secure flags set correctly
  [PASS] dnssec                DNSSEC signed and validated

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Grade: D  ·  Score: 41/100  ·  4 FAIL · 4 WARN · 1 INFO · 4 PASS
  Report saved: example_com_20260816_143201.html
```

---

## Why Tblue

Most security scanners are built for attackers — they try to exploit things. Tblue is built for defenders. It reads what your site sends back and tells you what a real attacker would learn from it. The difference:

| | Tblue | Penetration testing tools |
|---|---|---|
| Purpose | Find what's exposed | Exploit what's exposed |
| Modifies anything | Never | Yes |
| Requires auth | No | Often |
| Safe to run anytime | Yes | No |
| Audience | Site owners, devs | Security professionals |

---

## What it checks

614 modules run in parallel. Every scan covers all of these:

| Category | What it looks for |
|---|---|
| **TLS and Transport** | Certificate validity, cipher weakness, HSTS, HTTPS redirect, compression oracle |
| **HTTP Headers** | CSP (with dangerous value detection), CORS, Permissions-Policy, Referrer-Policy, X-Frame-Options, 30+ header checks |
| **Cookies** | HttpOnly, Secure, SameSite, cookie prefixes, partitioned cookies |
| **Authentication** | JWT algorithm confusion, session fixation, session entropy, MFA detection, password policy, WebAuthn |
| **Authorization** | IDOR, broken object-level auth, mass assignment, path traversal, directory listing |
| **OAuth and Identity** | OAuth implicit flow, PKCE, redirect URI validation, SAML signature wrapping, OIDC nonce |
| **CSRF and Clickjacking** | CSRF token detection, double-submit cookie, SameSite bypass, tabnapping |
| **Injection** | Command injection patterns, SSTI, XXE, LDAP injection, log injection, CRLF injection |
| **XSS** | DOM sink detection (innerHTML, location), prototype pollution, CSS injection, SVG injection |
| **SSRF** | Cloud metadata exposure, DNS rebinding, open redirect chains |
| **Secrets** | API keys in JS bundles, debug endpoints, Spring Actuator, source maps, error page disclosure |
| **API Security** | Rate limiting, versioning downgrade, pagination abuse, schema exposure, GraphQL introspection |
| **Supply Chain** | SRI validation, dependency confusion signals, importmap security, polyfill hijacking |
| **Cloud** | Public S3 buckets, K8s API exposure, Docker daemon, CI/CD secret leakage |
| **DNS and Email** | SPF, DMARC, DKIM, CAA, DNSSEC, subdomain takeover, typosquatting |
| **Browser APIs** | WebUSB, WebBluetooth, WebXR, Payment Request, Geolocation, File System Access (78 checks) |
| **JavaScript** | Prototype pollution, RegEx DoS, Function constructor, unsafe eval patterns |
| **Privacy** | Canvas fingerprinting, EXIF metadata, PHI exposure, cookie consent |
| **Compliance** | PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF — each mapped to root security controls |

Full reference with descriptions, CWE mappings, and remediation guidance: **[SCANNERS.md](SCANNERS.md)**

---

## Installation

```bash
pip install tblue
```

**From source:**

```bash
git clone https://github.com/taylannuhogluofficial-png/Tblue.git
cd Tblue
pip install -e .
```

**Docker (no Python setup required):**

```bash
docker build -t tblue .
docker run --rm tblue -u https://yoursite.com
```

---

## Quick start

```bash
# Full scan — all 614 modules, 50 parallel workers
tblue -u https://yoursite.com

# Save an HTML report with remediation guidance for every finding
tblue -u https://yoursite.com -o report.html

# JSON output for programmatic use or dashboards
tblue -u https://yoursite.com --json -o report.json

# SARIF for GitHub Code Scanning / VS Code Problems panel
tblue -u https://yoursite.com --sarif -o results.sarif

# SIEM / SOC exports
tblue -u https://yoursite.com --siem cef        # ArcSight CEF format
tblue -u https://yoursite.com --siem elastic    # Elastic SIEM format
tblue -u https://yoursite.com --splunk          # Splunk SPL correlation searches
tblue -u https://yoursite.com --sigma           # Sigma detection rules (.yaml)
tblue -u https://yoursite.com --sentinel        # Microsoft Sentinel KQL analytics rules

# Run only specific modules
tblue -u https://yoursite.com --only headers,ssl,cookies,xss

# Run an entire category
tblue -u https://yoursite.com --only authentication

# Skip specific modules
tblue -u https://yoursite.com --skip browser_dom_xss

# Authenticated scan — pass your session cookie
tblue -u https://yoursite.com --cookie "session=abc123; csrftoken=xyz"

# Authenticated scan — Bearer token
tblue -u https://yoursite.com --bearer "eyJhbGci..."

# Browser-powered scan — covers SPA routing, DOM XSS, localStorage (requires Playwright)
tblue -u https://yoursite.com --browser

# AI-powered analysis of results (requires Anthropic API key)
tblue -u https://yoursite.com --ai-key $ANTHROPIC_API_KEY

# Continuous monitoring — re-scan every hour, alert on new findings
tblue -u https://yoursite.com --monitor --interval 3600

# CI/CD gate — exit code 1 if score drops below threshold
tblue -u https://yoursite.com --fail-below 80

# Compliance-focused scans (run the relevant compliance modules)
tblue -u https://yoursite.com --only pci_dss_compliance
tblue -u https://yoursite.com --only hipaa_compliance
tblue -u https://yoursite.com --only soc2_compliance,iso27001_compliance
```

---

## Use in CI / GitHub Actions

Gate your pipeline on security score. The scan fails the build if the score drops below your threshold:

```yaml
# .github/workflows/security.yml
name: Security scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  tblue:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install tblue
      - run: tblue -u https://yoursite.com --fail-below 80 -o tblue-report.html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: tblue-report
          path: tblue-report.html
```

`--fail-below 80` exits with code 1 if the score is under 80, failing the job. Remove it to always pass (report only).

---

## Output formats

| Format | Flag | Best for |
|---|---|---|
| Terminal | *(default)* | Quick review — colored PASS / WARN / FAIL, score A–F, trend vs last scan |
| HTML | `-o report.html` | Sharing with your team — full findings, fix instructions, category scores |
| JSON | `--json -o report.json` | Dashboards, CI pipelines, custom integrations |
| SARIF | `--sarif -o results.sarif` | GitHub Code Scanning and VS Code Problems panel |
| SIEM CEF/LEEF/Elastic | `--siem cef` / `--siem elastic` | SOC ingestion — ArcSight, QRadar, Elastic SIEM |
| Splunk SPL | `--splunk` | Native Splunk correlation searches |
| Sigma | `--sigma` | SIEM detection rules for correlation |
| Microsoft Sentinel KQL | `--sentinel` | Azure Sentinel / Azure Monitor queries |

---

## Severity levels

| Level | Meaning | Suggested action |
|---|---|---|
| **FAIL** | Clear security gap — missing header, dangerous config, exposed secret | Fix before next deploy |
| **WARN** | Weakened defence that needs an additional condition to exploit | Fix this sprint |
| **INFO** | Context useful for attacker reconnaissance | Review and suppress if intentional |
| **PASS** | Check passed — control is in place | No action needed |

The terminal and HTML report also show a letter grade (A+ to F) and a numeric score (0–100) based on the distribution of findings.

---

## Architecture

Tblue runs all 614 scanners in parallel using a `ThreadPoolExecutor` (default 50 workers). A shared response cache prevents redundant HTTP requests when multiple scanners hit the same URL.

Each scanner inherits from `BaseScanner`, returns typed result dicts, and short-circuits immediately when the response has no relevant signals — so passive scans stay fast even on slow sites.

Browser scanners are optional and powered by Playwright. They cover DOM XSS, SPA routing, and browser storage checks that are invisible from raw HTTP responses.

Scan history is stored locally at `~/.tblue/scans/`. Each run is compared against the previous one so you can see what improved and what regressed.

### Adding a scanner

```
1. Create tblue/scanner/your_scanner_name.py
2. Inherit from BaseScanner and implement scan(url) -> list
3. Return self._result(url, "check_type", "FAIL"|"WARN"|"PASS", detail="...") dicts
4. Add a gateway check so the scanner short-circuits when no relevant signals exist
5. Register it in tblue/cli.py — import it, add key to ALL_MODULES, add tuple to _SCANNER_REGISTRY
6. Write tests in tests/test_your_scanner_name.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete guide.

---

## Requirements

- Python 3.10 or higher
- `pip install tblue` installs all required dependencies automatically
- Playwright is optional — only needed for `--browser` mode:
  ```bash
  pip install playwright && playwright install
  ```

---

## Use as an AI plugin (MCP)

Tblue includes a built-in MCP server so you can give your AI assistant blue-team scanning as a native tool. Once connected, you can ask your AI to scan a site, explain a finding, or focus on a specific category — it handles the rest.

### Connect to Claude Code

```bash
claude mcp add tblue -e PYTHONPATH=/path/to/tblue -- python3 -m tblue.mcp_server
```

### Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac):

```json
{
  "mcpServers": {
    "tblue": {
      "command": "python3",
      "args": ["-m", "tblue.mcp_server"],
      "env": { "PYTHONPATH": "/path/to/tblue" }
    }
  }
}
```

### What the AI can do

Once connected, your AI has three tools:

**`scan`** — Run any or all scanners against a URL. Supports authentication, category filters, and module-level control. Returns severity-sorted findings with a grade, pass count, and diff against the previous scan.

```
"Scan my site for authentication weaknesses"
→ scan(url="https://yoursite.com", category="authentication")

"Full security audit with my session cookie"
→ scan(url="https://yoursite.com", auth_cookie="session=abc123")

"Check only JWT and CORS"
→ scan(url="https://yoursite.com", modules=["jwt", "cors"])
```

**`list_modules`** — List available scanner modules, optionally filtered by keyword or category.

```
"What JWT-related checks does Tblue have?"
→ list_modules(search="jwt")
```

**`explain_module`** — Get a plain-language explanation of what a specific scanner checks, why it matters, and how to fix it.

```
"What does the CORS scanner actually check?"
→ explain_module(module_key="cors")
```

### Scan categories

Pass any of these as `category` to run a focused scan:

`authentication` · `authorization` · `cors` · `csp` · `cookies` · `headers` · `tls` · `oauth` · `ssrf` · `secrets` · `api` · `graphql` · `supply_chain` · `cloud` · `dns` · `injection` · `csrf`

---

## Legal

Tblue is built for scanning websites you own or have explicit written permission to test. Running it against a site without authorization is illegal in most jurisdictions. The authors accept no liability for unauthorized use.

---

## Disclaimer

Tblue is a passive scanner by default — it only reads what your site sends back and never modifies state. The optional `--active` flag enables a small number of probing checks (e.g. sending crafted requests to detect open redirects or SSRF surfaces); only use it on targets you own or have explicit permission to test.

It flags things that look wrong based on known security standards. It does not verify that a finding is exploitable in your specific configuration, and it cannot catch issues that are only visible behind authentication or under specific conditions.

Treat findings as a starting point for your security review, not a final verdict. Validate critical issues manually before reporting them as confirmed vulnerabilities.

---

## License

MIT — see [LICENSE](LICENSE)
