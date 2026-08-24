# I built a free tool that runs 614 passive security checks on any website

**tl;dr:** `pip install tblue` → `tblue -u https://yoursite.com` → get a security grade with fixes. No account, no API key, nothing sent anywhere.

---

## The problem I kept running into

Every time I wanted to do a quick security check on a site I was building, my options were:

- Pay for a scanner that wants a credit card before showing me anything
- Set up Burp Suite or ZAP — which take 30 minutes to configure before the first useful result
- Manually check headers in DevTools and hope I don't miss anything

None of those work when you just want a quick "is this obviously broken?" answer at the end of a sprint.

## What Tblue does differently

Tblue is **passive only**. It reads what your site sends back and flags what looks wrong. It never modifies anything, never brute-forces anything, never sends credentials. This means:

- You can run it any time without risk
- No proxy to set up — point it at a URL and go
- Works on production (nothing changes on the server side)

The output is a letter grade (A+ to F), a score (0–100), and a categorized list of findings with remediation guidance built in.

## What it actually checks (614 modules)

I was surprised by how many passive signals there are. Some examples:

**Security headers (30+ checks):**
- Content-Security-Policy — is it missing? Does it contain `unsafe-inline`? Is the `default-src` too permissive?
- CORS — is the `Access-Control-Allow-Origin` a wildcard? On which endpoints?
- Permissions-Policy, Referrer-Policy, X-Frame-Options, HSTS

**Cookies:**
- HttpOnly, Secure, SameSite for every cookie
- Cookie prefix rules (`__Secure-`, `__Host-`)

**Email security:**
- SPF, DKIM, DMARC — missing or misconfigured records
- CAA (Certificate Authority Authorization)

**Secrets in the page:**
- API keys in JavaScript bundles
- `.env`, `.git`, `composer.json`, `package.json` exposed
- Source map files that expose original source code

**DNS and infrastructure:**
- Subdomain takeover signals (dangling CNAMEs)
- DNSSEC validation
- Typosquatting detection for your domain

**Compliance:**
- PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF — each control mapped to the scanners that verify it

The full list is in [SCANNERS.md](https://github.com/taylannuhogluofficial-png/Tblue/blob/main/SCANNERS.md).

## What it looks like

```
$ tblue -u https://example.com

  Scanning https://example.com — 614 modules · 50 workers · depth 3
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [FAIL] hsts_missing       HSTS not set — site reachable over plain HTTP
  [FAIL] csp_missing        Content-Security-Policy absent — no XSS defence
  [FAIL] spf_missing        SPF record not found — domain open to spoofing
  [WARN] cors_wildcard      CORS Access-Control-Allow-Origin: * on /api
  [WARN] csp_unsafe_inline  unsafe-inline in script-src negates CSP
  [PASS] ssl_https          TLS 1.3 active, valid certificate chain
  [PASS] x_frame_options    X-Frame-Options: SAMEORIGIN present

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Grade: D  ·  Score: 41/100  ·  3 FAIL · 2 WARN · 2 PASS
  Report saved: example_com_20260823_091542.html
```

The HTML report is beautiful and shareable — dark theme, score ring, severity badges, and a full remediation playbook for every finding.

## Use it in CI

The `--fail-below` flag lets you gate your pipeline on security score:

```yaml
- run: pip install tblue
- run: tblue -u https://yoursite.com --fail-below 80 -o report.html
```

Exit code 1 if the score drops below 80. Works with GitHub Actions, GitLab CI, CircleCI — anything that checks exit codes.

## Use it with your AI assistant (MCP)

Tblue ships with a built-in MCP server:

```bash
claude mcp add tblue -- python3 -m tblue.mcp_server
```

After that you can ask Claude: *"Scan my site for authentication weaknesses"* and it runs the relevant scanners, explains the findings, and suggests fixes — without you opening a terminal.

## Installation

```bash
pip install tblue
tblue -u https://yoursite.com
```

That's it. No account. No API key. No data leaves your machine.

GitHub: [github.com/taylannuhogluofficial-png/Tblue](https://github.com/taylannuhogluofficial-png/Tblue)

---

*Would love to hear what you scan first, and what findings surprise you. Happy to answer questions in the comments.*
