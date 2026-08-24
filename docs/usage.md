# Usage

## Basic scan

```bash
python -m tblue -u https://yoursite.com
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target URL (required) | — |
| `-d`, `--depth` | Crawl depth | 3 |
| `-o`, `--output` | Report output path | tblue_report.html |
| `--json` | Also export JSON report | off |
| `--skip` | Modules to skip | none |
| `--only` | Run specific modules only | all |
| `--version` | Show version | — |

## Examples

```bash
# Full scan with default settings
python -m tblue -u https://yoursite.com

# Save report to custom path
python -m tblue -u https://yoursite.com -o my_report.html

# Also export JSON
python -m tblue -u https://yoursite.com --json

# Run headers and SSL only
python -m tblue -u https://yoursite.com --only headers,ssl

# Skip XSS scanning
python -m tblue -u https://yoursite.com --skip xss

# Shallow crawl — faster for large sites
python -m tblue -u https://yoursite.com -d 1
```

## Output

After the scan completes you will see:

- Colored terminal output with pass / warn / fail per check
- A summary showing total passed, warned, and failed
- An HTML report saved to your output path — open it in any browser

## Reading the report

The HTML report has five sections:

**SSL** — confirms HTTPS is enabled

**Headers** — each of the 10 security headers with a letter grade A+ to F,
the actual header value, and what to fix if it is missing or weak

**Cookies** — each cookie with HttpOnly, Secure, and SameSite flag status

**XSS** — each form and URL parameter tested, with pass or fail per field

**DOM patterns** — risky JavaScript patterns found in your page source,
with an explanation of the risk and how to fix it

## Important

Only scan websites you own or have explicit written permission to test.
