# Scanner modules

Tblue is built as a collection of independent scanner modules.
Each module inherits from `BaseScanner` and implements a `scan(url)` method.

---

## SSL scanner

**File:** `tblue/scanner/ssl.py`

Checks whether the target site uses HTTPS.

Returns PASS if the URL scheme is `https`, FAIL if it is `http`.

---

## Header scanner

**File:** `tblue/scanner/headers.py`

Checks all 10 security headers with value analysis.

Checks:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Resource-Policy

For each header it checks:
1. Whether the header is present
2. Whether the value is configured correctly

Produces a letter grade A+ to F based on combined results.

---

## Cookie scanner

**File:** `tblue/scanner/cookies.py`

Reads Set-Cookie response headers and checks each cookie for:
- HttpOnly — prevents JavaScript from reading the cookie
- Secure — cookie only sent over HTTPS
- SameSite — prevents cross-site request forgery

---

## XSS scanner

**File:** `tblue/scanner/xss.py`

Tests forms and URL parameters for unescaped input reflection.

Uses a harmless text marker with no JavaScript. If the marker is reflected
back in the response unescaped, the field is flagged for manual review.

Tests:
- All forms found on the page (GET and POST)
- URL parameters in the page URL

---

## DOM scanner

**File:** `tblue/scanner/dom.py`

Scans page source for risky JavaScript patterns that could indicate
DOM-based XSS vulnerabilities.

Patterns checked:
- `document.write(`
- `innerHTML`
- `outerHTML`
- `eval(`
- `setTimeout(`
- `setInterval(`
- `location.hash`
- `document.URL`
- `document.referrer`

---

## Adding a new module

1. Create `tblue/scanner/your_module.py`
2. Inherit from `BaseScanner`
3. Implement `scan(url)` returning a list of result dicts
4. Register it in `tblue/cli.py`
5. Add definitions to `tblue/definitions/` if needed
6. Write tests in `tests/test_your_module.py`

See `CONTRIBUTING.md` for full guidance.
