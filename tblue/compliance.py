"""
Compliance report generator.

Maps Tblue scanner findings to five frameworks:
  - OWASP Top 10 2021 (A01–A10)
  - PCI DSS 4.0 (selected requirements)
  - NIST CSF 2.0 Functions (Identify / Protect / Detect / Respond / Recover)
  - ISO/IEC 27001:2022 Annex A controls
  - CWE Top 25 Most Dangerous Software Weaknesses

Call generate_report(all_results) after all scanners complete to get a
structured dict suitable for the HTML report or JSON export.
"""

from typing import List, Dict, Any

# ── Framework definitions ─────────────────────────────────────────────────────

OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

PCI_DSS_4 = {
    "4.2.1":  "Strong cryptography in transit",
    "6.2.4":  "Prevent injection / XSS in bespoke software",
    "6.3.2":  "Inventory of bespoke and third-party software",
    "6.4.1":  "Web-facing applications protected by WAF",
    "6.4.3":  "All payment page scripts managed and justified",
    "7.2":    "Access control systems configured to deny by default",
    "8.2.1":  "All user accounts managed per authentication policy",
    "8.3.6":  "Passwords meet minimum complexity requirements",
    "10.2":   "Audit logs capture required events",
    "12.3.4": "Hardware and software technologies reviewed for vulnerabilities",
    "12.10.4":"Personnel with incident response responsibilities are trained",
}

NIST_CSF = {
    "ID": "Identify — understand assets, risks, and governance",
    "PR": "Protect — implement safeguards",
    "DE": "Detect — identify cybersecurity events",
    "RS": "Respond — take action on detected incidents",
    "RC": "Recover — restore capabilities after incidents",
}

ISO_27001_2022 = {
    "A.5.8":  "Information security in project management",
    "A.5.14": "Information transfer (secure protocols)",
    "A.5.23": "Information security for cloud services",
    "A.8.9":  "Configuration management",
    "A.8.20": "Network security controls",
    "A.8.21": "Security of network services",
    "A.8.22": "Segregation of networks",
    "A.8.23": "Web filtering",
    "A.8.24": "Use of cryptography",
    "A.8.25": "Secure development life cycle",
    "A.8.26": "Application security requirements",
    "A.8.27": "Secure system architecture and engineering principles",
    "A.8.28": "Secure coding",
    "A.8.29": "Security testing in development and acceptance",
    "A.8.32": "Change management",
    "A.8.33": "Test information",
    "A.8.34": "Protection of information systems during audit testing",
}

CWE_TOP25 = {
    "CWE-79":  "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-89":  "Improper Neutralization of Special Elements in SQL Commands (SQLi)",
    "CWE-22":  "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-78":  "Improper Neutralization of Special Elements in OS Commands",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-77":  "Improper Neutralization of Special Elements in a Command",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-1321":"Improperly Controlled Modification of Prototype Attributes",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-400": "Uncontrolled Resource Consumption (DoS / rate limiting)",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-276": "Incorrect Default Permissions (directory listing)",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-1275":"Sensitive Cookie with Improper SameSite Attribute",
}

# ── Mapping rules ─────────────────────────────────────────────────────────────
# Each rule: (keyword_in_scanner_type_lower, {owasp:[...], pci:[...], nist:[...]})

_RULES: List[tuple] = [
    # HSTS, HTTPS, TLS, mixed content
    ("hsts|tls|ssl|mixed.*content|redirect.*http|cleartext",
     {"owasp": ["A02"], "pci": ["4.2.1"], "nist": ["PR"]}),

    # CSP, unsafe-inline, XSS
    ("csp|unsafe.*inline|unsafe.*eval|xss|content.*security.*policy",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR", "DE"]}),

    # Cookie flags
    ("cookie.*httponly|cookie.*secure|cookie.*samesite|session.*cookie",
     {"owasp": ["A02", "A07"], "pci": ["8.2.1"], "nist": ["PR"]}),

    # Admin, exposed endpoints
    ("admin.*expos|phpymyadmin|actuator|exposed.*endpoint|debug.*panel",
     {"owasp": ["A01", "A05"], "pci": ["7.2"], "nist": ["PR", "DE"]}),

    # CORS
    ("cors|cross.*origin",
     {"owasp": ["A01", "A05"], "pci": [], "nist": ["PR"]}),

    # SRI, supply chain, third-party scripts
    ("sri|supply.*chain|third.*party.*script|subresource.*integrity",
     {"owasp": ["A08"], "pci": ["6.4.3"], "nist": ["PR", "ID"]}),

    # Outdated / vulnerable libraries, SCA
    ("sca.*cve|outdated.*lib|js.*lib.*cve|cms.*cve|known.*vulnerability|outdated.*component",
     {"owasp": ["A06"], "pci": ["6.3.2", "12.3.4"], "nist": ["ID", "DE"]}),

    # JWT, authentication
    ("jwt|alg.*none|weak.*jwt|authentication|login",
     {"owasp": ["A07"], "pci": ["8.2.1", "8.3.6"], "nist": ["PR"]}),

    # Open redirect, phishing
    ("open.*redirect|redirect.*parameter",
     {"owasp": ["A01"], "pci": [], "nist": ["PR"]}),

    # Host header injection
    ("host.*header.*inject",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"]}),

    # HTTP methods (TRACE, PUT)
    ("http.*trace|trace.*method|put.*method|dangerous.*method",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"]}),

    # Headers (missing security headers)
    ("x-frame-options|x-content-type|referrer-policy|permissions.*policy|security.*header",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"]}),

    # WAF
    ("waf.*not.*detected|no.*waf",
     {"owasp": ["A05"], "pci": ["6.4.1"], "nist": ["PR", "DE"]}),

    # DNS, subdomain takeover
    ("subdomain.*takeover|dangling.*dns|dns.*security|caa|dnssec|dmarc|spf|dkim",
     {"owasp": ["A05"], "pci": [], "nist": ["ID", "PR"]}),

    # Port exposure, infra
    ("port.*open|port.*expos|database.*port|redis|mongodb",
     {"owasp": ["A05"], "pci": ["7.2"], "nist": ["ID", "PR"]}),

    # JS secrets, credentials in code
    ("js.*secret|api.*key.*expos|credential.*file|\\.env.*expos|private.*key",
     {"owasp": ["A02", "A05"], "pci": ["6.3.2"], "nist": ["PR", "DE"]}),

    # HTML comments, info disclosure
    ("html.*comment|info.*disclosure|error.*page|stack.*trace|version.*disclosure",
     {"owasp": ["A05"], "pci": [], "nist": ["DE"]}),

    # DOM risks, prototype pollution, postMessage
    ("dom.*risk|prototype|postmessage",
     {"owasp": ["A03", "A08"], "pci": ["6.2.4"], "nist": ["PR"]}),

    # GDPR, privacy, consent
    ("gdpr|consent|cookie.*banner|privacy.*policy",
     {"owasp": ["A05"], "pci": [], "nist": ["ID"]}),

    # Threat intelligence
    ("abuseipdb|virustotal|otx|threat.*intel|ip.*reputation",
     {"owasp": ["A09"], "pci": ["10.2"], "nist": ["DE", "RS"]}),

    # Security.txt, disclosure, contact
    ("security.*txt|vulnerability.*disclosure|contact.*security",
     {"owasp": ["A09"], "pci": ["12.10.4"], "nist": ["RS"]}),

    # Typosquatting
    ("typosquat|lookalike.*domain",
     {"owasp": ["A05"], "pci": [], "nist": ["ID", "DE"]}),

    # Robots.txt, exposed paths
    ("robots.*txt|sitemap|backup.*file|source.*map",
     {"owasp": ["A05"], "pci": [], "nist": ["DE"],
      "iso": ["A.8.23"], "cwe": []}),

    # Rate limiting
    ("rate.*limit|brute.*force",
     {"owasp": ["A07"], "pci": ["8.3.6"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-400"]}),

    # Form security, CSRF
    ("form.*security|csrf|login.*get",
     {"owasp": ["A01", "A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.28"], "cwe": ["CWE-352"]}),

    # Cloud storage
    ("s3.*public|azure.*blob.*public|gcs.*public|cloud.*storage.*public",
     {"owasp": ["A01", "A05"], "pci": ["7.2"], "nist": ["PR", "DE"],
      "iso": ["A.5.23", "A.8.20"], "cwe": ["CWE-732"]}),

    # Phase 11/12 additions
    ("api.*surface|openapi.*expos|swagger.*expos|routes.*without.*security",
     {"owasp": ["A01", "A05"], "pci": ["7.2"], "nist": ["ID", "PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-306"]}),

    ("directory.*listing|index.*of|parent.*directory",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-276"]}),

    ("ssrf|server.?side.*request.*forgery",
     {"owasp": ["A10"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.28"], "cwe": ["CWE-918"]}),

    ("oauth.*implicit|oauth.*state|oauth.*redirect.*uri|oauth.*client.*secret|oidc",
     {"owasp": ["A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.8.25", "A.8.28"], "cwe": ["CWE-306"]}),

    ("cache.*poison|unkeyed.*header",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.28"], "cwe": ["CWE-79"]}),

    ("request.*smuggling|cl.*te|te.*cl",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.21"], "cwe": ["CWE-444"]}),

    ("websocket.*ws://|websocket.*unencrypt|websocket.*auth",
     {"owasp": ["A02", "A07"], "pci": ["4.2.1", "8.2.1"], "nist": ["PR"],
      "iso": ["A.8.24"], "cwe": ["CWE-311"]}),

    ("saml.*http|saml.*relay.*state|saml.*assertion|saml.*metadata",
     {"owasp": ["A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.8.25", "A.8.26"], "cwe": ["CWE-601", "CWE-306"]}),

    ("prototype.*pollution|__proto__|unsafe.*merge|proto.*assignment",
     {"owasp": ["A03", "A08"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.28", "A.8.29"], "cwe": ["CWE-1321"]}),

    ("open.*redirect|relay.*state.*redirect",
     {"owasp": ["A01"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-601"]}),

    ("cookie.*secure|cookie.*samesite|cookie.*httponly",
     {"owasp": ["A02", "A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-614", "CWE-1275"]}),

    # ── Phase 16 compliance rules ─────────────────────────────────────────────
    # JWT Advanced
    ("jwt.*alg.*none|jwt.*kid.*traversal|jwt.*jku.*http",
     {"owasp": ["A02", "A07"], "pci": ["8.3.1", "8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-347", "CWE-345"]}),

    ("jwt.*missing.*exp|jwt.*long.*expiry|jwt.*in.*url",
     {"owasp": ["A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-613", "CWE-598"]}),

    # CORS Advanced
    ("cors.*origin.*reflected|cors.*arbitrary.*origin|cors.*null.*origin|cors.*subdomain.*bypass",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-942", "CWE-346"]}),

    # HTTP/2
    ("http2.*vulnerable|cve-2023-44487|rapid.*reset|h2c.*cleartext",
     {"owasp": ["A05", "A06"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR", "RC"],
      "iso": ["A.8.8", "A.8.22"], "cwe": ["CWE-400", "CWE-770"]}),

    # GraphQL advanced
    ("graphql.*ide.*exposed|graphiql.*exposed|graphql.*introspection.*production",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-200", "CWE-284"]}),

    ("graphql.*batching|graphql.*stack.*trace|graphql.*sensitive.*field",
     {"owasp": ["A03", "A09"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-770", "CWE-209"]}),

    # ── Phase 18 compliance rules ─────────────────────────────────────────────
    # API Security Headers
    ("api.*security.*stack.*trace|api.*database.*error|api.*server.*version",
     {"owasp": ["A05", "A09"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-209", "CWE-200", "CWE-16"]}),

    ("api.*security.*cache.*control|api.*security.*xcto|api.*security.*missing",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-525", "CWE-16"]}),

    # Rate limiting
    ("rate.*limit.*missing|no.*rate.*limit.*sensitive|rate.*limit.*sensitive",
     {"owasp": ["A04", "A07"], "pci": ["6.2.4", "8.3.6"], "nist": ["PR"],
      "iso": ["A.8.22", "A.8.26"], "cwe": ["CWE-307", "CWE-799"]}),

    # SSRF Advanced
    ("ssrf.*url.*accept|ssrf.*form.*param|ssrf.*import.*webhook|ssrf.*xml.*xxe|ssrf.*private.*ip",
     {"owasp": ["A10"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.22"], "cwe": ["CWE-918", "CWE-611", "CWE-352"]}),

    # GraphQL depth limiting
    ("graphql.*depth.*deep|graphql.*no.*limit|graphql.*alias.*amplif",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.22", "A.8.26"], "cwe": ["CWE-400", "CWE-770"]}),

    # Business logic flaws
    ("business.*logic.*price|client.*submitted.*price|hidden.*price|idor.*sequential",
     {"owasp": ["A01", "A04"], "pci": ["6.2.4", "12.3.2"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-285", "CWE-639", "CWE-841"]}),

    ("business.*logic.*privilege|privilege.*escalation.*form|role.*field.*in.*form",
     {"owasp": ["A01", "A04"], "pci": ["7.2.1", "7.2.2"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.2"], "cwe": ["CWE-285", "CWE-269"]}),

    # OAuth Advanced
    ("oauth.*advanced.*pkce|authorization.*code.*without.*pkce|pkce.*plain",
     {"owasp": ["A07", "A02"], "pci": ["8.3.6", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-287", "CWE-352", "CWE-345"]}),

    ("oauth.*advanced.*scope|over.privileged.*scope|scope.*admin",
     {"owasp": ["A01", "A07"], "pci": ["7.2.1", "7.2.2"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.2"], "cwe": ["CWE-272", "CWE-732"]}),

    ("oauth.*advanced.*nonce|oidc.*nonce|oauth.*advanced.*device|dynamic.*client.*registration",
     {"owasp": ["A07", "A02"], "pci": ["8.3.6"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-287", "CWE-294"]}),

    # CRLF Injection
    ("crlf.*injection|response.*splitting|crlf.*redirect|crlf.*marker",
     {"owasp": ["A03", "A06"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-93", "CWE-113", "CWE-20"]}),

    # Mass Assignment
    ("mass.*assignment.*privileged|mass.*assignment.*is.admin|mass.*assignment.*role"
     "|mass.*assignment.*field.*accepted|mass.*assignment.*422",
     {"owasp": ["A01", "A04"], "pci": ["6.2.4", "7.2.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-915", "CWE-285", "CWE-732"]}),

    # Log Injection
    ("log.*injection.*user.agent|log.*injection.*xff|log.*injection.*crlf"
     "|log.*injection.*log4shell|log.*forging",
     {"owasp": ["A03", "A09"], "pci": ["6.2.4", "10.3.1"], "nist": ["DE", "PR"],
      "iso": ["A.8.15", "A.8.26"], "cwe": ["CWE-117", "CWE-93", "CWE-116"]}),

    # File Inclusion
    ("file.*inclusion.*passwd|lfi.*confirmed|file.*inclusion.*win.ini"
     "|file.*inclusion.*php.*filter|file.*inclusion.*php.*include",
     {"owasp": ["A01", "A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-22", "CWE-98", "CWE-73"]}),

    # Content Injection
    ("content.*injection.*unescaped.*html|html.*injection.*parameter"
     "|content.*injection.*css.*injection",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-74", "CWE-80", "CWE-116"]}),

    # API Authentication Security
    ("api.*auth.*basic.*http|basic.*auth.*non.https|api.*key.*url|api.*key.*query.*string"
     "|api.*auth.*accessible.*without|401.*missing.*www-authenticate",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.3.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.5", "A.9.4", "A.8.26"], "cwe": ["CWE-287", "CWE-306", "CWE-522"]}),

    # IDOR
    ("idor.*parameter|idor.*adjacent.*resource|idor.*api.*resource",
     {"owasp": ["A01"], "pci": ["6.2.4", "7.1.1"], "nist": ["PR", "DE"],
      "iso": ["A.8.3", "A.5.15"], "cwe": ["CWE-639", "CWE-284", "CWE-285"]}),

    # Sensitive Data Exposure
    ("sensitive.*data.*credential.*url|sensitive.*data.*password.*url"
     "|sensitive.*data.*session.*url|session.*token.*url",
     {"owasp": ["A02"], "pci": ["6.2.4", "4.2.1"], "nist": ["PR"],
      "iso": ["A.8.10", "A.8.12"], "cwe": ["CWE-598", "CWE-200", "CWE-319"]}),

    ("sensitive.*data.*html.*comment|token.*html.*comment"
     "|sensitive.*data.*pii.*url",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.12", "A.5.34"], "cwe": ["CWE-200", "CWE-359", "CWE-540"]}),

    ("sensitive.*data.*autocomplete|password.*autocomplete",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-256", "CWE-200"]}),

    # HTTP Verb Tampering
    ("http.*verb.*tampering.*trace|trace.*method.*enabled"
     "|http.*verb.*tampering.*debug|http.*verb.*tampering.*override",
     {"owasp": ["A05", "A01"], "pci": ["6.2.4", "1.3.2"], "nist": ["PR"],
      "iso": ["A.8.20", "A.8.26"], "cwe": ["CWE-650", "CWE-749", "CWE-16"]}),

    # Service Worker Security
    ("service.*worker.*root.*scope|service.*worker.*fetch.*cache"
     "|pwa.*manifest.*http.*start_url|pwa.*manifest.*scope",
     {"owasp": ["A05", "A08"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-829", "CWE-1021", "CWE-16"]}),

    # XXE Injection
    ("xxe.*injection.*passwd|xxe.*injection.*win.ini|xxe.*file.*disclosed"
     "|xxe.*injection.*xml.*parser.*error|xxe.*dtd.*processing",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-611", "CWE-776", "CWE-918"]}),

    # SSRF
    ("ssrf.*cloud.*metadata|ssrf.*metadata.*endpoint"
     "|ssrf.*private.*ip|ssrf.*internal.*ip|ssrf.*connection.*error",
     {"owasp": ["A10"], "pci": ["6.2.4", "1.3.2"], "nist": ["PR", "DE"],
      "iso": ["A.8.20", "A.8.22", "A.8.26"], "cwe": ["CWE-918", "CWE-441"]}),

    # LDAP Injection
    ("ldap.*injection.*bypass|ldap.*injection.*authentication.*bypass"
     "|ldap.*injection.*metacharacter|ldap.*error.*triggered",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-90", "CWE-116", "CWE-287"]}),

    ("ldap.*injection.*error.*message.*leaked|ldap.*error.*baseline",
     {"owasp": ["A04", "A09"], "pci": ["6.2.4"], "nist": ["PR", "DE"],
      "iso": ["A.8.15", "A.8.26"], "cwe": ["CWE-90", "CWE-209"]}),

    # Command Injection
    ("command.*injection.*uid.*gid|command.*injection.*os.*command.*output"
     "|command.*injection.*shell.*error|command.*injection.*timing.*delay",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-78", "CWE-88", "CWE-116"]}),

    # Dependency Confusion
    ("dependency.*confusion.*internal|internal.*package.*manifest"
     "|dependency.*confusion.*npm|dependency.*confusion.*pypi",
     {"owasp": ["A06", "A08"], "pci": ["6.3.2", "6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.8", "A.8.30"], "cwe": ["CWE-427", "CWE-829", "CWE-494"]}),

    ("dependency.*confusion.*manifest.*exposed|npm.*manifest.*exposed"
     "|requirements.*exposed|gemfile.*exposed",
     {"owasp": ["A05", "A06"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.26", "A.8.30"], "cwe": ["CWE-200", "CWE-540"]}),

    # OpenAPI / Swagger exposure
    ("openapi.*documentation.*ui|openapi.*swagger.*ui|redoc.*exposed"
     "|openapi.*spec.*exposed|openapi.*machine.readable",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "6.5.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.26", "A.8.23"], "cwe": ["CWE-200", "CWE-213"]}),

    ("openapi.*internal.*server|openapi.*staging|openapi.*secret",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.12"], "cwe": ["CWE-200", "CWE-540", "CWE-312"]}),

    # Clickjacking
    ("clickjacking.*no framing|clickjacking.*no.*protection|clickjacking.*sensitive"
     "|clickjacking.*allow.from|clickjacking.*js.*frame",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1021", "CWE-693"]}),

    # Account Enumeration
    ("account.*enumeration.*status|account.*enumeration.*user.*not.*found"
     "|account.*enumeration.*success|account.*enumeration.*size",
     {"owasp": ["A07", "A01"], "pci": ["6.2.4", "8.2.6"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-204", "CWE-203", "CWE-200"]}),

    # HTTP Parameter Pollution
    ("http.*parameter.*pollution|hpp.*last.*duplicate|hpp.*both|hpp.*array|hpp.*encoded",
     {"owasp": ["A03", "A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-235", "CWE-20", "CWE-436"]}),

    # Weak Cryptography
    ("weak.*crypto.*md5|weak.*crypto.*digest|content.md5|low.entropy.*session"
     "|weak.*crypto.*cipher|weak.*cipher|md5.*length.*token",
     {"owasp": ["A02", "A07"], "pci": ["4.2.1", "8.3.2", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.24"], "cwe": ["CWE-327", "CWE-916", "CWE-330", "CWE-326"]}),

    # CSP bypass vectors
    ("csp.*advanced.*unsafe.inline|csp.*advanced.*wildcard|csp.*advanced.*data.*uri"
     "|csp.*advanced.*jsonp|csp.*bypass",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4", "6.3.2"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-693", "CWE-116"]}),

    # ── Phase 15 compliance rules ─────────────────────────────────────────────
    # K8s exposure
    ("k8s.*exposed|kubernetes.*api.*exposed|k8s.*namespace|k8s.*secret",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "7.2.1"], "nist": ["PR", "DE"],
      "iso": ["A.8.22", "A.8.23"], "cwe": ["CWE-284", "CWE-306"]}),

    # SCIM
    ("scim.*exposed|scim.*unauthenticated|identity.*management.*endpoint",
     {"owasp": ["A01", "A07"], "pci": ["8.2.1", "8.3.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.2"], "cwe": ["CWE-284", "CWE-306"]}),

    # gRPC
    ("grpc.*reflection|grpc.*endpoint.*exposed|grpc.*content.*type",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-284", "CWE-200"]}),

    # Cloud metadata / SSRF
    ("cloud.*metadata|ssrf.*imds|metadata.*ssrf|kubernetes.*service.*account",
     {"owasp": ["A10"], "pci": ["6.2.4"], "nist": ["PR", "DE"],
      "iso": ["A.8.22", "A.8.23"], "cwe": ["CWE-918", "CWE-522"]}),

    # NoSQL injection
    ("nosql.*injection|mongodb.*operator|couchdb.*admin|nosql.*error",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-943", "CWE-89"]}),

    # Web cache deception
    ("web.*cache.*deception|cache.*hit.*sensitive|cacheable.*authenticated",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-525", "CWE-200"]}),

    # Session management
    ("session.*id.*url|session.*identifier.*url|jsessionid|phpsessid.*url",
     {"owasp": ["A02", "A07"], "pci": ["8.2.1", "8.3.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-598", "CWE-200"]}),

    ("weak.*session.*token|predictable.*session|session.*entropy",
     {"owasp": ["A02", "A07"], "pci": ["8.3.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-330", "CWE-331"]}),

    ("session.*management|multiple.*session.*cookies|remember.me.*expiry|session.*logout",
     {"owasp": ["A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-384", "CWE-613"]}),

    # CI/CD pipeline exposure
    ("cicd.*exposure|pipeline.*config.*expos|github.*workflow|jenkinsfile.*expos|travis.*yml",
     {"owasp": ["A05", "A02"], "pci": ["6.3.2", "6.4.2"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-312", "CWE-200"]}),
    ("hardcoded.*secret.*ci|cicd.*secret|pipeline.*token.*expos|dockerfile.*expos",
     {"owasp": ["A02", "A05"], "pci": ["6.3.2", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.13"], "cwe": ["CWE-312", "CWE-798"]}),
    (r"package\.json.*expos|requirements.*expos|composer.*expos|dependency.*fingerprint",
     {"owasp": ["A06", "A05"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200", "CWE-693"]}),
    ("coverage.*report.*expos|test.*result.*expos|build.*report.*expos",
     {"owasp": ["A05"], "pci": ["6.4.2"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # EL injection
    ("spring4shell|cve.2022.22965|spel.*evaluation.*error|spring.*expression.*injection",
     {"owasp": ["A03", "A06"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR", "RS"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-917", "CWE-95"]}),
    ("ognl.*evaluation.*error|struts.*ognl|cve.2017.5638|cve.2023.50164",
     {"owasp": ["A03", "A06"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR", "RS"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-917", "CWE-77"]}),
    ("thymeleaf.*injection|thymeleaf.*expression.*injection",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-917"]}),
    ("unprocessed.*el.*expression|jsp.*el.*artifact",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-917"]}),
    ("struts.*debug.*console|struts.*webconsole",
     {"owasp": ["A05", "A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-917", "CWE-16"]}),
    ("spring.*whitelabel.*error|spring.*boot.*error.*page",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-209"]}),

    # JSON injection
    ("jsonp.*callback.*not.*validated|jsonp.*injection|jsonp.*reflected",
     {"owasp": ["A03", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-74", "CWE-79"]}),
    ("json.*injection.*parameter|json.*key.*injected",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-74", "CWE-116"]}),
    ("__proto__.*pollution.*json|prototype.*pollution.*json",
     {"owasp": ["A03", "A08"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-74", "CWE-1321"]}),
    ("json.*unescaped.*html|unescaped.*html.*json",
     {"owasp": ["A03", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-116", "CWE-79"]}),
    ("json.*content.type.*missing.*nosniff|json.*x.content.type",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-116"]}),

    # Race condition / TOCTOU
    ("race.*condition|toctou|double.spend|concurrent.*token.*redemption",
     {"owasp": ["A04", "A07"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-362", "CWE-367"]}),
    ("idempotency.*missing.*token|coupon.*no.*idempotency|gift.card.*race",
     {"owasp": ["A04", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-362", "CWE-352"]}),
    ("rate.*limit.*bypass.*concurrent|concurrent.*bypass",
     {"owasp": ["A04"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR", "RS"],
      "iso": ["A.8.26"], "cwe": ["CWE-307", "CWE-362"]}),
    ("idempotency.*key.*supported|idempotency.*protection",
     {"owasp": ["A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-362"]}),

    # Password reset security
    ("password.*reset.*host.*header|host.*header.*injection.*reset",
     {"owasp": ["A07", "A05"], "pci": ["6.2.4", "8.4.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-640", "CWE-20"]}),
    ("password.*reset.*csrf|no.*csrf.*reset",
     {"owasp": ["A01", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-352", "CWE-640"]}),
    ("reset.*token.*url|token.*query.*string.*reset|weak.*reset.*token",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.4.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.5"], "cwe": ["CWE-598", "CWE-640"]}),
    ("user.*enumeration.*reset|reset.*reveals.*email",
     {"owasp": ["A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-204", "CWE-640"]}),
    ("reset.*session.*cookie|reset.*cookie.*secure|reset.*cookie.*httponly",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-614", "CWE-1004"]}),

    # API version security
    (r"api.*version.*auth.*bypass|deprecated.*api.*auth.*bypass|v\d+.*auth.*bypass",
     {"owasp": ["A01", "A07"], "pci": ["6.2.4", "8.4.1"], "nist": ["PR", "ID"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-306", "CWE-287"]}),
    ("deprecated.*api.*version|old.*api.*version.*active|api.*sunset",
     {"owasp": ["A09"], "pci": ["6.3.2"], "nist": ["ID", "PR"],
      "iso": ["A.8.9", "A.8.26"], "cwe": ["CWE-1059", "CWE-693"]}),
    ("api.*version.*enumeration|shadow.*api|unversioned.*api",
     {"owasp": ["A09", "A05"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200", "CWE-1059"]}),
    ("deprecation.*header|sunset.*header",
     {"owasp": ["A09"], "pci": ["6.3.2"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-1059"]}),

    # WebAuthn / FIDO2 security
    ("webauthn.*rpid.*wildcard|relying.*party.*wildcard",
     {"owasp": ["A07"], "pci": ["8.4.1", "8.4.2"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.5"], "cwe": ["CWE-287", "CWE-295"]}),
    ("sms.*otp.*fallback|sms.*bypass|webauthn.*sms|sim.*swap",
     {"owasp": ["A07"], "pci": ["8.4.1"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-308", "CWE-287"]}),
    ("webauthn.*conditional.*ui|passkey.*autocomplete|fido2.*ux",
     {"owasp": ["A07"], "pci": ["8.4.1"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-308"]}),
    ("http.*magic.*link|plaintext.*auth.*link",
     {"owasp": ["A02", "A07"], "pci": ["8.4.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.5"], "cwe": ["CWE-319", "CWE-287"]}),
    ("webauthn.*discovery|well.known.*webauthn",
     {"owasp": ["A07"], "pci": ["8.4.1"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-287"]}),

    # Client-side storage security
    ("password.*written.*localstorage|secret.*localstorage|credential.*sessionstorage",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR"],
      "iso": ["A.8.11", "A.8.26"], "cwe": ["CWE-312", "CWE-922"]}),
    ("jwt.*token.*localstorage|auth.*token.*localstorage|bearer.*sessionstorage",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR"],
      "iso": ["A.8.11", "A.8.5", "A.8.26"], "cwe": ["CWE-312", "CWE-922", "CWE-614"]}),
    ("pii.*payment.*localstorage|credit.*card.*storage|ssn.*sessionstorage",
     {"owasp": ["A02"], "pci": ["3.2.1", "3.5.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.11", "A.5.33"], "cwe": ["CWE-312", "CWE-922"]}),
    ("auth.*read.*localstorage|getitem.*token.*auth",
     {"owasp": ["A07", "A01"], "pci": ["8.4.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-522", "CWE-312"]}),
    ("indexeddb.*sensitive|indexed.*db.*credentials",
     {"owasp": ["A02"], "pci": ["3.5.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.11"], "cwe": ["CWE-312", "CWE-922"]}),
    ("sensitive.*key.*localstorage|sensitive.*key.*sessionstorage",
     {"owasp": ["A02"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.11"], "cwe": ["CWE-312"]}),
    ("websql.*deprecated|openDatabase|web.*sql.*database",
     {"owasp": ["A04"], "pci": ["6.3.2"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-477"]}),

    # Client-Side Template Injection (CSTI)
    ("angularjs.*sandbox.*escape|angularjs.*csti|ng.app.*sandbox",
     {"owasp": ["A03", "A06"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-1336"]}),
    ("ng.bind.html.*sanitize|ng-bind-html.*ngsanitize",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79", "CWE-116"]}),
    ("angular.*eval.*parse.*expression|angularjs.*eval",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-1336"]}),
    ("vue.*v.html|vue.*html.*directive",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79", "CWE-116"]}),
    ("react.*dangerously.*setinnerhtml|dangerouslysetinnerhtml",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79"]}),
    ("handlebars.*triple.*stache|triple.stache.*unescaped",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79", "CWE-116"]}),
    ("angular.*bypass.*security.*trust|bypasssecuritytrust",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-1336"]}),
    ("nunjucks.*renderstring.*user|nunjucks.*template.*injection",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-1336"]}),
    ("client.side.*template.*injection|csti.*unsafe",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79", "CWE-1336"]}),

    # Fetch Metadata policy (COOP/COEP/CORP)
    ("missing.*cross.origin.opener.policy|coop.*absent|cross.origin.*opener.*policy",
     {"owasp": ["A05", "A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-693", "CWE-352"]}),
    ("missing.*cross.origin.embedder.policy|coep.*absent",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-693"]}),
    ("missing.*cross.origin.resource.policy|corp.*absent|cross.site.*corp",
     {"owasp": ["A05", "A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-284", "CWE-352"]}),
    ("api.*endpoint.*cross.site.*corp|form.*endpoint.*cross.site",
     {"owasp": ["A05", "A01"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-352", "CWE-284"]}),
    ("fetch.*metadata.*policy|coop.*coep.*corp.*headers",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-693"]}),

    # Path confusion / URL normalization bypass
    ("path.*confusion.*access.*control|url.*normalization.*bypass|path.*bypass",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-22", "CWE-284", "CWE-436"]}),
    ("spring.*actuator.*bypass|actuator.*path.*confusion",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR", "ID"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-284", "CWE-22"]}),
    ("double.slash.*bypass|nginx.*path.*bypass|semicolon.*path.*bypass",
     {"owasp": ["A01"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-436", "CWE-284"]}),
    ("double.*encoded.*slash|null.*byte.*bypass|trailing.*dot.*bypass",
     {"owasp": ["A01", "A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-22", "CWE-436"]}),

    # CSV / Formula Injection
    ("dde.*formula.*csv|csv.*dde.*injection|dde.*command.*csv",
     {"owasp": ["A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1236", "CWE-94"]}),
    ("unescaped.*formula.*csv|formula.*injection.*csv|csv.*injection|spreadsheet.*injection",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1236"]}),
    ("csv.*missing.*content.disposition|csv.*without.*attachment",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-116", "CWE-1236"]}),
    ("csv.*nosniff.*missing|csv.*content.type.*options",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-116"]}),

    # Reflected File Download (RFD)
    ("rfd.*user.controlled.*executable|reflected.*file.*download.*bat|rfd.*probe.*executable",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-494", "CWE-79"]}),
    ("reflected.*file.*download|rfd.*filename.*controlled|rfd.*content.*disposition",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-494", "CWE-116"]}),
    ("jsonp.*callback.*attachment.*rfd|rfd.*jsonp",
     {"owasp": ["A03", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-494", "CWE-79"]}),
    ("rfd.*script.*content.*attachment|script.*prefix.*download",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-494"]}),

    # Source Map Exposure
    ("source.*map.*source.*content|javascript.*source.*map.*exposed|sourcecontent.*exposed",
     {"owasp": ["A05", "A02"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.26"], "cwe": ["CWE-540", "CWE-200"]}),
    (r"source.*map.*publicly|\.map.*file.*exposed|sourcemap.*exposed",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-540", "CWE-200"]}),
    (r"webpack.*stats.*json|stats\.json.*exposed",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200", "CWE-540"]}),
    ("internal.*path.*source.*root|sourceRoot.*server.*path",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # Framework Config and Log File Exposure (Phase 44)
    (r"laravel.*log.*exposed|storage.*logs.*accessible|application.*log.*exposed|error\.log.*accessible",
     {"owasp": ["A09", "A02"], "pci": ["6.2.4", "10.2"], "nist": ["PR", "DE"],
      "iso": ["A.8.15", "A.8.12"], "cwe": ["CWE-532", "CWE-200", "CWE-312"]}),
    ("log.*auth.*token.*exposed|session.*id.*log|token.*in.*log",
     {"owasp": ["A02", "A09"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.15"], "cwe": ["CWE-532", "CWE-312", "CWE-522"]}),
    (r"spring.*boot.*application.*properties|application\.yml.*exposed|datasource.*password",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-312", "CWE-538", "CWE-200"]}),
    (r"appsettings.*json.*exposed|asp\.net.*connectionstring.*exposed",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-312", "CWE-538"]}),
    (r"rails.*database\.yml.*exposed|rails.*secrets\.yml|rails.*master\.key",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.24"], "cwe": ["CWE-312", "CWE-321", "CWE-538"]}),
    ("django.*settings.*exposed|django.*secret_key|local_settings.*exposed",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-312", "CWE-798", "CWE-538"]}),
    (r"web\.config.*password|web\.config.*connectionstring",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-312", "CWE-538"]}),
    (r"hibernate.*cfg.*exposed|persistence\.xml.*exposed|jdbc.*password",
     {"owasp": ["A02"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12"], "cwe": ["CWE-312", "CWE-538"]}),
    ("framework.*config.*no.*exposed|no.*configuration.*file.*log.*file",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-538"]}),

    # API Collection Exposure (Phase 43)
    ("postman.*collection.*exposed|postman_collection.*accessible|insomnia.*workspace.*exposed",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "3.5.1", "8.6.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.12", "A.8.9", "A.5.23"], "cwe": ["CWE-312", "CWE-538", "CWE-200"]}),
    ("hoppscotch.*collection.*exposed|api.*client.*collection.*exposed",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-200", "CWE-538"]}),
    ("bearer.*token.*authorization.*collection|api.*key.*header.*collection",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.3.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.5.15"], "cwe": ["CWE-312", "CWE-522", "CWE-798"]}),
    ("hardcoded.*credential.*collection|credential.*postman|credential.*insomnia",
     {"owasp": ["A02"], "pci": ["3.5.1", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12"], "cwe": ["CWE-312", "CWE-798"]}),
    ("no.*postman.*collection.*exposed|no.*api.*collection.*exposed",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-538"]}),

    # Link Security — Tabnabbing / Opener Hijacking (Phase 42)
    ("target.*blank.*missing.*noopener|reverse.*tabnabbing|opener.*hijacking",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1022", "CWE-200"]}),
    ("external.*iframe.*without.*sandbox|iframe.*sandbox.*missing|unsandboxed.*iframe",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-1021", "CWE-693"]}),
    ("window.*open.*noopener.*missing|window.*open.*blank.*without.*noopener",
     {"owasp": ["A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-1022"]}),
    ("dns.prefetch.*tracking|preconnect.*tracking|tracking.*prefetch.*privacy",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.5.34", "A.8.26"], "cwe": ["CWE-200"]}),
    ("link.*security.*no.*opener|link.*security.*no.*issue",
     {"owasp": ["A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-1022"]}),

    # Developer Artifact Exposure (Phase 41)
    ("har.*file.*exposed|browser.*har.*session|network.*har.*file|har.*cookie.*data",
     {"owasp": ["A02", "A09"], "pci": ["3.5.1", "6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.10", "A.8.12"], "cwe": ["CWE-312", "CWE-538", "CWE-200"]}),
    ("terraform.*state.*file|terraform.*tfstate|terraform.*state.*secret.*value",
     {"owasp": ["A02", "A05"], "pci": ["3.5.1", "6.2.4", "8.6.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.12", "A.8.9", "A.5.23"], "cwe": ["CWE-312", "CWE-538", "CWE-200"]}),
    (r"\.npmrc.*auth.*token|npmrc.*npm.*auth.*exposed|yarnrc.*auth.*token",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.26"], "cwe": ["CWE-312", "CWE-798"]}),
    ("ssh.*private.*key.*exposed|id_rsa.*accessible|id_ed25519.*accessible|server.*key.*accessible",
     {"owasp": ["A02"], "pci": ["8.3.1", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.24", "A.8.12"], "cwe": ["CWE-312", "CWE-321", "CWE-522"]}),
    (r"docker.*config.*auth.*exposed|docker.*registry.*auth|docker.*config\.json.*accessible",
     {"owasp": ["A02", "A05"], "pci": ["8.6.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.12", "A.5.23"], "cwe": ["CWE-312", "CWE-538"]}),
    ("aws.*credentials.*exposed|aws.*access.*key.*detected|aws_secret_access_key",
     {"owasp": ["A02", "A05"], "pci": ["8.6.1", "3.5.1", "6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.12", "A.5.23", "A.8.9"], "cwe": ["CWE-312", "CWE-798", "CWE-522"]}),
    ("kubeconfig.*exposed|kubernetes.*kubeconfig.*accessible|kube.*cluster.*token",
     {"owasp": ["A02", "A01"], "pci": ["8.6.1", "6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.12", "A.5.15", "A.8.9"], "cwe": ["CWE-312", "CWE-522", "CWE-284"]}),
    ("package.lock.*embedded.*credential|package.lock.*git.*token",
     {"owasp": ["A02", "A06"], "pci": ["6.2.4", "6.3.2"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.30"], "cwe": ["CWE-312", "CWE-540"]}),
    ("composer.*auth.*json.*exposed|composer.*github.*oauth.*token",
     {"owasp": ["A02", "A05"], "pci": ["8.6.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.26"], "cwe": ["CWE-312", "CWE-798"]}),
    ("developer.*artifact.*exposed|sensitive.*developer.*file|no.*developer.*file.*exposed",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-538", "CWE-200"]}),

    # Phase 45 — XSSI (Cross-Site Script Inclusion) — WSTG-CLNT-13
    ("xssi.*json.*array.*anti.xssi|json.*array.*missing.*anti.xssi|json.*array.*without.*prefix",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-284", "CWE-200", "CWE-829"]}),
    ("xssi.*nosniff.*missing|json.*response.*missing.*nosniff",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-116", "CWE-284"]}),
    ("xssi.*content.type.*missing|json.*missing.*application.json",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-116", "CWE-200"]}),
    ("no.*xssi.*vulnerabilities|xssi.*pass",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-284"]}),

    # Phase 49 — GraphQL Field Suggestion & Schema Enumeration
    ("graphql.*field.*suggestion.*schema|did you mean.*graphql|graphql.*schema.*enumerat",
     {"owasp": ["A05", "A01"], "pci": ["6.2.4", "6.4.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-200", "CWE-209"]}),
    ("graphql.*stack.*trace|graphql.*file.*path.*error|graphql.*exception",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-209"]}),
    ("no.*graphql.*schema.*enumeration|graphql.*field.*suggestion.*pass",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200"]}),

    # Phase 48 — AI/LLM API Endpoint Exposure
    ("ollama.*model.*list|ai.*model.*without.*auth|llm.*endpoint.*accessible",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "6.4.1"], "nist": ["PR", "ID"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-200", "CWE-284"]}),
    ("flowise.*chatflow|flowise.*api.*key|langflow.*exposed",
     {"owasp": ["A01", "A02"], "pci": ["6.2.4", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.5.15"], "cwe": ["CWE-284", "CWE-200"]}),
    ("ai.*api.*exposure.*accessible|hf.*tgi.*exposed|vllm.*exposed",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR", "RS"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-200", "CWE-284"]}),
    ("no.*exposed.*ai.*llm.*api|ai.*api.*exposure.*pass",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-284"]}),

    # Phase 47 — Cross-Domain Policy & Mobile App Link Security
    ("crossdomain.*xml.*allows.*all.*origins|allow.access.from.*domain.*wildcard|crossdomain.*wildcard",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "6.4.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-183", "CWE-284"]}),
    ("clientaccesspolicy.*allows.*all|clientaccess.*wildcard|silverlight.*cross.domain",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-284"]}),
    ("assetlinks.*missing.*sha|android.*app.*link.*missing.*fingerprint",
     {"owasp": ["A01", "A07"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-284", "CWE-345"]}),
    ("apple.app.site.*discloses|aasa.*ios|assetlinks.*android.*package|mobile.*deep.*link",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.26"], "cwe": ["CWE-200", "CWE-284"]}),
    ("no.*permissive.*cross.domain|cross.domain.*pass",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-284"]}),

    # Phase 46 — Server-Timing Information Disclosure
    ("server.timing.*sensitive.*information|server.timing.*service.*name|server.timing.*internal.*ip",
     {"owasp": ["A05"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.26"], "cwe": ["CWE-200", "CWE-208"]}),
    ("server.timing.*auth.*timing|timing.*side.channel.*auth",
     {"owasp": ["A07", "A05"], "pci": ["8.3.2", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-208", "CWE-200"]}),
    ("no.*sensitive.*server.timing|server.timing.*pass",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # Phase 50 — JS File Analysis (DOM XSS Sinks)
    ("js file.*eval|dom sink.*eval|js.*new function",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-95"]}),
    ("js file.*inner.*html|js file.*document.*write|dom sink.*inner|insert.*adjacent",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79", "CWE-80"]}),
    ("js file.*prototype.*pollution|prototype.*pollution.*js",
     {"owasp": ["A03", "A08"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-915", "CWE-1321"]}),
    ("js file.*postmessage.*origin|postmessage.*without.*origin.*js",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-346", "CWE-79"]}),
    ("js file.*document.*domain|document.*domain.*relaxation",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-183"]}),
    ("js file.*fetch.*credentials|credential.*fetch.*cross.origin",
     {"owasp": ["A02", "A05"], "pci": ["4.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-346", "CWE-352"]}),
    ("js file.*no.*dangerous|no.*dom sink|js.*analysis.*pass",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79"]}),

    # Phase 51 — Version CVE Correlation
    ("version cve.*critical|version cve.*high|known.*cve|vulnerable.*component.*version",
     {"owasp": ["A06"], "pci": ["6.3.2", "12.3.4"], "nist": ["ID", "PR"],
      "iso": ["A.8.8", "A.8.29"], "cwe": ["CWE-1035", "CWE-937"]}),
    ("version.*banner.*exposed|software.*version.*exposed|server.*version.*banner",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),
    ("version cve.*pass|no.*version.*banner",
     {"owasp": ["A06", "A05"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.8"], "cwe": ["CWE-1035"]}),

    # Phase 53 — LLM Prompt Injection Surface
    ("llm.*prompt.*injection|prompt injection.*accessible|chat.*widget|llm.*api.*endpoint",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4", "6.4.1"], "nist": ["PR", "DE"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-77", "CWE-200"]}),
    ("llm.*error.*leak|system.*prompt.*leak|llm.*configuration.*leak",
     {"owasp": ["A02", "A05"], "pci": ["6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.26"], "cwe": ["CWE-200", "CWE-209"]}),
    ("no.*llm.*endpoint|llm.*pass",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-77"]}),

    # Phase 54 — XSLeak (Cross-Site Leak)
    ("xsleak.*coop.*missing|cross.origin.opener.*missing",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-346"]}),
    ("xsleak.*coep.*missing|cross.origin.embedder.*missing",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200"]}),
    ("xsleak.*corp.*missing|cross.origin.resource.*missing",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-346"]}),
    ("xsleak.*framing|framing.*protection.*missing",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-1021"]}),
    ("timing.allow.origin.*xsleak|xsleak.*timing",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-208"]}),
    ("xsleak.*vary.*cookie|authenticated.*vary.*cookie",
     {"owasp": ["A05"], "pci": ["4.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-525"]}),
    ("xsleak.*pass|cross.site.*isolation.*in.place",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200"]}),

    # Phase 55 — Crawler / Informational meta-findings
    (r"crawled pages",
     {"owasp": ["A09"], "pci": [], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),
    (r"^http://",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.20"], "cwe": ["CWE-319"]}),
    (r"^https://",
     {"owasp": ["A02"], "pci": ["4.2.1"], "nist": ["PR"],
      "iso": ["A.8.24"], "cwe": ["CWE-311"]}),

    # Phase 56 — Login page security
    ("login.*csrf|login.*cache.*control|login.*form.*method|login.*form.*get"
     "|login.*page.*http|login.*sri|login.*subresource",
     {"owasp": ["A07", "A01"], "pci": ["8.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-352", "CWE-613"]}),
    ("login.*https|login.*mfa|login.*account.*lockout|login.*rate.*limit"
     "|login.*username.*enumeration|login.*remember.*me",
     {"owasp": ["A07", "A04"], "pci": ["8.3.1", "8.3.4", "8.3.6"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.5"], "cwe": ["CWE-307", "CWE-308", "CWE-204"]}),
    ("login.*password.*autocomplete|login.*password.*maxlength|login.*password.*field"
     "|login.*password.*type",
     {"owasp": ["A07", "A02"], "pci": ["8.3.2", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-256", "CWE-521"]}),

    # Phase 57 — Email infrastructure security
    ("email security.*dkim|email security.*spf|email security.*dmarc"
     "|email.*bimi|email.*dane.*tlsa|email.*mta.sts|email.*tls.rpt",
     {"owasp": ["A05", "A09"], "pci": ["6.2.4", "12.1.2"], "nist": ["PR", "DE"],
      "iso": ["A.8.20", "A.8.22"], "cwe": ["CWE-940", "CWE-345"]}),
    ("email.*dmarc.*fully.*enforced|email.*dmarc.*p.quarantine|email.*dmarc.*partial"
     "|email.*dmarc.*subdomain|email.*spf.*allows.*all|email.*spf.*approaching"
     "|email.*spf.*exceeded|email.*spf.*neutral|email.*spf.*strict",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.20"], "cwe": ["CWE-940"]}),

    # Phase 58 — TLS deep findings
    ("tls.*hsts.*not.*preload|tls.*hsts.*preload.*ready|tls.*md5.*cert|tls.*sha.1.*cert"
     "|tls.*cert.*expired|tls.*cert.*expiring|tls.*cert.*expiry|tls.*cert.*signature"
     "|tls.*forward.*secrecy|tls.*key.*size|tls.*weak.*ec|tls.*no.*forward",
     {"owasp": ["A02", "A05"], "pci": ["4.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.24", "A.8.20"], "cwe": ["CWE-326", "CWE-295", "CWE-310"]}),
    ("ssl.*https|ssl.*sans.*coverage|ssl.*sans.*mismatch|ssl.*tls.*version"
     "|ssl.*cert.*authority|ssl.*cert.*chain|ssl.*cert.*expiry|ssl.*no.*sans|ssl.*self.signed",
     {"owasp": ["A02"], "pci": ["4.2.1"], "nist": ["PR"],
      "iso": ["A.8.24"], "cwe": ["CWE-295", "CWE-326"]}),

    # Phase 59 — Cookie attribute variants
    ("cookie.*samesite.*missing|cookie.*samesite.lax|cookie.*samesite.none"
     "|cookie.*samesite.strict|cookie.*host.*prefix.*violation"
     "|cookie.*missing.*partitioned|cookie.*missing.*security.*prefix"
     "|cookie.*wildcard.*domain|cookie.*low.*entropy|cookie.*long.*expiry"
     "|cookie.*expiry|cookie.*overly.*broad.*domain|cookie flags.*duplicate",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-614", "CWE-1275", "CWE-330"]}),
    ("cookie advanced.*all.*cookies.*pass|cookie advanced.*no.*cookies.*set",
     {"owasp": ["A02", "A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-614"]}),

    # Phase 60 — CSP and CSP advanced
    ("csp.*base.uri|csp.*form.action|csp.*frame.ancestors|csp.*nonce.*quality"
     "|csp.*object.src|csp.*bypass.*source|csp.*static.*nonce|csp.*weak.*nonce"
     "|csp.*violation.*reporting|csp.*no.*violation|csp.*deprecated.*csp"
     "|csp.*duplicate.*headers",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-693"]}),
    ("csp advanced.*report.only|csp advanced.*base.uri.*not|csp advanced.*meta.*tag"
     "|csp advanced.*form.action.*not|csp advanced.*frame.ancestors"
     "|csp advanced.*upgrade.insecure|csp advanced.*violation.*reporting"
     "|csp advanced.*trusted.*types",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-693", "CWE-116"]}),
    ("csp.*delivered.*meta.*tag|csp.*frame.ancestors.*wildcard|csp.*dangerous.*value"
     "|csp.*potential.*bypass",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-693", "CWE-79"]}),

    # Phase 61 — Deserialization
    ("deserialization.*asp.net.*viewstate|deserialization.*java.*serial"
     "|deserialization.*java.*object|deserialization.*php.*serial"
     "|deserialization.*python.*pickle|deserialization.*node.serialize"
     "|deserialization.*no.*insecure",
     {"owasp": ["A08", "A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-502", "CWE-915"]}),

    # Phase 62 — Form security
    ("form.*well.known.*change.password|form.*csrf.*missing|form.*csrf.*present"
     "|form.*password.*manager|form.*sensitive.*cach",
     {"owasp": ["A01", "A07"], "pci": ["6.2.4", "8.4.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-352", "CWE-525"]}),

    # Phase 63 — Permissions-Policy
    ("permissions.policy.*missing|permissions.policy.*allowed.*all|permissions.policy.*blocked"
     "|permissions.policy.*not.*restricted|permissions.policy.*partially.*restricted"
     "|permissions.policy.*restricted.*self|permissions.policy.*configured"
     "|permissions.policy.*header.*absent|permissions.policy.*deprecated|feature.policy",
     {"owasp": ["A05", "A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-693", "CWE-16"]}),

    # Phase 64 — File upload
    ("file upload.*http.*put|file upload.*dangerous.*mime|file upload.*no.*csrf"
     "|file upload.*no.*content.type|file upload.*no.*upload.*forms"
     "|file upload.*server.side.*path.*disclosed|file upload.*wildcard.*accept",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4", "6.5.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-434", "CWE-552", "CWE-352"]}),

    # Phase 65 — GDPR and privacy
    ("gdpr.*cookie.*consent|gdpr.*cookies.*before.*consent|gdpr.*no.*privacy.*policy"
     "|gdpr.*no.*tracking|gdpr.*privacy.*policy.*present|gdpr.*tracking.*without.*consent"
     "|gdpr.*tracking.*with.*consent",
     {"owasp": ["A05", "A01"], "pci": [], "nist": ["GV", "PR"],
      "iso": ["A.5.34", "A.5.31"], "cwe": ["CWE-359", "CWE-200"]}),

    # Phase 66 — API auth and versioning
    ("api auth.*returns.*200.*error|api auth.*no.*authentication.*weaknesses"
     "|api auth.*no.*response|api security headers.*all.*passed"
     "|api security headers.*endpoint.*unresponsive|api security headers.*no.*api"
     "|api security headers.*no.*response|api security.*missing.*strict.transport"
     "|api security.*server.*version.*exposed|api security.*unusually.*large",
     {"owasp": ["A07", "A05"], "pci": ["6.2.4", "8.3.1"], "nist": ["PR"],
      "iso": ["A.8.26", "A.5.15"], "cwe": ["CWE-306", "CWE-200"]}),
    ("api versioning.*target.*unreachable|api versioning.*missing.*security.*headers"
     "|api versioning.*returns.*data.*auth|api collection.*target.*unreachable",
     {"owasp": ["A09", "A05"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-1059", "CWE-200"]}),

    # Phase 67 — AI API unreachable
    ("ai api exposure.*target.*unreachable",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200"]}),

    # Phase 68 — Account enumeration informational
    ("account enumeration.*no.*auth.*endpoints|account enumeration.*no.*response"
     "|account enumeration.*responses.*indistinguishable",
     {"owasp": ["A07", "A01"], "pci": ["8.2.6", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-204", "CWE-200"]}),

    # Phase 69 — Business logic informational
    ("business logic.*no.*obvious|business logic.*no.*response"
     "|business logic.*quantity.*field",
     {"owasp": ["A04", "A01"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-841", "CWE-285"]}),

    # Phase 70 — CI/CD informational
    ("ci.*cd.*exposure.*accessible|ci.*cd.*exposure.*unreachable"
     "|ci/cd exposure.*accessible|ci/cd exposure.*unreachable",
     {"owasp": ["A05", "A02"], "pci": ["6.3.2", "6.4.2"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.12"], "cwe": ["CWE-312", "CWE-200"]}),

    # Phase 71 — CMS detection
    ("cms detection.*not.*identified|cms.*detected",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # Phase 72 — COEP / CORP / CORS advanced
    ("coep header missing|corp header missing|coep.*cross.origin.embedder"
     "|corp.*cross.origin.resource",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-693"]}),
    ("cors advanced.*arbitrary.*subdomain.*trusted|cors advanced.*no.*origin.*validation",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-942", "CWE-346"]}),
    ("cors.*policy$",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-942"]}),

    # Phase 73 — CSTI Nunjucks
    ("csti.*nunjucks|csti.*target.*unreachable",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-1336"]}),

    # Phase 74 — CSV injection informational
    ("csv injection.*lacks.*content.disposition|csv injection.*target.*unreachable",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-1236", "CWE-116"]}),

    # Phase 75 — Clickjacking JS-only / no response
    ("clickjacking.*only.*javascript|clickjacking.*js.*frame.busting"
     "|clickjacking.*no.*response",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-1021"]}),

    # Phase 76 — Client-side storage specifics
    ("client.side storage.*indexeddb|client.side storage.*jwt|client.side storage.*auth.*token"
     "|client.side storage.*no.*sensitive|client.side storage.*target.*unreachable",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR"],
      "iso": ["A.8.11", "A.8.26"], "cwe": ["CWE-312", "CWE-922"]}),

    # Phase 77 — Command / Content injection informational
    ("command injection.*no.*indicators|command injection.*no.*response"
     "|command injection.*no.*vulnerable",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-78"]}),
    ("content injection.*no.*indicators|content injection.*no.*reflectable"
     "|content injection.*no.*response",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-74"]}),

    # Phase 78 — Cross-domain policy specifics
    ("cross.domain policy.*clientaccess.*exposes|cross.domain policy.*clientaccess.*present"
     "|cross.domain policy.*crossdomain.*allows.*http|cross.domain policy.*crossdomain.*present"
     "|cross.domain policy.*crossdomain.*wildcard|cross.domain policy.*target.*unreachable",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-284", "CWE-183"]}),

    # Phase 79 — DNS nameserver diversity
    ("dns.*all.*nameservers.*same.*provider|dns.*nameservers.*are.*diverse"
     "|dns.*single.*nameserver",
     {"owasp": ["A05"], "pci": [], "nist": ["PR", "RC"],
      "iso": ["A.8.22"], "cwe": ["CWE-695"]}),

    # Phase 80 — DOM external scripts SRI
    ("dom.*external.*scripts.*sri|dom.*external.*scripts.*without.*sri",
     {"owasp": ["A08", "A05"], "pci": ["6.3.2", "6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.30", "A.8.9"], "cwe": ["CWE-829", "CWE-494"]}),

    # Phase 81 — Dependency confusion informational
    ("dependency confusion.*no.*manifest.*found|dependency confusion.*no.*response",
     {"owasp": ["A06", "A08"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.30"], "cwe": ["CWE-427"]}),

    # Phase 82 — Developer artifact unreachable
    ("developer artifact.*target.*unreachable",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-538"]}),

    # Phase 83 — EL injection (Apache Commons JEXL)
    ("el injection.*apache.*commons.*jexl|el injection.*target.*unreachable",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-917"]}),

    # Phase 84 — Exposed files
    ("exposed file.*TEST_VALUE|exposed files.*none.*found",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-538", "CWE-200"]}),

    # Phase 85 — Fetch Metadata informational
    ("fetch metadata.*coop.*coep.*corp.*present|fetch metadata.*target.*unreachable",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-693"]}),

    # Phase 86 — File inclusion no response
    ("file inclusion.*no.*response",
     {"owasp": ["A01", "A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-22"]}),

    # Phase 87 — Framework config unreachable
    ("framework config.*target.*unreachable",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # Phase 88 — GraphQL informational
    ("graphql advanced.*no.*issues|graphql advanced.*sensitive.*field"
     "|graphql depth.*no.*endpoint|graphql depth.*no.*issues|graphql depth.*no.*response"
     "|graphql.*no.*endpoint.*detected",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200"]}),

    # Phase 89 — HTML comment informational
    ("html comment.*TEST_VALUE|html comments.*no.*sensitive",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-615"]}),

    # Phase 90 — HTTP methods
    ("http methods$|http methods.*allow.*header.*not.*present"
     "|http methods.*dangerous.*method|http methods.*write.*method",
     {"owasp": ["A05", "A01"], "pci": ["6.2.4", "1.3.2"], "nist": ["PR"],
      "iso": ["A.8.20", "A.8.26"], "cwe": ["CWE-749", "CWE-650"]}),

    # Phase 91 — HTTP verb tampering informational
    ("http verb tampering.*arbitrary.*method.*accepted|http verb tampering.*no.*issues"
     "|http verb tampering.*no.*response",
     {"owasp": ["A05", "A01"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.20", "A.8.26"], "cwe": ["CWE-749", "CWE-650"]}),

    # Phase 92 — HTTP → HTTPS redirect
    ("http.*→.*https.*redirect|http.*https.*redirect",
     {"owasp": ["A02", "A05"], "pci": ["4.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.20", "A.8.24"], "cwe": ["CWE-319"]}),

    # Phase 93 — HTTP/2 no issues
    ("http/2.*no.*http/2.*security.*issues",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.22"], "cwe": ["CWE-400"]}),

    # Phase 94 — Header reflection
    ("header reflection.*TEST_VALUE",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-116"]}),

    # Phase 95 — IDOR informational
    ("idor.*no.*indicators.*detected|idor.*no.*response",
     {"owasp": ["A01"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-639"]}),

    # Phase 96 — JS file analysis informational
    ("js file analysis.*no.*same.origin|js file analysis.*target.*unreachable",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-79"]}),

    # Phase 97 — JS libraries outdated
    ("js libraries.*no.*detectable.*versions|js libraries.*versions.*appear.*current"
     "|js library.*outdated",
     {"owasp": ["A06"], "pci": ["6.3.2", "6.3.3"], "nist": ["ID", "PR"],
      "iso": ["A.8.8", "A.8.9"], "cwe": ["CWE-1035", "CWE-937"]}),

    # Phase 98 — JSON injection informational
    ("json injection.*html.*js.*injection|json injection.*json.like.*data"
     "|json injection.*__proto__|json injection.*no.*vulnerabilities"
     "|json injection.*target.*unreachable",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-74", "CWE-79"]}),

    # Phase 99 — JWT Advanced informational
    ("jwt advanced.*www.authenticate.*bearer.*http|jwt advanced.*no.*jwt.*security"
     "|jwt advanced.*no.*issues.*detected",
     {"owasp": ["A02", "A07"], "pci": ["8.3.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-319", "CWE-287"]}),

    # Phase 100 — JWT security informational
    ("jwt security.*algorithm.*expiry|jwt security.*long.lived|jwt security.*no.*expiry"
     "|jwt security.*no.*tokens.*detected|jwt security.*symmetric",
     {"owasp": ["A02", "A07"], "pci": ["8.3.1", "8.2.1"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-347", "CWE-613", "CWE-327"]}),

    # Phase 101 — K8s specifics
    ("k8s.*kubernetes.*api.*response.*on.*main|k8s.*TEST_VALUE.*accessible",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "7.2.1"], "nist": ["PR", "DE"],
      "iso": ["A.8.22", "A.8.23"], "cwe": ["CWE-284", "CWE-306"]}),

    # Phase 102 — LDAP injection informational
    ("ldap injection.*no.*indicators|ldap injection.*no.*login.*form"
     "|ldap injection.*no.*response",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-90"]}),

    # Phase 103 — Link security unreachable
    ("link security.*target.*unreachable",
     {"owasp": ["A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-1022"]}),

    # Phase 104 — Log injection
    ("log injection.*value.*reflected.*response|log injection.*no.*reflection"
     "|log injection.*no.*response",
     {"owasp": ["A03", "A09"], "pci": ["6.2.4", "10.3.1"], "nist": ["DE", "PR"],
      "iso": ["A.8.15", "A.8.26"], "cwe": ["CWE-117", "CWE-116"]}),

    # Phase 105 — Management endpoint
    ("management endpoint.*accessible",
     {"owasp": ["A05", "A01"], "pci": ["6.2.4", "7.2.1"], "nist": ["PR"],
      "iso": ["A.8.22", "A.8.26"], "cwe": ["CWE-284", "CWE-306"]}),

    # Phase 106 — Mass assignment informational
    ("mass assignment.*no.*indicators|mass assignment.*no.*response",
     {"owasp": ["A01", "A04"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-915"]}),

    # Phase 107 — Mobile deep link
    ("mobile deep link.*assetlinks",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-284", "CWE-345"]}),

    # Phase 108 — OAuth Advanced informational
    ("oauth advanced.*no.*authorization.*code|oauth advanced.*no.*issues"
     "|oauth advanced.*no.*response|oauth.*oidc.*no.*flows|oauth.*oidc.*no.*obvious",
     {"owasp": ["A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-306", "CWE-287"]}),

    # Phase 109 — Open ports
    ("open ports.*TEST_VALUE",
     {"owasp": ["A05"], "pci": ["1.3.1"], "nist": ["ID", "PR"],
      "iso": ["A.8.20", "A.8.22"], "cwe": ["CWE-284"]}),

    # Phase 110 — OpenID Connect discovery
    ("openid connect discovery",
     {"owasp": ["A07", "A05"], "pci": ["8.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-200", "CWE-287"]}),

    # Phase 111 — PII disclosure
    ("pii disclosure.*phone|pii disclosure.*credit",
     {"owasp": ["A02"], "pci": ["3.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.34", "A.8.12"], "cwe": ["CWE-359", "CWE-200"]}),

    # Phase 112 — Password reset informational
    ("password reset.*no.*reset.*flow|password reset.*target.*unreachable"
     "|password reset.*user.*enumeration",
     {"owasp": ["A07", "A01"], "pci": ["8.4.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.5"], "cwe": ["CWE-640", "CWE-204"]}),

    # Phase 113 — Path confusion unreachable
    ("path confusion.*target.*unreachable",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-22", "CWE-284"]}),

    # Phase 114 — Path traversal variants
    ("path traversal.*high.risk.*file|path traversal.*medium.risk.*dir"
     "|path traversal.*traversal.*sequence.*parameter|path traversal.*no.*lfi",
     {"owasp": ["A01", "A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-22", "CWE-73"]}),

    # Phase 115 — RFD unreachable
    ("rfd.*target.*unreachable",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-494"]}),

    # Phase 116 — Rate limiting informational
    ("rate limiting.*enforced|rate limiting.*no.*response.*from.*target"
     "|rate limiting.*not.*detected",
     {"owasp": ["A04", "A07"], "pci": ["8.3.6", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.22", "A.8.26"], "cwe": ["CWE-307", "CWE-799"]}),

    # Phase 117 — Redirect chain
    ("redirect chain.*redirect.*hop.*acceptable|redirect chain.*excessive.*redirect"
     "|redirect chain.*many.*redirect|redirect chain.*redirect.*loop",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-601", "CWE-20"]}),

    # Phase 118 — Referrer-Policy permissive
    ("referrer.policy.*no.referrer.when.downgrade|referrer.policy.*unsafe.url",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-116"]}),

    # Phase 119 — Response header specifics
    ("response header.*dns.*prefetch|response header.*etag.*inode"
     "|response header.*x.dns.prefetch.*not.*set|response header.*deprecated",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.9"], "cwe": ["CWE-200", "CWE-16"]}),

    # Phase 120 — SAML specifics
    ("saml.*sso.*endpoint.*found|saml.*assertion.*visible"
     "|saml.*sso.*no.*saml.*flows|saml.*sso.*no.*obvious",
     {"owasp": ["A07", "A02"], "pci": ["8.2.1", "8.3.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.5"], "cwe": ["CWE-287", "CWE-306"]}),

    # Phase 121 — SCA
    ("sca.*no.*known.*vulnerabilities.*in|sca.*vulnerable.*dependencies.*in",
     {"owasp": ["A06"], "pci": ["6.3.2", "12.3.4"], "nist": ["ID", "PR"],
      "iso": ["A.8.8", "A.8.29"], "cwe": ["CWE-1035", "CWE-937"]}),

    # Phase 122 — SRI advanced / SRI informational
    ("sri advanced.*integrity.*without.*crossorigin|sri.*all.*external.*resources"
     "|sri.*no.*external.*resources|sri.*external.*without.*integrity",
     {"owasp": ["A08", "A05"], "pci": ["6.3.2", "6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.30", "A.8.9"], "cwe": ["CWE-829", "CWE-494"]}),

    # Phase 123 — SSTI additional
    ("ssti.*werkzeug.*interactive|ssti.*template.*syntax.*visible"
     "|ssti.*template.*engine.*error.*exposed",
     {"owasp": ["A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1336", "CWE-95"]}),

    # Phase 124 — Security headers specifics
    ("security headers.*cors.*cookie.*samesite|security headers.*deprecated"
     "|security headers.*duplicate",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-16", "CWE-614"]}),

    # Phase 125 — Sensitive URL parameter
    ("sensitive url parameter.*TEST_VALUE|sensitive url parameters.*none.*detected"
     "|sensitive.*url.*param",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.26"], "cwe": ["CWE-598", "CWE-200"]}),

    # Phase 126 — Sensitive data exposure informational
    ("sensitive data exposure.*no.*issues|sensitive data exposure.*no.*response"
     "|sensitive data exposure.*password.*autocomplete",
     {"owasp": ["A02"], "pci": ["6.2.4", "3.5.1"], "nist": ["PR"],
      "iso": ["A.8.12", "A.8.10"], "cwe": ["CWE-256", "CWE-200"]}),

    # Phase 127 — Server-Timing unreachable
    ("server.timing.*target.*unreachable",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # Phase 128 — Service worker security informational
    ("service worker security.*no.*issues|service worker security.*no.*response"
     "|service worker.*pwa.*manifest.*scope",
     {"owasp": ["A05", "A08"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-829", "CWE-1021"]}),

    # Phase 129 — Session management informational
    ("session management.*no.*issues|session management.*remember.me",
     {"owasp": ["A07"], "pci": ["8.2.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-613", "CWE-384"]}),

    # Phase 130 — Source map informational
    ("source map.*target.*unreachable|source map.*webpack.*stats",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-540", "CWE-200"]}),

    # Phase 131 — Subdomain surface
    ("subdomain surface.*active.*subdomains|subdomain surface.*no.*common",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID", "PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),

    # Phase 132 — Threat intelligence
    ("threat intelligence.*virustotal|threat intelligence.*no.*api.*keys",
     {"owasp": ["A06", "A09"], "pci": ["12.3.4", "12.10.4"], "nist": ["DE", "RS"],
      "iso": ["A.8.8", "A.5.25"], "cwe": ["CWE-1035"]}),

    # Phase 133 — URL parameter encoding bypass
    ("url parameter.*encoding.*bypass",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-116", "CWE-79"]}),

    # Phase 134 — Version CVE unreachable
    ("version cve.*target.*unreachable",
     {"owasp": ["A06"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.8"], "cwe": ["CWE-1035"]}),

    # Phase 135 — WAF/CDN
    ("waf.*cdn.*detected|waf.*cdn.*none.*detected",
     {"owasp": ["A05", "A09"], "pci": ["6.2.4"], "nist": ["PR", "DE"],
      "iso": ["A.8.20", "A.8.22"], "cwe": ["CWE-200"]}),

    # Phase 136 — Weak crypto informational
    ("weak crypto.*no.*response|weak crypto.*no.*weak.*algorithms.*detected",
     {"owasp": ["A02"], "pci": ["4.2.1", "8.3.2"], "nist": ["PR"],
      "iso": ["A.8.24"], "cwe": ["CWE-327"]}),

    # Phase 137 — WebAuthn informational
    ("webauthn.*well.known.*webauthn|webauthn.*conditional.*ui"
     "|webauthn.*not.*implemented|webauthn security.*target.*unreachable",
     {"owasp": ["A07"], "pci": ["8.4.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.5"], "cwe": ["CWE-287", "CWE-308"]}),

    # Phase 138 — WebSocket no issues
    ("websocket.*no.*issues.*detected",
     {"owasp": ["A02", "A07"], "pci": ["4.2.1"], "nist": ["PR"],
      "iso": ["A.8.24"], "cwe": ["CWE-311"]}),

    # Phase 139 — XML endpoint specifics
    ("xml endpoint.*doctype.*dtd|xml endpoint.*soap.*xml.*service.*indicators"
     "|xml endpoint.*wsdl.*soap.*service|xml endpoint.*form.*with.*xml.*mime"
     "|xml endpoint.*page.*served.*as|xml endpoint.*parser.*error",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-611", "CWE-776"]}),

    # Phase 140 — XML/XXE no endpoints
    ("xml.*xxe.*no.*xml.*endpoints|xml.*xxe.*no.*indicators|xxe injection.*no.*xml"
     "|xxe injection.*no.*indicators|xxe injection.*no.*response",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-611"]}),

    # Phase 141 — XSLeak informational
    ("xsleak.*cross.site.*leak.*mitigations|xsleak.*target.*unreachable",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200"]}),

    # Phase 142 — gRPC informational
    ("grpc.*health.*check.*accessible|grpc.*no.*grpc.*endpoints",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.22", "A.8.26"], "cwe": ["CWE-284", "CWE-200"]}),

    # Phase 143 — security.txt
    (r"security\.txt.*incomplete|security\.txt.*missing|security\.txt.*present",
     {"owasp": ["A05"], "pci": [], "nist": ["RS"],
      "iso": ["A.5.25"], "cwe": ["CWE-200"]}),

    # Phase 144 — Access control admin interface
    ("access control.*admin.*login.*page.*discoverable",
     {"owasp": ["A01", "A05"], "pci": ["7.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.26"], "cwe": ["CWE-284", "CWE-200"]}),

    # Phase 145 — Remaining gap fixes (lowercase-safe, no TEST_VALUE in patterns)
    (r"api versioning.*deprecated.*active",
     {"owasp": ["A09"], "pci": ["6.3.2"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-1059"]}),
    ("business logic.*cart.*basket|business logic.*numeric.*object.*id",
     {"owasp": ["A04", "A01"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-285", "CWE-639"]}),
    ("ci.*cd.*hardcoded.*secret|ci/cd.*hardcoded",
     {"owasp": ["A02", "A05"], "pci": ["6.3.2", "8.6.1"], "nist": ["PR"],
      "iso": ["A.8.12"], "cwe": ["CWE-798", "CWE-312"]}),
    (r"coop header missing",
     {"owasp": ["A05"], "pci": [], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-693"]}),
    ("certificate transparency",
     {"owasp": ["A02", "A05"], "pci": ["4.2.1", "6.2.4"], "nist": ["ID", "PR"],
      "iso": ["A.8.24", "A.8.9"], "cwe": ["CWE-295", "CWE-200"]}),
    (r"cookie.*__host.*prefix",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.2.1"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-614", "CWE-1275"]}),
    ("el injection.*no.*expression|el injection.*no.*indicators",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-917"]}),
    (r"exposed file\s*—",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-538", "CWE-200"]}),
    ("file upload.*server.*file.*path.*content.disposition|file upload.*path.*content.disposition",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-552", "CWE-200"]}),
    ("graphql depth.*enforced",
     {"owasp": ["A04", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.22", "A.8.26"], "cwe": ["CWE-400"]}),
    ("graphql field suggestion.*internal|graphql field suggestion.*unreachable",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-209", "CWE-200"]}),
    ("graphql.*introspection.*enabled",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-200", "CWE-284"]}),
    (r"http/2.*alt.svc",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),
    (r"header reflection\s*—",
     {"owasp": ["A03", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-116"]}),
    ("js file analysis.*dom sink",
     {"owasp": ["A03"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-79", "CWE-80"]}),
    (r"k8s.*accessible|k8s.*no.*exposed",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4", "7.2.1"], "nist": ["PR", "DE"],
      "iso": ["A.8.22", "A.8.23"], "cwe": ["CWE-284", "CWE-306"]}),
    ("oauth.*token.*url.*fragment",
     {"owasp": ["A02", "A07"], "pci": ["6.2.4", "8.3.1"], "nist": ["PR"],
      "iso": ["A.8.5", "A.8.26"], "cwe": ["CWE-598", "CWE-287"]}),
    (r"open ports\s*—",
     {"owasp": ["A05"], "pci": ["1.3.1"], "nist": ["ID", "PR"],
      "iso": ["A.8.20", "A.8.22"], "cwe": ["CWE-284"]}),
    ("password reset.*form.*get|password reset.*form.*uses.*get",
     {"owasp": ["A07", "A02"], "pci": ["6.2.4", "8.4.1"], "nist": ["PR"],
      "iso": ["A.5.15"], "cwe": ["CWE-598", "CWE-640"]}),
    ("scim.*accessible",
     {"owasp": ["A01", "A07"], "pci": ["8.2.1", "8.3.1"], "nist": ["PR"],
      "iso": ["A.5.15", "A.8.2"], "cwe": ["CWE-284", "CWE-306"]}),
    (r"ssti\s*—|ssti.*no.*template.*injection",
     {"owasp": ["A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1336", "CWE-95"]}),
    ("sensitive data exposure.*internal.*path.*header",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-209", "CWE-200"]}),
    ("server.timing.*header.*present",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR", "ID"],
      "iso": ["A.8.9", "A.8.26"], "cwe": ["CWE-200", "CWE-208"]}),
    ("service worker.*pwa.*manifest.*start_url.*http",
     {"owasp": ["A02", "A05"], "pci": ["4.2.1", "6.2.4"], "nist": ["PR"],
      "iso": ["A.8.24", "A.8.26"], "cwe": ["CWE-319"]}),
    (r"template injection\s*—",
     {"owasp": ["A03"], "pci": ["6.2.4", "6.3.3"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-1336", "CWE-95"]}),
    ("grpc.*endpoint.*found|grpc.*protocol.*headers.*detected",
     {"owasp": ["A01", "A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26", "A.8.28"], "cwe": ["CWE-284", "CWE-200"]}),
    (r"html comment\s*—",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.9"], "cwe": ["CWE-615"]}),
    (r"cms\s*—",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["ID"],
      "iso": ["A.8.9"], "cwe": ["CWE-200"]}),
    (r"security headers.*deprecated",
     {"owasp": ["A05"], "pci": ["6.2.4"], "nist": ["PR"],
      "iso": ["A.8.26"], "cwe": ["CWE-16"]}),
]


def _match_frameworks(finding_type: str) -> Dict[str, List[str]]:
    """Return deduped OWASP/PCI/NIST/ISO/CWE codes that apply to this finding type."""
    import re as _re
    needle = finding_type.lower()
    owasp, pci, nist, iso, cwe = set(), set(), set(), set(), set()
    for pattern, codes in _RULES:
        if _re.search(pattern, needle):
            owasp.update(codes.get("owasp", []))
            pci.update(codes.get("pci", []))
            nist.update(codes.get("nist", []))
            iso.update(codes.get("iso", []))
            cwe.update(codes.get("cwe", []))
    return {
        "owasp": sorted(owasp),
        "pci":   sorted(pci),
        "nist":  sorted(nist),
        "iso":   sorted(iso),
        "cwe":   sorted(cwe),
    }


def generate_report(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a compliance coverage report from all scanner results.

    Returns a dict with:
      - owasp_coverage: per-category status (PASS/FAIL/WARN/UNCHECKED)
      - pci_coverage:   per-requirement status
      - nist_coverage:  per-function status
      - findings_by_owasp: grouped findings per OWASP category
    """
    # Track worst status per framework code
    owasp_status: Dict[str, str]  = {}
    pci_status:   Dict[str, str]  = {}
    nist_status:  Dict[str, str]  = {}
    iso_status:   Dict[str, str]  = {}
    cwe_status:   Dict[str, str]  = {}
    findings_by_owasp: Dict[str, List[Dict]] = {}

    _RANK = {"FAIL": 0, "WARN": 1, "PASS": 2}

    def _worse(current: str, new: str) -> str:
        if current not in _RANK:
            return new
        return new if _RANK.get(new, 99) < _RANK[current] else current

    for result in all_results:
        ftype  = result.get("type", "")
        status = result.get("status", "")
        codes  = _match_frameworks(ftype)

        for cat in codes["owasp"]:
            owasp_status[cat] = _worse(owasp_status.get(cat, ""), status)
            findings_by_owasp.setdefault(cat, [])
            if status in ("FAIL", "WARN"):
                findings_by_owasp[cat].append({
                    "type":   ftype,
                    "status": status,
                    "url":    result.get("url", ""),
                })

        for req in codes["pci"]:
            pci_status[req] = _worse(pci_status.get(req, ""), status)

        for func in codes["nist"]:
            nist_status[func] = _worse(nist_status.get(func, ""), status)

        for ctrl in codes["iso"]:
            iso_status[ctrl] = _worse(iso_status.get(ctrl, ""), status)

        for cid in codes["cwe"]:
            cwe_status[cid] = _worse(cwe_status.get(cid, ""), status)

    # Build final output with human-readable labels
    owasp_out = {}
    for cat, label in OWASP_TOP_10.items():
        owasp_out[cat] = {
            "label":    label,
            "status":   owasp_status.get(cat, "UNCHECKED"),
            "findings": findings_by_owasp.get(cat, []),
        }

    pci_out = {}
    for req, label in PCI_DSS_4.items():
        pci_out[req] = {
            "label":  label,
            "status": pci_status.get(req, "UNCHECKED"),
        }

    nist_out = {}
    for func, label in NIST_CSF.items():
        nist_out[func] = {
            "label":  label,
            "status": nist_status.get(func, "UNCHECKED"),
        }

    iso_out = {}
    for ctrl, label in ISO_27001_2022.items():
        iso_out[ctrl] = {
            "label":  label,
            "status": iso_status.get(ctrl, "UNCHECKED"),
        }

    cwe_out = {}
    for cid, label in CWE_TOP25.items():
        cwe_out[cid] = {
            "label":  label,
            "status": cwe_status.get(cid, "UNCHECKED"),
        }

    # Summary counts
    def _counts(status_map):
        from collections import Counter
        c = Counter(v["status"] for v in status_map.values())
        return dict(c)

    return {
        "owasp_coverage": owasp_out,
        "pci_coverage":   pci_out,
        "nist_coverage":  nist_out,
        "iso_coverage":   iso_out,
        "cwe_coverage":   cwe_out,
        "summary": {
            "owasp": _counts(owasp_out),
            "pci":   _counts(pci_out),
            "nist":  _counts(nist_out),
            "iso":   _counts(iso_out),
            "cwe":   _counts(cwe_out),
        },
    }
