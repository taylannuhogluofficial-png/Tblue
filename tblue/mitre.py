"""
MITRE ATT&CK technique lookup for Tblue findings.

Maps finding type strings to Enterprise ATT&CK technique IDs so every
result carries machine-readable threat taxonomy. Lets security teams
immediately know the kill-chain stage and pivot to related detections.

Mappings target **Enterprise** ATT&CK v16 tactic names (notably
"Defense Evasion", which ATT&CK v18 later split into "Stealth" and
"Defense Impairment"). Technique IDs and names are verified against the
published catalogue by tests/test_mitre_catalogue.py; only Enterprise
techniques are used, so Mobile-only IDs such as T1430 are not valid here.

Reference: https://attack.mitre.org/techniques/enterprise/
"""

ATTACK_MATRIX  = "enterprise"
ATTACK_VERSION = "16"

import re
from typing import List, Dict

_T = lambda tid, name, tactic: {"id": tid, "name": name, "tactic": tactic,
                                  "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}

# Ordered rules — all matching rules contribute (deduped by technique ID).
# Pattern is matched case-insensitively against the lowercased finding type string.
_RULES = [
    # ── Reconnaissance ────────────────────────────────────────────────────────
    (r"version.*disclosure|technology.*disclosure|server.*header|x-powered-by|x-runtime|x-aspnet",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),

    (r"certificate.*transparency|crt\.sh|subdomain.*enum",
     _T("T1596.003", "Search Open Technical Databases: Digital Certificates", "Reconnaissance")),

    (r"port.*open|port.*expos|database.*port|redis|mongodb|elastic.*port|memcached",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    (r"dns.*advanced|caa|dnssec|ns.*diversity|dns.*security",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    (r"stack.*trace|error.*page|framework.*version|traceback|exception",
     _T("T1082", "System Information Discovery", "Discovery")),

    (r"robots.*txt|sitemap.*disallow|sensitive.*path",
     _T("T1119", "Automated Collection", "Collection")),

    (r"typosquat|lookalike.*domain|brand.*impersonat",
     _T("T1583.001", "Acquire Infrastructure: Domains", "Resource Development")),

    # ── Initial Access ────────────────────────────────────────────────────────
    (r"admin.*expos|phpymyadmin|actuator.*env|actuator.*heap|spring.*boot.*actuator"
     r"|\.env.*expos|env.*file.*expos|backup.*file|source.*map.*expos",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    (r"cms.*cve|known.*vulnerability|outdated.*lib|sca.*cve",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    (r"supply.*chain|sri.*missing|sri.*coverage|sri.*weak",
     _T("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access")),

    (r"open.*redirect|redirect.*parameter",
     _T("T1566.002", "Phishing: Spearphishing Link", "Initial Access")),

    (r"spf.*fail|dmarc.*missing|dmarc.*none|mta.*sts.*missing|email.*spoofing",
     _T("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access")),

    (r"subdomain.*takeover|dangling.*dns|cname.*unclaimed",
     _T("T1584.001", "Compromise Infrastructure: Domains", "Resource Development")),

    (r"waf.*not.*detected|no.*waf",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # ── Execution ─────────────────────────────────────────────────────────────
    (r"xss|unsafe.*inline|unsafe.*eval|reflected.*xss|dom.*xss|template.*inject",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    (r"csp.*missing|no.*content.*security.*policy",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # ── Credential Access ─────────────────────────────────────────────────────
    (r"\.env|credential.*file|html.*comment.*password|html.*comment.*credential"
     r"|html.*comment.*key|backup.*file.*credential|git.*expos",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),

    (r"aws.*key|stripe.*key|github.*token|openai.*key|private.*key|rsa.*key|api.*secret"
     r"|jwt.*secret|hardcoded.*secret|js.*secret",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),

    (r"private.*key|pem.*block|rsa.*private",
     _T("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access")),

    (r"rate.*limit.*missing|no.*rate.*limit|brute.*force",
     _T("T1110", "Brute Force", "Credential Access")),

    (r"cookie.*httponly|cookie.*secure|session.*cookie|auth.*cookie|sensitive.*cookie",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),

    (r"jwt.*alg.*none|alg.*none|weak.*jwt|hs256.*jwt",
     _T("T1134", "Access Token Manipulation", "Privilege Escalation")),

    # ── Collection ────────────────────────────────────────────────────────────
    (r"cors.*reflect|cors.*wildcard|cors.*null|cross.*origin.*misconfig",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    (r"mixed.*content|http.*resource.*https",
     _T("T1557", "Adversary-in-the-Middle", "Collection")),

    (r"hsts.*missing|no.*hsts|http.*downgrade|redirect.*chain.*http",
     _T("T1557", "Adversary-in-the-Middle", "Collection")),

    (r"cloud.*storage.*public|s3.*public|azure.*blob.*public|gcs.*public|bucket.*public",
     _T("T1530", "Data from Cloud Storage", "Collection")),

    (r"graphql.*introspection|api.*doc.*expos|swagger.*expos|openapi.*expos",
     _T("T1213", "Data from Information Repositories", "Collection")),

    (r"host.*header.*inject",
     _T("T1565", "Data Manipulation", "Impact")),

    (r"host.*header.*inject",
     _T("T1189", "Drive-by Compromise", "Initial Access")),

    (r"gdpr.*no.*consent|no.*cookie.*consent|tracking.*script.*first.*load",
     _T("T1119", "Automated Collection", "Collection")),

    # ── Impact ────────────────────────────────────────────────────────────────
    (r"permissions.*policy.*camera|permissions.*policy.*microphone",
     _T("T1125", "Video Capture", "Collection")),

    (r"permissions.*policy.*geolocation",
     _T("T1119", "Automated Collection", "Collection")),

    # ── Defense Evasion / Privilege Escalation ───────────────────────────────
    (r"http.*trace|trace.*method",
     _T("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")),

    (r"login.*get.*method|password.*get.*method",
     _T("T1040", "Network Sniffing", "Credential Access")),

    (r"info.*disclosure|internal.*ip.*header|internal.*hostname",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),

    (r"threat.*intel.*abuse|ip.*reputation|known.*malicious|abuseipdb",
     _T("T1584", "Compromise Infrastructure", "Resource Development")),

    (r"threat.*intel.*otx|alienvault|malware.*pulse",
     _T("T1584", "Compromise Infrastructure", "Resource Development")),

    # ── Phase 11 scanners ─────────────────────────────────────────────────────
    (r"api.*surface|openapi.*expos|swagger.*ui.*expos|api.*doc.*expos|routes.*no.*security",
     _T("T1213", "Data from Information Repositories", "Collection")),

    (r"directory.*listing|index.*of|parent.*directory.*expos",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    (r"ssrf|server.?side.*request.*forgery|ssrf.*param|url.*valued.*param",
     _T("T1090", "Proxy", "Command and Control")),

    (r"oauth.*implicit|oauth.*state.*missing|oauth.*client.*secret|oauth.*redirect.*uri"
     r"|oidc.*discovery|oauth.*token.*fragment",
     _T("T1550.001", "Use Alternate Authentication Material: Application Access Token", "Defense Evasion")),

    (r"cache.*poison|unkeyed.*header.*reflect|x-forwarded-host.*reflect",
     _T("T1565.002", "Data Manipulation: Transmitted Data Manipulation", "Impact")),

    (r"request.*smuggling|cl.*te|te.*cl|dual.*cl.*te|transfer.?encoding.*ambigu",
     _T("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")),

    # ── Phase 12 scanners ─────────────────────────────────────────────────────
    (r"websocket.*ws://|websocket.*unencrypt|websocket.*no.*tls|unencrypted.*websocket",
     _T("T1040", "Network Sniffing", "Credential Access")),

    (r"websocket.*wildcard.*cors|cross.?site.*websocket|websocket.*hijack",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    (r"websocket.*endpoint|websocket.*unauthenticat",
     _T("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")),

    (r"saml.*http|saml.*unencrypt|saml.*plain.*http",
     _T("T1040", "Network Sniffing", "Credential Access")),

    (r"saml.*relay.*state|open.*relay.*state|saml.*redirect",
     _T("T1601.001", "Modify System Image: Patch System Image", "Defense Evasion")),

    (r"saml.*assertion.*exposed|saml.*metadata.*exposed|saml.*endpoint.*reachable",
     _T("T1213", "Data from Information Repositories", "Collection")),

    (r"prototype.*pollution|__proto__.*assign|constructor.*prototype.*assign",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    (r"vulnerable.*library.*jquery|vulnerable.*library.*lodash|vulnerable.*library.*hoek",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    (r"unsafe.*merge.*pattern|unchecked.*key.*iteration",
     _T("T1574", "Hijack Execution Flow", "Persistence")),

    # ── Phase 16 scanners ─────────────────────────────────────────────────────
    # JWT Advanced
    (r"jwt.*alg.*none|jwt.*algorithm.*none",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"jwt.*kid.*path.*traversal|kid.*traversal",
     _T("T1055", "Process Injection", "Defense Evasion")),
    (r"jwt.*jku.*http|jwt.*external.*key|jwt.*sensitive.*payload",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"jwt.*url.*leak|jwt.*in.*url",
     _T("T1040", "Network Sniffing", "Credential Access")),
    (r"jwt.*missing.*exp|jwt.*long.*expiry",
     _T("T1550.004", "Use Alternate Authentication Material: Web Session Cookie", "Defense Evasion")),

    # CORS Advanced
    (r"cors.*origin.*reflected|cors.*arbitrary.*origin|cors.*credentials.*origin",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"cors.*null.*origin|cors.*subdomain.*bypass|cors.*http.*origin",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"cors.*vary.*missing|cors.*cache",
     _T("T1557", "Adversary-in-the-Middle", "Collection")),

    # HTTP/2 security
    (r"http/2.*vulnerable|cve-2023-44487|rapid.*reset|h2c.*cleartext",
     _T("T1499", "Endpoint Denial of Service", "Impact")),
    (r"alt-svc.*protocol|http2.*rate.*limit",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # GraphQL advanced
    (r"graphql.*ide.*exposed|graphiql.*exposed|graphql.*playground",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"graphql.*introspection|graphql.*schema.*exposed",
     _T("T1213", "Data from Information Repositories", "Collection")),
    (r"graphql.*batching|graphql.*stack.*trace",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # ── Phase 18 scanners ─────────────────────────────────────────────────────
    # API Security Headers
    (r"api.*security.*stack.*trace|api.*db.*error|api.*database.*error",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"api.*security.*cache|api.*security.*content.type|api.*security.*xcto",
     _T("T1040", "Network Sniffing", "Credential Access")),
    (r"api.*security.*deprecated|deprecated.*api.*version",
     _T("T1203", "Exploitation for Client Execution", "Execution")),

    # Rate limiting
    (r"rate.*limit.*missing|rate.*limit.*sensitive|no.*rate.*limit",
     _T("T1110", "Brute Force", "Credential Access")),
    (r"rate.*limit.*header|retry.*after.*present",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # SSRF Advanced
    (r"ssrf.*url.*accepting|ssrf.*form.*param|ssrf.*query.*param",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"ssrf.*import.*webhook|ssrf.*webhook.*endpoint|ssrf.*xml.*xxe",
     _T("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")),
    (r"ssrf.*private.*ip|private.*ip.*response",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # GraphQL depth limiting
    (r"graphql.*depth.*deep.*query|graphql.*no.*limit|graphql.*alias.*amplif",
     _T("T1499", "Endpoint Denial of Service", "Impact")),
    (r"graphql.*depth.*enforced",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # Business logic
    (r"business.*logic.*price|client.*submitted.*price|hidden.*price.*field",
     _T("T1565", "Data Manipulation", "Impact")),
    (r"business.*logic.*idor|idor.*sequential|numeric.*object.*id",
     _T("T1530", "Data from Cloud Storage", "Collection")),
    (r"business.*logic.*privilege|privilege.*escalation.*param|role.*field",
     _T("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")),
    (r"cart.*basket.*endpoint|quantity.*no.*min|negative.*quantity",
     _T("T1565", "Data Manipulation", "Impact")),

    # OAuth Advanced
    (r"oauth.*advanced.*pkce|authorization.*code.*without.*pkce|pkce.*plain",
     _T("T1528", "Steal Application Access Token", "Credential Access")),
    (r"oauth.*advanced.*scope|over.privileged.*scope|scope.*admin|scope.*all",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"oauth.*advanced.*nonce|oidc.*missing.*nonce",
     _T("T1550.001", "Use Alternate Authentication Material: Application Access Token", "Defense Evasion")),
    (r"oauth.*advanced.*device.*flow|device.*authorization.*endpoint",
     _T("T1078.004", "Valid Accounts: Cloud Accounts", "Persistence")),
    (r"oauth.*advanced.*dynamic.*client|dynamic.*client.*registration",
     _T("T1078", "Valid Accounts", "Persistence")),

    # CRLF Injection
    (r"crlf.*injection|response.*splitting|header.*injection",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"crlf.*redirect.*param|crlf.*marker.*body",
     _T("T1566.002", "Phishing: Spearphishing Link", "Initial Access")),

    # Mass Assignment
    (r"mass.*assignment.*privileged.*field.*accepted|mass.*assignment.*fail",
     _T("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")),
    (r"mass.*assignment.*field.*form|mass.*assignment.*priv.*field.*form",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"mass.*assignment.*422|mass.*assignment.*parsed",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Log Injection
    (r"log.*injection.*user.agent|log.*injection.*xff|log.*forging|header.*reflected",
     _T("T1027", "Obfuscated Files or Information", "Defense Evasion")),
    (r"log.*injection.*crlf|crlf.*log|crlf.*header.*inject",
     _T("T1565.001", "Data Manipulation: Stored Data Manipulation", "Impact")),
    (r"log.*injection.*log4shell|jndi.*pattern",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # File Inclusion
    (r"file.*inclusion.*passwd|lfi.*confirmed|file.*inclusion.*win.ini",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"file.*inclusion.*php.*filter|file.*inclusion.*php.*include.*error",
     _T("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution")),

    # Content Injection
    (r"content.*injection.*unescaped.*html|html.*injection.*parameter",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"content.*injection.*css.*injection|css.*injection.*parameter",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # API Authentication Security
    (r"api.*auth.*basic.*http|basic.*auth.*non.https|http.*basic.*auth",
     _T("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access")),
    (r"api.*auth.*api.*key.*url|api.*key.*query.*string",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"api.*auth.*accessible.*without.*auth|sensitive.*endpoint.*no.*auth",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"api.*auth.*401.*www-authenticate|401.*missing.*www-authenticate",
     _T("T1110", "Brute Force", "Credential Access")),

    # IDOR
    (r"idor.*parameter|idor.*adjacent.*resource|idor.*api.*resource",
     _T("T1078", "Valid Accounts", "Privilege Escalation")),
    (r"idor.*broken.*object|bola.*broken.*object",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Sensitive Data Exposure
    (r"sensitive.*data.*credential.*url|sensitive.*data.*password.*url",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"sensitive.*data.*session.*url|session.*token.*url",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"sensitive.*data.*html.*comment|token.*html.*comment",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"sensitive.*data.*pii.*url|pii.*url",
     _T("T1213", "Data from Information Repositories", "Collection")),

    # HTTP Verb Tampering
    (r"http.*verb.*tampering.*trace|trace.*method.*enabled",
     _T("T1565.002", "Data Manipulation: Transmitted Data Manipulation", "Impact")),
    (r"http.*verb.*tampering.*override.*accepted|method.*override.*delete|_method.*delete",
     _T("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")),
    (r"http.*verb.*tampering.*debug.*method|debug.*method.*enabled",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # Service Worker Security
    (r"service.*worker.*root.*scope|service.*worker.*scope.*intercepts",
     _T("T1557", "Adversary-in-the-Middle", "Collection")),
    (r"service.*worker.*fetch.*cache|service.*worker.*update.*mechanism",
     _T("T1565.001", "Data Manipulation: Stored Data Manipulation", "Impact")),
    (r"pwa.*manifest.*http.*start_url|manifest.*insecure.*http",
     _T("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning", "Collection")),

    # XXE Injection
    (r"xxe.*injection.*passwd.*disclosed|xxe.*injection.*win.ini|xxe.*file.*disclosed",
     _T("T1005", "Data from Local System", "Collection")),
    (r"xxe.*injection.*xml.*parser.*error|xxe.*dtd.*processing",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # SSRF
    (r"ssrf.*cloud.*metadata|ssrf.*metadata.*endpoint",
     _T("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access")),
    (r"ssrf.*private.*ip|ssrf.*internal.*ip|ssrf.*connection.*error",
     _T("T1090.003", "Proxy: Multi-hop Proxy", "Command and Control")),

    # LDAP Injection
    (r"ldap.*injection.*bypass|ldap.*injection.*authentication.*bypass",
     _T("T1110.001", "Brute Force: Password Guessing", "Credential Access")),
    (r"ldap.*injection.*error.*message.*leaked|ldap.*error.*baseline",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),
    (r"ldap.*injection.*metacharacter|ldap.*error.*triggered",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Command Injection
    (r"command.*injection.*uid.*gid|command.*injection.*os.*command.*output",
     _T("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution")),
    (r"command.*injection.*shell.*error|command.*injection.*timing.*delay",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Dependency Confusion
    (r"dependency.*confusion.*internal.*package|internal.*package.*manifest|"
     r"dependency.*confusion.*fail",
     _T("T1195.001", "Supply Chain Compromise: Compromise Software Dependencies", "Initial Access")),
    (r"dependency.*confusion.*manifest.*exposed|npm.*manifest|pypi.*manifest|gemfile.*exposed",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # OpenAPI / Swagger exposure
    (r"openapi.*swagger.*ui.*exposed|openapi.*documentation.*ui|redoc.*exposed",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"openapi.*spec.*exposed|openapi.*machine.readable",
     _T("T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance")),
    (r"openapi.*internal.*server|openapi.*staging.*url",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),
    (r"openapi.*secret.*spec|openapi.*api.key.*example",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),

    # Clickjacking
    (r"clickjacking.*no framing|clickjacking.*sensitive.*page|clickjacking.*no.*protection",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"clickjacking.*js.*frame.bust|clickjacking.*allow.from",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Account Enumeration
    (r"account.*enumeration.*status.*code|account.*enumeration.*user.*not.*found",
     _T("T1589.001", "Gather Victim Identity Information: Credentials", "Reconnaissance")),
    (r"account.*enumeration.*success.*message|account.*enumeration.*size",
     _T("T1589.002", "Gather Victim Identity Information: Email Addresses", "Reconnaissance")),

    # HTTP Parameter Pollution
    (r"http.*parameter.*pollution|hpp.*last.*duplicate|hpp.*both.*value|hpp.*array.*notation",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"hpp.*encoded.*%26|encoded.*ampersand.*duplicate",
     _T("T1027", "Obfuscated Files or Information", "Defense Evasion")),

    # Weak Cryptography
    (r"weak.*crypto.*md5.*etag|content.md5|md5.*length.*token|md5.*cookie",
     _T("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access")),
    (r"weak.*crypto.*digest.*md5|http.*digest.*md5",
     _T("T1557", "Adversary-in-the-Middle", "Credential Access")),
    (r"weak.*crypto.*rc4|weak.*cipher|low.entropy.*session",
     _T("T1040", "Network Sniffing", "Credential Access")),

    # CSP bypass vectors
    (r"csp.*advanced.*unsafe.inline|csp.*unsafe.inline",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"csp.*advanced.*wildcard|csp.*wildcard.*script.src",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"csp.*advanced.*data.*uri|csp.*data.*script.src",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"csp.*advanced.*jsonp.*bypass|csp.*bypass.*host",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # ── Phase 15 scanners ─────────────────────────────────────────────────────
    # K8s exposure
    (r"k8s.*namespace.*exposed|kubernetes.*api.*exposed|k8s.*api.*anonymous",
     _T("T1613", "Container and Resource Discovery", "Discovery")),
    (r"kubernetes.*secret|k8s.*secret.*list",
     _T("T1552.007", "Unsecured Credentials: Container API", "Credential Access")),
    (r"kubernetes.*dashboard.*exposed|k8s.*dashboard",
     _T("T1059.006", "Command and Scripting Interpreter: Python", "Execution")),
    (r"k8s.*metrics|kubernetes.*metrics|k8s.*healthz",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # SCIM
    (r"scim.*exposed.*without.*auth|scim.*unauthenticated|identity.*management.*endpoint",
     _T("T1087.004", "Account Discovery: Cloud Account", "Discovery")),
    (r"scim.*accessible|scim.*endpoint.*found",
     _T("T1078.004", "Valid Accounts: Cloud Accounts", "Defense Evasion")),

    # gRPC
    (r"grpc.*reflection.*exposed|grpc.*reflection.*api",
     _T("T1046", "Network Service Discovery", "Discovery")),
    (r"grpc.*endpoint.*found|grpc.*content.*type|grpc.*protocol.*headers",
     _T("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")),

    # Cloud metadata
    (r"cloud.*metadata.*endpoint.*reference|metadata.*ssrf|ssrf.*imds|imds.*exposed",
     _T("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access")),
    (r"kubernetes.*service.*account.*token.*exposed|k8s.*token",
     _T("T1552.007", "Unsecured Credentials: Container API", "Credential Access")),

    # NoSQL injection
    (r"nosql.*injection|mongodb.*error.*exposed|mongodb.*operator.*in.*url|couchdb.*admin",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"nosql.*error.*message|database.*error.*exposed",
     _T("T1082", "System Information Discovery", "Discovery")),

    # Web cache deception
    (r"web.*cache.*deception|cache.*hit.*sensitive|cacheable.*authenticated|dynamic.*content.*cached",
     _T("T1557", "Adversary-in-the-Middle", "Collection")),
    (r"session.*cookie.*without.*cache.control|cache.*deception",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),

    # Session security
    (r"session.*id.*in.*url|session.*identifier.*url|jsessionid.*url|phpsessid.*url",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"weak.*session.*token|predictable.*session.*id|session.*entropy",
     _T("T1110.003", "Brute Force: Password Spraying", "Credential Access")),
    (r"session.*fixation|remember.me.*without.*expiry|multiple.*session.*cookies",
     _T("T1550.004", "Use Alternate Authentication Material: Web Session Cookie", "Defense Evasion")),
    (r"login.*form.*get.*method|session.*management.*no.*logout",
     _T("T1078", "Valid Accounts", "Defense Evasion")),

    # CI/CD pipeline exposure
    (r"cicd.*exposure|ci.*cd.*config.*expos|pipeline.*config.*accessible|github.*workflow.*expos",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"jenkinsfile.*expos|travis.*yml.*expos|gitlab.*ci.*expos|circleci.*expos",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"dockerfile.*expos|docker.compose.*expos|build.*artifact.*expos",
     _T("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access")),
    (r"hardcoded.*secret.*ci|cicd.*secret.*expos|pipeline.*token.*expos",
     _T("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access")),
    (r"package\.json.*expos|requirements\.txt.*expos|composer\.json.*expos",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # EL injection (SpEL, OGNL, Thymeleaf)
    (r"spring4shell|cve.2022.22965|spel.*evaluation.*error|spring.*expression.*error",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"ognl.*evaluation.*error|struts.*ognl|cve.2017.5638|cve.2023.50164",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"thymeleaf.*injection|thymeleaf.*expression|cve.2023.38286",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"el.*injection.*expression|unprocessed.*el.*expression|jsp.*el.*artifact",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"struts.*debug.*console|struts.*webconsole|ognl.*rce",
     _T("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution")),
    (r"struts.*action.*extension|\.action.*ognl|\.do.*ognl",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"spring.*whitelabel.*error|spring.*boot.*error.*page",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # JSON injection
    (r"jsonp.*callback.*not.*validated|jsonp.*injection|jsonp.*reflected",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"json.*injection.*parameter|json.*key.*injected|json.*string.*concat",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"__proto__.*pollution|prototype.*pollution.*json|constructor.*json",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"json.*unescaped.*html|html.*tags.*json.*response",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"json.*content.type.*missing|json.*x.content.type",
     _T("T1203", "Exploitation for Client Execution", "Execution")),

    # Race condition / TOCTOU
    (r"race.*condition|toctou|double.spend|concurrent.*token|idempotency.*missing",
     _T("T1499.004", "Endpoint Denial of Service: Application or System Exploitation", "Impact")),
    (r"token.*redemption.*no.*idempotency|coupon.*race|gift.card.*race",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"rate.*limit.*bypass.*concurrent|concurrent.*bypass.*rate",
     _T("T1498", "Network Denial of Service", "Impact")),
    (r"high.risk.*endpoint.*lacks.*idempotency|toctou.*vulnerable",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Password reset security
    (r"password.*reset.*host.*header|host.*header.*injection.*reset|reset.*link.*poisoned",
     _T("T1556", "Modify Authentication Process", "Credential Access")),
    (r"password.*reset.*csrf|no.*csrf.*reset|reset.*form.*csrf",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"reset.*token.*url|token.*query.*string.*reset|reset.*token.*exposed",
     _T("T1552.003", "Unsecured Credentials: Bash History", "Credential Access")),
    (r"user.*enumeration.*reset|reset.*reveals.*email|different.*error.*reset",
     _T("T1589.002", "Gather Victim Identity Information: Email Addresses", "Reconnaissance")),
    (r"weak.*reset.*token|short.*reset.*token|low.*entropy.*token",
     _T("T1110.003", "Brute Force: Password Spraying", "Credential Access")),
    (r"reset.*form.*get.*method|email.*exposed.*url.*reset",
     _T("T1552.003", "Unsecured Credentials: Bash History", "Credential Access")),

    # API version security
    (r"api.*version.*auth.*bypass|v\d+.*returns.*data.*where.*requires.*auth|deprecated.*api.*auth",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"deprecated.*api.*version.*active|old.*api.*version.*accessible|api.*v\d+.*sunset",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"api.*version.*enumeration.*hint|version.*enumeration.*response",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),
    (r"unversioned.*api.*endpoint|shadow.*api|api.*inventory",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"sunset.*header|deprecation.*header|api.*deprecated",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # WebAuthn / FIDO2
    (r"webauthn.*rpid.*wildcard|relying.*party.*id.*wildcard",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"sms.*otp.*fallback|sms.*bypass.*webauthn|sim.*swap.*auth",
     _T("T1111", "Multi-Factor Authentication Interception", "Credential Access")),
    (r"webauthn.*conditional.*ui.*missing|passkey.*autocomplete.*missing",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"http.*magic.*link|plaintext.*auth.*link|magic.*link.*http",
     _T("T1557", "Adversary-in-the-Middle", "Collection")),
    (r"well.*known.*webauthn.*unexpected|webauthn.*discovery.*misconfigured",
     _T("T1556", "Modify Authentication Process", "Credential Access")),

    # Client-side storage security
    (r"password.*written.*localStorage|secret.*localStorage|credential.*sessionStorage",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"jwt.*token.*localStorage|auth.*token.*localStorage|bearer.*sessionStorage",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"pii.*payment.*localStorage|credit.*card.*storage|ssn.*sessionStorage",
     _T("T1005", "Data from Local System", "Collection")),
    (r"auth.*read.*localStorage.*decision|getItem.*token.*auth.*decision",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"indexedDB.*sensitive|indexed.*db.*credentials|indexed.*db.*passwords",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"sensitive.*key.*localStorage|sensitive.*key.*sessionStorage",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"websql.*deprecated|openDatabase.*usage|web.*sql.*database",
     _T("T1005", "Data from Local System", "Collection")),

    # Client-Side Template Injection (CSTI)
    (r"angularjs.*sandbox.*escape|angularjs.*csti|ng-app.*sandbox",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"ng.bind.html.*without.*sanitize|ng-bind-html.*ngSanitize",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"angular.*eval.*parse.*expression|angularjs.*eval.*user",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"vue.*v.html.*unescaped|vue.*html.*directive",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"react.*dangerously.*setInnerHTML|react.*dangerous.*inner.*html",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"handlebars.*triple.*stache|handlebars.*unescaped.*html",
     _T("T1203", "Exploitation for Client Execution", "Execution")),
    (r"underscore.*template.*unsafe|lodash.*template.*interpolation",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"angular.*bypass.*security.*trust|bypassSecurityTrust",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"nunjucks.*renderString.*user|nunjucks.*template.*injection",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"csti.*unsafe.*template|client.side.*template.*injection",
     _T("T1203", "Exploitation for Client Execution", "Execution")),

    # Fetch Metadata policy
    (r"missing.*cross.origin.opener.policy|coop.*header.*absent|cross.origin.*opener",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"missing.*cross.origin.embedder.policy|coep.*header.*absent|cross.origin.*embedder",
     _T("T1203", "Exploitation for Client Execution", "Execution")),
    (r"missing.*cross.origin.resource.policy|corp.*header.*absent|cross-site.*without.*corp",
     _T("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "Collection")),
    (r"api.*endpoint.*cross.site.*corp|cross.site.*request.*no.*policy|fetch.*metadata.*policy",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"form.*action.*corp|form.*endpoint.*cross.site",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"unusual.*coop.*value|non.standard.*cross.origin.opener",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # Path confusion / URL normalization bypass
    (r"spring.*actuator.*bypass|actuator.*path.*confusion|spring.*boot.*path.*bypass",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"path.*confusion.*access.*control|url.*normalization.*bypass|path.*bypass.*admin",
     _T("T1078", "Valid Accounts", "Defense Evasion")),
    (r"double.slash.*bypass|nginx.*double.slash|//admin.*bypass",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"semicolon.*bypass|\.\.;.*bypass|spring.*mvc.*semicolon|trailing.*semicolon",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"double.*encoded.*slash|%252F.*bypass|url.*double.*encoding.*bypass",
     _T("T1027.001", "Obfuscated Files or Information: Binary Padding", "Defense Evasion")),
    (r"null.*byte.*truncation|%00.*bypass|null.*byte.*injection.*path",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"trailing.*dot.*bypass|path.*dot.*normalization|ims.*dot.*bypass",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # CSV / Formula Injection
    (r"dde.*formula.*csv|dde.*command.*csv|csv.*dde.*injection",
     _T("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution")),
    (r"unescaped.*formula.*csv|formula.*injection.*csv|csv.*injection.*formula",
     _T("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution")),
    (r"hyperlink.*csv.*exfil|csv.*exfiltration.*formula",
     _T("T1041", "Exfiltration Over C2 Channel", "Exfiltration")),
    (r"csv.*missing.*content.disposition|csv.*without.*attachment",
     _T("T1203", "Exploitation for Client Execution", "Execution")),
    (r"csv.*nosniff.*missing|csv.*content.type.*options",
     _T("T1203", "Exploitation for Client Execution", "Execution")),
    (r"export.*endpoint.*formula|download.*csv.*formula|spreadsheet.*injection",
     _T("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution")),

    # Reflected File Download (RFD)
    (r"rfd.*user.controlled.*executable.*filename|reflected.*file.*download.*bat|user.controlled.*bat.*filename",
     _T("T1204.002", "User Execution: Malicious File", "Execution")),
    (r"reflected.*file.*download|rfd.*executable.*filename|rfd.*probe.*reflected",
     _T("T1204.002", "User Execution: Malicious File", "Execution")),
    (r"jsonp.*callback.*attachment.*rfd|jsonp.*reflected.*attachment",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"script.*content.*prefix.*attachment|script.like.*content.*download",
     _T("T1204.002", "User Execution: Malicious File", "Execution")),
    (r"rfd.*filename.*disposition|user.controlled.*filename.*disposition",
     _T("T1566.002", "Phishing: Spearphishing Link", "Initial Access")),

    # Source Map Exposure
    (r"source.*map.*source.*content|javascript.*source.*map.*exposed|sourcecontent.*exposed",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"source.*map.*publicly.*accessible|\.map.*file.*exposed|sourcemap.*exposed",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),
    (r"webpack.*stats.*json|stats\.json.*exposed|webpack.*chunks.*exposed",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"internal.*path.*source.*root|sourcemap.*path.*disclosure|sourceRoot.*server.*path",
     _T("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance")),

    # Framework Config and Log File Exposure (Phase 44)
    (r"laravel.*log.*exposed|storage.*logs.*accessible|application.*log.*exposed|catalina.*out.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"log.*file.*stack.*trace|error\.log.*accessible|debug\.log.*exposed",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"log.*auth.*token|session.*id.*log|token.*log.*entry",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"spring.*boot.*application\.properties|application\.yml.*exposed|datasource\.password.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"appsettings.*json.*exposed|connectionstring.*exposed|asp\.net.*config.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"rails.*database\.yml.*exposed|rails.*secrets\.yml.*exposed|rails.*master\.key.*exposed",
     _T("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access")),
    (r"django.*settings.*exposed|django.*secret_key.*exposed|local_settings.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"web\.config.*connectionstring|web\.config.*password.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"hibernate.*cfg.*xml.*exposed|persistence\.xml.*exposed|jdbc.*password.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"framework.*config.*no.*exposed|no.*configuration.*file.*exposed",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # API Collection Exposure (Phase 43)
    (r"postman.*collection.*exposed|postman_collection.*accessible|postman.*api.*collection",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"insomnia.*workspace.*exposed|insomnia.*collection.*accessible",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"hoppscotch.*collection.*exposed|api.*client.*collection.*accessible",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"bearer.*token.*authorization.*header.*collection|api.*key.*request.*header.*collection",
     _T("T1528", "Steal Application Access Token", "Credential Access")),
    (r"hardcoded.*credential.*collection|credential.*postman|credential.*insomnia",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"api.*collection.*endpoint.*structure|api.*collection.*request.*parameter",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    # Link Security — Tabnabbing / Opener Hijacking (Phase 42)
    (r"target.*blank.*missing.*rel.*noopener|noopener.*missing.*target.*blank|reverse.*tabnabbing",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"opener.*hijacking|window\.opener.*redirect|tabnabbing.*link",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"external.*iframe.*without.*sandbox|iframe.*sandbox.*missing|unsandboxed.*iframe",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"window\.open.*noopener.*missing|window.*open.*blank.*without.*noopener",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"dns.prefetch.*tracking|preconnect.*tracking.*domain|tracking.*prefetch",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),

    # Developer Artifact Exposure (Phase 41)
    (r"har.*file.*exposed|browser.*har.*session|network.*har.*file|har.*cookie.*data",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"terraform.*state.*file|terraform.*tfstate|terraform.*infrastructure.*inventory",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"terraform.*state.*password|terraform.*state.*secret|terraform.*state.*resources",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"\.npmrc.*auth.*token|npmrc.*npm.*auth|yarnrc.*auth.*config",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"ssh.*private.*key.*exposed|id_rsa.*accessible|id_ed25519.*accessible|server\.key.*accessible",
     _T("T1552.004", "Unsecured Credentials: Private Keys", "Credential Access")),
    (r"docker.*config.*registry.*auth|docker.*auth.*token.*exposed|docker.*config\.json",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"aws.*credentials.*exposed|aws.*access.*key.*id.*detected|aws_secret_access_key",
     _T("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access")),
    (r"kubeconfig.*exposed|kubernetes.*kubeconfig|kube.*config.*cluster.*token",
     _T("T1552.007", "Unsecured Credentials: Container API", "Credential Access")),
    (r"package.lock.*git.*token|package.lock.*embedded.*credential",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"composer.*auth.*json|composer.*oauth.*token|composer.*github.*oauth",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"developer.*artifact.*exposed|sensitive.*developer.*file|dev.*config.*accessible",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 45 — XSSI (Cross-Site Script Inclusion)
    (r"xssi.*json.*array.*anti.xssi|json.*array.*missing.*anti.xssi|json.*array.*without.*prefix",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"xssi.*nosniff.*missing|json.*response.*missing.*nosniff|mime.*sniff.*json",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"xssi.*content.type.*missing|json.*missing.*application.json|mime.type.*json.*wrong",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"no.*xssi.*vulnerabilities|xssi.*pass",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 49 — GraphQL Field Suggestion & Schema Enumeration via Errors
    (r"graphql.*field.*suggestion.*schema.*enumerable|did you mean.*graphql|graphql.*suggestion",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"graphql.*type.*name.*error|internal.*type.*name.*graphql|graphql.*schema.*enumerat",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"graphql.*stack.*trace.*error|graphql.*file.*path.*error",
     _T("T1082", "System Information Discovery", "Discovery")),
    (r"no.*graphql.*schema.*enumeration|graphql.*field.*suggestion.*pass",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    # Phase 48 — AI/LLM API Endpoint Exposure
    (r"ollama.*model.*list|ai.*api.*ollama|ollama.*accessible",
     _T("T1087.004", "Account Discovery: Cloud Account", "Discovery")),
    (r"openai.*compatible.*model|llm.*model.*list.*accessible|ai.*model.*without.*auth",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"hf.*tgi.*info|hugging.*face.*inference.*exposed|vllm.*config.*exposed",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"flowise.*chatflow|flowise.*api.*key|langflow.*flow.*exposed",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),
    (r"ai.*api.*exposure.*accessible|llm.*inference.*endpoint.*exposed",
     _T("T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood", "Impact")),
    (r"no.*exposed.*ai.*llm|ai.*api.*pass",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 47 — Cross-Domain Policy & Mobile App Link Security
    (r"crossdomain.*xml.*allows.*all.*origins|allow.access.from.*domain.*wildcard",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"clientaccesspolicy.*allows.*all|clientaccess.*wildcard|silverlight.*cross.domain",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"apple.app.site.*discloses.*ios|aasa.*app.*identif|apple.app.site.*present",
     _T("T1592.001", "Gather Victim Host Information: Hardware", "Reconnaissance")),
    (r"assetlinks.*missing.*sha.*256|assetlinks.*without.*fingerprint|android.*app.*link.*missing",
     _T("T1036.004", "Masquerading: Masquerade Task or Service", "Defense Evasion")),
    (r"assetlinks.*discloses.*android|assetlinks.*package.*name",
     _T("T1592.004", "Gather Victim Host Information: Client Configurations", "Reconnaissance")),
    (r"no.*permissive.*cross.domain|cross.domain.*pass",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 46 — Server-Timing Information Disclosure
    (r"server.timing.*internal.*ip|server.timing.*ip.*address|internal.*ip.*server.timing",
     _T("T1590.005", "Gather Victim Network Information: IP Addresses", "Reconnaissance")),
    (r"server.timing.*sensitive.*information|server.timing.*service.*name|server.timing.*internal.*service",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"server.timing.*datacenter|server.timing.*region|datacenter.*server.timing",
     _T("T1590.004", "Gather Victim Network Information: Network Topology", "Reconnaissance")),
    (r"server.timing.*auth.*timing|auth.*metric.*server.timing|timing.*side.channel",
     _T("T1110.001", "Brute Force: Password Guessing", "Credential Access")),
    (r"no.*sensitive.*server.timing|server.timing.*pass",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    # Phase 50 — JS File Analysis (DOM XSS Sinks)
    (r"js file.*eval|dom sink.*eval|js.*new function",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"js file.*inner.*html|js file.*document\.write|js file.*insert.*adjacent|dom sink",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"js file.*prototype.*pollution|prototype pollution.*js file",
     _T("T1211", "Exploitation for Defense Evasion", "Defense Evasion")),
    (r"js file.*postmessage.*origin|postmessage.*without.*origin",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"js file.*document\.domain|document\.domain.*relaxation",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"js file.*fetch.*credentials|credential.*fetch.*cross.origin",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"js file.*no.*dangerous|no.*dom sink|js.*pass",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 51 — Version CVE Correlation
    (r"version cve.*critical|version cve.*high|known.*cve|vulnerable.*component",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"version.*banner.*exposed|software.*version.*exposed|server.*version.*banner",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),
    (r"version cve.*pass|no.*version.*banner",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),

    # Phase 53 — LLM Prompt Injection Surface
    (r"llm.*prompt.*injection|prompt injection.*accessible|chat.*widget.*detected|llm.*api.*endpoint",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"llm.*error.*leaks|llm.*configuration.*leak|system.*prompt.*leak",
     _T("T1552", "Unsecured Credentials", "Credential Access")),
    (r"llm.*endpoint.*auth.*error|auth.*error.*llm|chat.*endpoint.*unauthenticated",
     _T("T1078", "Valid Accounts", "Initial Access")),
    (r"no.*llm.*endpoint|llm.*pass",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 54 — XSLeak (Cross-Site Leak)
    (r"xsleak.*coop.*missing|cross.origin.opener.*missing|coop.*missing",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"xsleak.*coep.*missing|cross.origin.embedder.*missing",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"xsleak.*corp.*missing|cross.origin.resource.*missing",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"xsleak.*framing|framing.*protection.*missing|frame.ancestors.*missing",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"timing.allow.origin.*\*|xsleak.*timing",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),
    (r"xsleak.*vary.*cookie|authenticated.*vary.*cookie",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"xsleak.*pass|cross.site.*isolation.*in.place",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 55 — Crawler / Informational meta-findings
    (r"crawled pages",
     _T("T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance")),
    (r"^http://",
     _T("T1584.001", "Compromise Infrastructure: Domains", "Resource Development")),
    (r"^https://",
     _T("T1590.006", "Gather Victim Network Information: Network Security Appliances", "Reconnaissance")),

    # Phase 56 — Login page security
    (r"login.*csrf|login.*cache.*control|login.*form.*method|login.*form.*get|login.*page.*http"
     r"|login.*subresource.*integrity|login.*sri",
     _T("T1078", "Valid Accounts", "Initial Access")),
    (r"login.*https|login.*mfa|login.*account.*lockout|login.*rate.*limit"
     r"|login.*username.*enumeration|login.*remember.*me",
     _T("T1110", "Brute Force", "Credential Access")),
    (r"login.*password.*autocomplete|login.*password.*maxlength|login.*password.*field"
     r"|login.*password.*type",
     _T("T1110.001", "Brute Force: Password Guessing", "Credential Access")),

    # Phase 57 — Email infrastructure security
    (r"email security.*dkim|email security.*spf|email security.*dmarc"
     r"|email.*bimi|email.*dane|email.*mta.sts|email.*tls.rpt",
     _T("T1566", "Phishing", "Initial Access")),
    (r"email.*dmarc.*fully.*enforced|email.*dmarc.*p.quarantine|email.*dmarc.*partial"
     r"|email.*dmarc.*subdomain|email.*spf.*allows.*all|email.*spf.*approaching"
     r"|email.*spf.*exceeded|email.*spf.*neutral|email.*spf.*strict",
     _T("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access")),

    # Phase 58 — TLS deep / SSL certificate findings
    (r"tls.*hsts.*not.*preload|tls.*hsts.*preload.*ready|tls.*md5.*cert|tls.*sha.1.*cert"
     r"|tls.*cert.*expired|tls.*cert.*expiring|tls.*cert.*expiry|tls.*cert.*signature"
     r"|tls.*forward.*secrecy|tls.*key.*size|tls.*weak.*ec|tls.*no.*forward",
     _T("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access")),
    (r"ssl.*https|ssl.*sans.*coverage|ssl.*sans.*mismatch|ssl.*tls.*version"
     r"|ssl.*cert.*authority|ssl.*cert.*chain|ssl.*cert.*expiry|ssl.*no.*sans|ssl.*self.signed",
     _T("T1557", "Adversary-in-the-Middle", "Credential Access")),

    # Phase 59 — Cookie attribute variants
    (r"cookie.*samesite.*missing|cookie.*samesite.lax|cookie.*samesite.none"
     r"|cookie.*samesite.strict|cookie.*host.*prefix.*violation|cookie.*missing.*partitioned"
     r"|cookie.*missing.*security.*prefix|cookie.*wildcard.*domain|cookie.*low.*entropy"
     r"|cookie.*long.*expiry|cookie.*expiry|cookie.*overly.*broad.*domain"
     r"|cookie flags.*duplicate",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"cookie advanced.*all.*cookies.*pass|cookie advanced.*no.*cookies.*set",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),

    # Phase 60 — CSP and CSP advanced findings
    (r"csp.*base.uri|csp.*form.action|csp.*frame.ancestors|csp.*nonce.*quality"
     r"|csp.*object.src|csp.*bypass.*source|csp.*static.*nonce|csp.*weak.*nonce"
     r"|csp.*violation.*reporting|csp.*no.*violation|csp.*cors.*cookie|csp.*deprecated"
     r"|csp.*duplicate",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"csp advanced.*report.only|csp advanced.*base.uri|csp advanced.*meta.*tag"
     r"|csp advanced.*form.action|csp advanced.*frame.ancestors|csp advanced.*upgrade.insecure"
     r"|csp advanced.*violation.*reporting|csp advanced.*trusted.*types",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"csp.*delivered.*meta.*tag|csp.*frame.ancestors.*wildcard|csp.*dangerous.*value"
     r"|csp.*potential.*bypass",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 61 — Deserialization indicators
    (r"deserialization.*asp.net.*viewstate|deserialization.*java.*serial"
     r"|deserialization.*java.*object.*cookie|deserialization.*java.*object.*response"
     r"|deserialization.*php.*serial.*cookie|deserialization.*php.*serial.*form"
     r"|deserialization.*python.*pickle|deserialization.*node.serialize"
     r"|deserialization.*no.*insecure",
     _T("T1059", "Command and Scripting Interpreter", "Execution")),

    # Phase 62 — Form security (CSRF, change-password, password managers, caching)
    (r"form.*well.known.*change.password|form.*csrf.*missing|form.*csrf.*present"
     r"|form.*password.*manager|form.*sensitive.*cach",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 63 — Permissions-Policy header
    (r"permissions.policy.*missing|permissions.policy.*allowed.*all|permissions.policy.*blocked"
     r"|permissions.policy.*not.*restricted|permissions.policy.*partially.*restricted"
     r"|permissions.policy.*restricted.*self|permissions.policy.*configured"
     r"|permissions.policy.*header.*absent|permissions.policy.*deprecated|feature.policy",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 64 — File upload security
    (r"file upload.*http.*put.*enabled|file upload.*put.*method|file upload.*dangerous.*mime"
     r"|file upload.*no.*csrf|file upload.*no.*content.type|file upload.*no.*upload.*forms"
     r"|file upload.*server.side.*path.*disclosed|file upload.*wildcard.*accept",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Phase 65 — GDPR and privacy
    (r"gdpr.*cookie.*consent|gdpr.*cookies.*before.*consent|gdpr.*no.*privacy.*policy"
     r"|gdpr.*no.*tracking|gdpr.*privacy.*policy.*present|gdpr.*tracking.*without.*consent"
     r"|gdpr.*tracking.*with.*consent",
     _T("T1589", "Gather Victim Identity Information", "Reconnaissance")),

    # Phase 66 — API auth, versioning, security headers
    (r"api auth.*returns.*200.*error|api auth.*no.*authentication|api auth.*no.*response"
     r"|api auth.*no.*auth.*weaknesses",
     _T("T1078", "Valid Accounts", "Initial Access")),
    (r"api security headers.*all.*passed|api security headers.*endpoint.*unresponsive"
     r"|api security headers.*no.*api.*endpoints|api security headers.*no.*response"
     r"|api security.*missing.*strict.transport|api security.*server.*version.*exposed"
     r"|api security.*unusually.*large",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (r"api versioning.*target.*unreachable|api versioning.*missing.*security.*headers"
     r"|api versioning.*returns.*data.*auth|api collection.*target.*unreachable",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Phase 67 — AI API, LLM
    (r"ai api exposure.*target.*unreachable",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 68 — Account enumeration
    (r"account enumeration.*no.*auth.*endpoints|account enumeration.*no.*response"
     r"|account enumeration.*responses.*indistinguishable",
     _T("T1087", "Account Discovery", "Discovery")),

    # Phase 69 — Business logic
    (r"business logic.*no.*obvious|business logic.*no.*response|business logic.*quantity.*field",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 70 — CI/CD
    (r"ci/cd exposure.*TEST_VALUE.*accessible|ci/cd exposure.*target.*unreachable"
     r"|ci.*cd.*exposure.*accessible|ci.*cd.*exposure.*unreachable",
     _T("T1552.001", "Unsecured Credentials: Credentials in Files", "Credential Access")),

    # Phase 71 — CMS detection
    (r"cms detection.*not.*identified|cms.*TEST_VALUE.*detected",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),

    # Phase 72 — COEP / CORP / CORS Advanced
    (r"coep header missing|corp header missing|coep.*cross.origin.embedder"
     r"|corp.*cross.origin.resource",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"cors advanced.*arbitrary.*subdomain.*trusted|cors advanced.*no.*origin.*validation",
     _T("T1185", "Browser Session Hijacking", "Collection")),
    (r"cors.*policy",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 73 — CSTI Nunjucks
    (r"csti.*nunjucks|csti.*target.*unreachable",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 74 — CSV injection target unreachable / no Content-Disposition
    (r"csv injection.*csv.*response.*lacks|csv injection.*lacks.*content.disposition"
     r"|csv injection.*target.*unreachable",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 75 — Clickjacking JS-only / no response
    (r"clickjacking.*only.*javascript|clickjacking.*js.*frame.busting|clickjacking.*no.*response",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 76 — Client-side storage specifics
    (r"client.side storage.*indexeddb|client.side storage.*jwt|client.side storage.*auth.*token"
     r"|client.side storage.*no.*sensitive|client.side storage.*target.*unreachable",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),

    # Phase 77 — Command / Content injection informational
    (r"command injection.*no.*indicators|command injection.*no.*response"
     r"|command injection.*no.*vulnerable",
     _T("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution")),
    (r"content injection.*no.*indicators|content injection.*no.*reflectable"
     r"|content injection.*no.*response",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 78 — Cross-domain policy specifics
    (r"cross.domain policy.*clientaccess.*exposes|cross.domain policy.*clientaccess.*present"
     r"|cross.domain policy.*crossdomain.*allows.*http|cross.domain policy.*crossdomain.*present"
     r"|cross.domain policy.*crossdomain.*uses.*wildcard|cross.domain policy.*target.*unreachable",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 79 — DNS nameserver diversity / redundancy
    (r"dns.*all.*nameservers.*same|dns.*nameservers.*are.*diverse|dns.*single.*nameserver",
     _T("T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance")),

    # Phase 80 — DOM external scripts SRI
    (r"dom.*external.*scripts.*sri|dom.*external.*scripts.*without.*sri",
     _T("T1195.001", "Supply Chain Compromise: Compromise Software Dependencies", "Initial Access")),

    # Phase 81 — Dependency confusion informational
    (r"dependency confusion.*no.*manifest.*found|dependency confusion.*no.*response",
     _T("T1195.001", "Supply Chain Compromise: Compromise Software Dependencies", "Initial Access")),

    # Phase 82 — Developer artifact unreachable
    (r"developer artifact.*target.*unreachable",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 83 — EL injection (Apache Commons JEXL)
    (r"el injection.*apache.*commons.*jexl|el injection.*target.*unreachable",
     _T("T1059", "Command and Scripting Interpreter", "Execution")),

    # Phase 84 — Exposed files
    (r"exposed file.*TEST_VALUE|exposed files.*none.*found",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 85 — Fetch Metadata informational
    (r"fetch metadata.*coop.*coep.*corp.*present|fetch metadata.*target.*unreachable",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 86 — File inclusion no response
    (r"file inclusion.*no.*response",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 87 — Framework config unreachable
    (r"framework config.*target.*unreachable",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 88 — GraphQL informational
    (r"graphql advanced.*no.*issues|graphql advanced.*sensitive.*field"
     r"|graphql depth.*no.*endpoint|graphql depth.*no.*issues|graphql depth.*no.*response"
     r"|graphql.*no.*endpoint.*detected",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    # Phase 89 — HTML comment specific findings
    (r"html comment.*TEST_VALUE|html comments.*no.*sensitive",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 90 — HTTP methods
    (r"http methods$|http methods.*allow.*header.*not.*present|http methods.*dangerous.*method"
     r"|http methods.*write.*method",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Phase 91 — HTTP verb tampering informational
    (r"http verb tampering.*arbitrary.*method.*accepted|http verb tampering.*no.*issues"
     r"|http verb tampering.*no.*response",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Phase 92 — HTTP → HTTPS redirect
    (r"http.*→.*https.*redirect|http.*https.*redirect",
     _T("T1557", "Adversary-in-the-Middle", "Credential Access")),

    # Phase 93 — HTTP/2 no issues
    (r"http/2.*no.*http/2.*security.*issues",
     _T("T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood", "Impact")),

    # Phase 94 — Header reflection
    (r"header reflection.*TEST_VALUE",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 95 — IDOR informational
    (r"idor.*no.*indicators|idor.*no.*response",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 96 — JS file analysis informational
    (r"js file analysis.*no.*same.origin|js file analysis.*target.*unreachable",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 97 — JS libraries / outdated
    (r"js libraries.*no.*detectable|js libraries.*versions.*appear.*current"
     r"|js library.*outdated",
     _T("T1203", "Exploitation for Client Execution", "Execution")),

    # Phase 98 — JSON injection specifics
    (r"json injection.*html.*js.*injection|json injection.*json.like.*data"
     r"|json injection.*__proto__|json injection.*no.*vulnerabilities"
     r"|json injection.*target.*unreachable",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 99 — JWT Advanced specific
    (r"jwt advanced.*www.authenticate.*bearer.*http|jwt advanced.*no.*jwt.*security"
     r"|jwt advanced.*no.*issues",
     _T("T1552", "Unsecured Credentials", "Credential Access")),

    # Phase 100 — JWT security specifics
    (r"jwt security.*algorithm.*expiry|jwt security.*long.lived|jwt security.*no.*expiry"
     r"|jwt security.*no.*tokens.*detected|jwt security.*symmetric",
     _T("T1552", "Unsecured Credentials", "Credential Access")),

    # Phase 101 — K8s specifics
    (r"k8s.*kubernetes.*api.*response.*on.*main|k8s.*TEST_VALUE.*accessible",
     _T("T1613", "Container and Resource Discovery", "Discovery")),

    # Phase 102 — LDAP injection informational
    (r"ldap injection.*no.*indicators|ldap injection.*no.*login.*form"
     r"|ldap injection.*no.*response",
     _T("T1087", "Account Discovery", "Discovery")),

    # Phase 103 — Link security unreachable
    (r"link security.*target.*unreachable",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 104 — Log injection
    (r"log injection.*value.*reflected.*response|log injection.*no.*reflection"
     r"|log injection.*no.*response",
     _T("T1027", "Obfuscated Files or Information", "Defense Evasion")),

    # Phase 105 — Management endpoint
    (r"management endpoint.*accessible",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 106 — Mass assignment informational
    (r"mass assignment.*no.*indicators|mass assignment.*no.*response",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 107 — Mobile deep link
    (r"mobile deep link.*assetlinks",
     _T("T1592.004", "Gather Victim Host Information: Client Configurations", "Reconnaissance")),

    # Phase 108 — OAuth Advanced informational
    (r"oauth advanced.*no.*authorization.*code|oauth advanced.*no.*issues"
     r"|oauth advanced.*no.*response|oauth.*oidc.*no.*flows|oauth.*oidc.*no.*obvious",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 109 — Open ports
    (r"open ports.*TEST_VALUE",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # Phase 110 — OpenID Connect discovery
    (r"openid connect discovery",
     _T("T1087.004", "Account Discovery: Cloud Account", "Discovery")),

    # Phase 111 — PII disclosure
    (r"pii disclosure.*phone|pii disclosure.*credit",
     _T("T1589", "Gather Victim Identity Information", "Reconnaissance")),

    # Phase 112 — Password reset informational
    (r"password reset.*no.*reset.*flow|password reset.*target.*unreachable"
     r"|password reset.*user.*enumeration",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 113 — Path confusion unreachable
    (r"path confusion.*target.*unreachable",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 114 — Path traversal variants
    (r"path traversal.*high.risk.*file|path traversal.*medium.risk.*dir"
     r"|path traversal.*traversal.*sequence.*parameter|path traversal.*no.*lfi",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 115 — RFD unreachable
    (r"rfd.*target.*unreachable",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 116 — Rate limiting
    (r"rate limiting.*enforced|rate limiting.*no.*response.*from.*target"
     r"|rate limiting.*not.*detected",
     _T("T1110", "Brute Force", "Credential Access")),

    # Phase 117 — Redirect chain
    (r"redirect chain.*redirect.*hop.*acceptable|redirect chain.*excessive.*redirect"
     r"|redirect chain.*many.*redirect|redirect chain.*redirect.*loop",
     _T("T1598", "Phishing for Information", "Reconnaissance")),

    # Phase 118 — Referrer-Policy permissive
    (r"referrer.policy.*no.referrer.when.downgrade|referrer.policy.*unsafe.url",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 119 — Response header specifics
    (r"response header.*dns.*prefetch|response header.*etag.*inode"
     r"|response header.*x.dns.prefetch.*not.*set|response header.*deprecated",
     _T("T1082", "System Information Discovery", "Discovery")),

    # Phase 120 — SAML specifics
    (r"saml.*sso.*endpoint.*found|saml.*assertion.*visible.*page.*source"
     r"|saml.*sso.*no.*saml.*flows|saml.*sso.*no.*obvious",
     _T("T1550.001", "Use Alternate Authentication Material: Application Access Token", "Defense Evasion")),

    # Phase 121 — SCA
    (r"sca.*no.*known.*vulnerabilities|sca.*vulnerable.*dependencies",
     _T("T1203", "Exploitation for Client Execution", "Execution")),

    # Phase 122 — SRI advanced / SRI informational
    (r"sri advanced.*integrity.*without.*crossorigin|sri.*all.*external.*resources"
     r"|sri.*no.*external.*resources|sri.*external.*without.*integrity",
     _T("T1195.001", "Supply Chain Compromise: Compromise Software Dependencies", "Initial Access")),

    # Phase 123 — SSTI additional
    (r"ssti.*werkzeug.*interactive|ssti.*template.*syntax.*visible"
     r"|ssti.*template.*engine.*error",
     _T("T1059", "Command and Scripting Interpreter", "Execution")),

    # Phase 124 — Security headers specifics
    (r"security headers.*cors.*cookie.*samesite|security headers.*deprecated.*TEST_VALUE"
     r"|security headers.*duplicate",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 125 — Sensitive URL parameter
    (r"sensitive url parameter.*TEST_VALUE|sensitive url parameters.*none.*detected"
     r"|sensitive.*url.*param",
     _T("T1598", "Phishing for Information", "Reconnaissance")),

    # Phase 126 — Sensitive data exposure informational
    (r"sensitive data exposure.*no.*issues|sensitive data exposure.*no.*response"
     r"|sensitive data exposure.*password.*autocomplete",
     _T("T1552", "Unsecured Credentials", "Credential Access")),

    # Phase 127 — Server-Timing unreachable
    (r"server.timing.*target.*unreachable",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    # Phase 128 — Service worker security informational
    (r"service worker security.*no.*issues|service worker security.*no.*response"
     r"|service worker.*pwa.*manifest.*scope",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 129 — Session management informational
    (r"session management.*no.*issues|session management.*remember.me",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 130 — Source map unreachable / webpack stats
    (r"source map.*target.*unreachable|source map.*webpack.*stats",
     _T("T1083", "File and Directory Discovery", "Discovery")),

    # Phase 131 — Subdomain surface
    (r"subdomain surface.*active.*subdomains|subdomain surface.*no.*common",
     _T("T1584.001", "Compromise Infrastructure: Domains", "Resource Development")),

    # Phase 132 — Threat intelligence
    (r"threat intelligence.*virustotal|threat intelligence.*no.*api.*keys",
     _T("T1596", "Search Open Technical Databases", "Reconnaissance")),

    # Phase 133 — URL parameter encoding bypass
    (r"url parameter.*encoding.*bypass",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),

    # Phase 134 — Version CVE unreachable
    (r"version cve.*target.*unreachable",
     _T("T1190", "Exploit Public-Facing Application", "Initial Access")),

    # Phase 135 — WAF/CDN
    (r"waf.*cdn.*detected|waf.*cdn.*none.*detected",
     _T("T1090", "Proxy", "Command and Control")),

    # Phase 136 — Weak crypto informational
    (r"weak crypto.*no.*response|weak crypto.*no.*weak.*algorithms",
     _T("T1553.004", "Subvert Trust Controls: Install Root Certificate", "Defense Evasion")),

    # Phase 137 — WebAuthn informational
    (r"webauthn.*well.known.*webauthn|webauthn.*conditional.*ui"
     r"|webauthn.*not.*implemented|webauthn security.*target.*unreachable",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 138 — WebSocket no issues
    (r"websocket.*no.*issues",
     _T("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement")),

    # Phase 139 — XML endpoint specifics
    (r"xml endpoint.*doctype.*dtd|xml endpoint.*soap.*xml.*service.*indicators"
     r"|xml endpoint.*wsdl.*soap|xml endpoint.*form.*with.*xml.*mime"
     r"|xml endpoint.*page.*served.*as|xml endpoint.*parser.*error",
     _T("T1059", "Command and Scripting Interpreter", "Execution")),

    # Phase 140 — XML/XXE no endpoints
    (r"xml.*xxe.*no.*xml.*endpoints|xml.*xxe.*no.*indicators|xxe injection.*no.*xml"
     r"|xxe injection.*no.*indicators|xxe injection.*no.*response",
     _T("T1059", "Command and Scripting Interpreter", "Execution")),

    # Phase 141 — XSLeak informational
    (r"xsleak.*cross.site.*leak.*mitigations|xsleak.*target.*unreachable",
     _T("T1185", "Browser Session Hijacking", "Collection")),

    # Phase 142 — gRPC informational
    (r"grpc.*health.*check.*accessible|grpc.*no.*grpc.*endpoints",
     _T("T1046", "Network Service Discovery", "Discovery")),

    # Phase 143 — security.txt
    (r"security\.txt.*incomplete|security\.txt.*missing|security\.txt.*present.*valid",
     _T("T1590", "Gather Victim Network Information", "Reconnaissance")),

    # Phase 144 — Access control admin interface
    (r"access control.*admin.*login.*page.*discoverable",
     _T("T1078", "Valid Accounts", "Initial Access")),

    # Phase 145 — Remaining gap fixes (lowercase-safe, no TEST_VALUE in patterns)
    (r"cms\s*—",
     _T("T1592", "Gather Victim Host Information", "Reconnaissance")),
    (r"cookie.*__host.*prefix(?!.*violation)",
     _T("T1539", "Steal Web Session Cookie", "Credential Access")),
    (r"exposed file\s*—",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"html comment\s*—",
     _T("T1083", "File and Directory Discovery", "Discovery")),
    (r"header reflection\s*—",
     _T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution")),
    (r"k8s.*accessible|k8s.*no.*exposed",
     _T("T1613", "Container and Resource Discovery", "Discovery")),
    (r"login.*form.*submits.*http|login.*form.*over.*http",
     _T("T1040", "Network Sniffing", "Credential Access")),
    (r"open ports\s*—",
     _T("T1046", "Network Service Discovery", "Discovery")),
    (r"ssl.*no.*subject.*alternative",
     _T("T1557", "Adversary-in-the-Middle", "Credential Access")),
    (r"ssti\s*—",
     _T("T1059", "Command and Scripting Interpreter", "Execution")),
    (r"security headers.*deprecated",
     _T("T1185", "Browser Session Hijacking", "Collection")),
]


def get_techniques(finding_type: str) -> List[Dict]:
    """Return ATT&CK techniques matching this finding type string."""
    needle = finding_type.lower()
    seen_ids: set = set()
    results = []
    for pattern, technique in _RULES:
        if technique["id"] in seen_ids:
            continue
        if re.search(pattern, needle):
            results.append(technique)
            seen_ids.add(technique["id"])
    return results
