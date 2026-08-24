"""
Severity scoring engine for Tblue.

Classifies each finding by severity (critical / high / medium / low / info),
computes a 0-100 site security score, and produces a prioritised fix list.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Tuple

# ── Severity constants ────────────────────────────────────────────────────────

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

SEVERITY_LABELS = {
    CRITICAL: "🔴 Critical",
    HIGH:     "🟠 High",
    MEDIUM:   "🟡 Medium",
    LOW:      "🔵 Low",
    INFO:     "⚪ Info",
}

# Points deducted per (severity, status) pair
_DEDUCTIONS: Dict[Tuple[str, str], int] = {
    (CRITICAL, "FAIL"): 20,
    (CRITICAL, "WARN"): 10,
    (HIGH,     "FAIL"): 10,
    (HIGH,     "WARN"):  5,
    (MEDIUM,   "FAIL"):  5,
    (MEDIUM,   "WARN"):  2,
    (LOW,      "FAIL"):  2,
    (LOW,      "WARN"):  1,
    (INFO,     "FAIL"):  0,
    (INFO,     "WARN"):  0,
    (INFO,     "PASS"):  0,
}

# Maximum points each severity band can deduct in total.
# Prevents many low-severity findings from overwhelming the score.
_SEVERITY_CAPS: Dict[str, int] = {
    CRITICAL: 35,
    HIGH:     25,
    MEDIUM:   20,
    LOW:      10,
    INFO:      0,
}

# ── Severity classification rules ─────────────────────────────────────────────
# Ordered list of (substring, severity_on_fail, severity_on_warn).
# First match wins. Case-insensitive on the lowercased type string.

_RULES: List[Tuple[str, str, str]] = [
    # ── CRITICAL FAILs ────────────────────────────────────────────────────────
    ("ssl / https",                              CRITICAL, HIGH),
    ("api keys in page source",                  CRITICAL, HIGH),
    ("git repository",                           CRITICAL, HIGH),
    (".env file",                                CRITICAL, HIGH),
    ("sql database dump",                        CRITICAL, HIGH),
    (".htpasswd credentials",                    CRITICAL, HIGH),
    ("wordpress config",                         CRITICAL, HIGH),
    ("php config backup",                        CRITICAL, HIGH),
    ("web.config backup",                        CRITICAL, HIGH),
    ("template injection",                       CRITICAL, MEDIUM),
    ("cors reflected origin with credentials",   CRITICAL, HIGH),
    ("login — form submits over http",           CRITICAL, HIGH),
    ("login — page served over http",            CRITICAL, HIGH),

    # ── HIGH FAILs ────────────────────────────────────────────────────────────
    ("form #",                                   HIGH, LOW),   # XSS form (WARN = encoded = low)
    ("url parameter reflection",                 HIGH, LOW),
    ("header reflection",                        HIGH, MEDIUM),
    ("json reflection",                          HIGH, MEDIUM),
    ("encoding bypass",                          HIGH, MEDIUM),
    ("http → https redirect",                    HIGH, MEDIUM),
    ("ssl — certificate",                        HIGH, MEDIUM),
    ("ssl — tls version",                        HIGH, MEDIUM),
    ("ssl — self-signed",                        HIGH, MEDIUM),
    ("ssl — sans",                               HIGH, MEDIUM),
    ("ssl — certificate chain",                  HIGH, MEDIUM),
    ("ssl — no subject alternative",             HIGH, MEDIUM),
    ("csp — missing",                            HIGH, MEDIUM),
    ("csp — dangerous value",                    HIGH, MEDIUM),
    ("csp — static or weak nonce",               HIGH, MEDIUM),
    ("stack trace in error page",                HIGH, MEDIUM),
    ("directory listing",                        HIGH, MEDIUM),
    ("login — csrf token",                       HIGH, MEDIUM),
    ("login — subresource integrity",            HIGH, MEDIUM),
    ("postmessage without origin",               HIGH, MEDIUM),
    ("open redirect",                            HIGH, MEDIUM),
    ("cors null origin",                         HIGH, HIGH),
    ("security headers",                         HIGH, MEDIUM),
    ("low entropy value",                        HIGH, MEDIUM),
    ("httponly",                                 HIGH, MEDIUM),
    ("secure missing",                           HIGH, MEDIUM),
    ("backup",                                   HIGH, MEDIUM),
    ("dom — external scripts without sri",       HIGH, MEDIUM),
    ("mixed content",                            HIGH, MEDIUM),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    ("samesite",                                 MEDIUM, LOW),
    ("x-frame-options",                          MEDIUM, LOW),
    ("x-content-type-options",                   MEDIUM, LOW),
    ("csp —",                                    MEDIUM, LOW),
    ("dom risk pattern",                         MEDIUM, LOW),
    ("internal ip",                              MEDIUM, LOW),
    ("source map",                               MEDIUM, LOW),
    ("x-powered-by",                             MEDIUM, LOW),
    ("x-aspnet",                                 MEDIUM, LOW),
    ("login — account lockout",                  MEDIUM, LOW),
    ("login — username enumeration",             MEDIUM, LOW),
    ("login — mfa",                              MEDIUM, LOW),
    ("login — remember me",                      MEDIUM, LOW),
    ("login — rate limiting",                    MEDIUM, LOW),
    ("login — cache control",                    MEDIUM, LOW),
    ("cors wildcard",                            MEDIUM, LOW),
    ("sensitive path",                           MEDIUM, LOW),
    ("csp + cookie",                             MEDIUM, LOW),

    # ── JS secrets ────────────────────────────────────────────────────────────
    ("js secret —",                                CRITICAL, HIGH),
    ("js secrets — none detected",                 INFO, INFO),

    # ── TLS deep ──────────────────────────────────────────────────────────────
    ("tls — weak cipher suite",                    HIGH, MEDIUM),
    ("tls — no forward secrecy",                   MEDIUM, LOW),
    ("tls — forward secrecy",                      INFO, INFO),
    ("tls — certificate expired",                  CRITICAL, HIGH),
    ("tls — certificate expiring imminently",      CRITICAL, HIGH),
    ("tls — certificate expiring soon",            HIGH, MEDIUM),
    ("tls — certificate expiry",                   INFO, INFO),
    ("tls — weak rsa key size",                    HIGH, MEDIUM),
    ("tls — weak ec key size",                     MEDIUM, LOW),
    ("tls — key size",                             INFO, INFO),
    ("tls — sha-1 certificate signature",          MEDIUM, LOW),
    ("tls — md5 certificate signature",            CRITICAL, HIGH),
    ("tls — certificate signature algorithm",      INFO, INFO),
    ("tls — hsts not preload-ready",               LOW, LOW),
    ("tls — hsts preload ready",                   INFO, INFO),

    # ── Email advanced ────────────────────────────────────────────────────────
    ("email — mta-sts not configured",             MEDIUM, LOW),
    ("email — mta-sts policy file missing",        MEDIUM, LOW),
    ("email — mta-sts policy file unreachable",    LOW, LOW),
    ("email — mta-sts configured",                 INFO, INFO),
    ("email — tls-rpt not configured",             LOW, LOW),
    ("email — tls-rpt configured",                 INFO, INFO),
    ("email — bimi not configured",                LOW, LOW),
    ("email — bimi configured",                    INFO, INFO),
    ("email — dane/tlsa not configured",           LOW, LOW),
    ("email — dane/tlsa configured",               INFO, INFO),
    ("email — spf allows all senders (+all)",      CRITICAL, HIGH),
    ("email — spf strict (-all)",                  INFO, INFO),
    ("email — spf softfail (~all)",                MEDIUM, LOW),
    ("email — spf neutral (?all)",                 MEDIUM, LOW),
    ("email — spf lookup limit exceeded",          HIGH, MEDIUM),
    ("email — spf approaching lookup limit",       LOW, LOW),
    ("email — dmarc policy is none",               HIGH, MEDIUM),
    ("email — dmarc p=quarantine",                 MEDIUM, LOW),
    ("email — dmarc fully enforced",               INFO, INFO),
    ("email — dmarc partial enforcement",          MEDIUM, LOW),
    ("email — dmarc subdomain policy not set",     LOW, LOW),

    # ── Supply chain ──────────────────────────────────────────────────────────
    ("sri — external resources without integrity", HIGH, MEDIUM),
    ("sri — all external resources",               INFO, INFO),
    ("sri — no external resources",                INFO, INFO),
    ("permissions-policy header missing",          MEDIUM, LOW),
    ("permissions-policy — configured",            INFO, INFO),
    ("coop header missing",                        MEDIUM, LOW),
    ("coop —",                                     INFO, INFO),
    ("coep header missing",                        MEDIUM, LOW),
    ("coep —",                                     INFO, INFO),
    ("corp header missing",                        LOW, LOW),
    ("corp —",                                     INFO, INFO),
    ("supply chain — tracking scripts",            MEDIUM, LOW),
    ("supply chain — no known trackers",           INFO, INFO),
    ("supply chain — no third-party",              INFO, INFO),

    # ── Form security ─────────────────────────────────────────────────────────
    ("form — csrf token missing",                  HIGH, MEDIUM),
    ("form — csrf tokens present",                 INFO, INFO),
    ("form — password field blocks",               MEDIUM, LOW),
    ("form — password fields allow",               INFO, INFO),
    ("form — .well-known/change-password missing", LOW, LOW),
    ("form — .well-known/change-password configured", INFO, INFO),
    ("form — sensitive page not cached",           INFO, INFO),
    ("form — sensitive page may be cached",        MEDIUM, LOW),
    ("form — sensitive page caching could",        LOW, LOW),

    # ── CT / crt.sh ───────────────────────────────────────────────────────────
    ("certificate transparency —",                 INFO, INFO),

    # ── Subdomain takeover ────────────────────────────────────────────────────
    ("subdomain takeover —",                       CRITICAL, HIGH),

    # ── Typosquatting ─────────────────────────────────────────────────────────
    ("typosquatting — registered lookalike domains with mail", CRITICAL, HIGH),
    ("typosquatting — registered lookalike domains detected",  HIGH, MEDIUM),
    ("typosquatting — no registered",              INFO, INFO),

    # ── SCA ───────────────────────────────────────────────────────────────────
    ("sca — vulnerable dependencies",              HIGH, MEDIUM),
    ("sca — no known vulnerabilities",             INFO, INFO),

    # ── Cloud storage ─────────────────────────────────────────────────────────
    ("cloud storage — public",                     CRITICAL, HIGH),
    ("cloud storage — no public buckets",          INFO, INFO),

    # ── CMS detection ─────────────────────────────────────────────────────────
    ("cms — ",                                     HIGH, MEDIUM),
    ("cms detection — not identified",             INFO, INFO),

    # ── Infra ─────────────────────────────────────────────────────────────────
    ("directory listing enabled",                  HIGH, MEDIUM),
    ("directory listing — not detected",           INFO, INFO),
    (".git directory exposed",                     CRITICAL, HIGH),
    ("source map",                                 MEDIUM, LOW),
    ("ide artifacts exposed",                      MEDIUM, LOW),
    ("environment template exposed",               MEDIUM, LOW),
    ("openid connect discovery",                   LOW, LOW),
    ("referrer-policy: unsafe-url",                MEDIUM, LOW),
    ("referrer-policy: no-referrer-when-downgrade", LOW, LOW),

    # ── CSP advanced ──────────────────────────────────────────────────────────
    ("csp advanced — report-only mode",            HIGH, MEDIUM),
    ("csp advanced — delivered via <meta>",        MEDIUM, LOW),
    ("csp advanced — no violation reporting",      MEDIUM, LOW),
    ("csp advanced — violation reporting",         INFO, INFO),
    ("csp advanced — frame-ancestors 'none'",      INFO, INFO),
    ("csp advanced — frame-ancestors 'self'",      INFO, INFO),
    ("csp advanced — frame-ancestors allows",      INFO, INFO),
    ("csp advanced — frame-ancestors directive missing", MEDIUM, LOW),
    ("csp advanced — base-uri not restricted",     MEDIUM, LOW),
    ("csp advanced — base-uri restriction",        INFO, INFO),
    ("csp advanced — form-action not restricted",  MEDIUM, LOW),
    ("csp advanced — form-action restriction",     INFO, INFO),
    ("csp advanced — upgrade-insecure-requests",   INFO, INFO),
    ("csp advanced — trusted types enforced",      INFO, INFO),

    # ── SRI advanced ──────────────────────────────────────────────────────────
    ("sri advanced — weak hash algorithm",         CRITICAL, HIGH),
    ("sri advanced — integrity= without crossorigin", MEDIUM, LOW),
    ("sri advanced — 100% coverage",               INFO, INFO),
    ("sri advanced — partial coverage",            MEDIUM, LOW),
    ("sri advanced — low coverage",                HIGH, MEDIUM),

    # ── Host header injection ─────────────────────────────────────────────────────
    ("host header injection",                          HIGH, HIGH),
    ("host header injection — not detected",           INFO, INFO),

    # ── Open redirect ─────────────────────────────────────────────────────────────
    ("open redirect parameter detected",               HIGH, MEDIUM),
    ("open redirect parameters — none detected",       INFO, INFO),

    # ── Permissions-Policy ─────────────────────────────────────────────────────────
    ("permissions-policy — header absent",             MEDIUM, LOW),
    ("permissions-policy — only deprecated feature-policy header set", LOW, LOW),
    ("permissions-policy — camera allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — microphone allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — geolocation allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — payment allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — usb allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — serial allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — bluetooth allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — display-capture allowed for all origins (*)", HIGH, MEDIUM),
    ("permissions-policy — camera not restricted",     MEDIUM, LOW),
    ("permissions-policy — microphone not restricted", MEDIUM, LOW),
    ("permissions-policy — geolocation not restricted",MEDIUM, LOW),
    ("permissions-policy — payment not restricted",    MEDIUM, LOW),
    ("permissions-policy — usb not restricted",        MEDIUM, LOW),
    ("permissions-policy — camera blocked ()",         INFO, INFO),
    ("permissions-policy — microphone blocked ()",     INFO, INFO),
    ("permissions-policy — geolocation blocked ()",    INFO, INFO),
    ("permissions-policy — payment blocked ()",        INFO, INFO),
    ("permissions-policy — camera restricted to self", INFO, INFO),
    ("permissions-policy — microphone restricted to self", INFO, INFO),
    ("permissions-policy — geolocation restricted to self", INFO, INFO),
    ("permissions-policy",                             LOW, LOW),

    # ── GDPR/Privacy ────────────────────────────────────────────────────────────────────
    ("gdpr — no cookie consent banner detected",       HIGH, MEDIUM),
    ("gdpr — cookie consent management platform detected", INFO, INFO),
    ("gdpr — no privacy policy link detected",         MEDIUM, LOW),
    ("gdpr — privacy policy link present",             INFO, INFO),
    ("gdpr — tracking script loaded on first load",    HIGH, MEDIUM),
    ("gdpr — no tracking scripts detected on first load", INFO, INFO),
    ("gdpr — cookies set on first load before consent",MEDIUM, LOW),

    # ── Threat intelligence ───────────────────────────────────────────────────
    ("threat intelligence — abuseipdb: ip",              HIGH, MEDIUM),
    ("threat intelligence — abuseipdb: ip",              HIGH, MEDIUM),  # covered below
    ("threat intelligence — otx:",                       HIGH, MEDIUM),
    ("threat intelligence — virustotal:",                HIGH, MEDIUM),
    ("threat intelligence — no api keys",                LOW, LOW),
    ("threat intelligence —",                            INFO, INFO),

    # ── Response headers ──────────────────────────────────────────────────────
    ("response header — version disclosure",       MEDIUM, LOW),
    ("response header — technology disclosure",    LOW, LOW),
    ("response headers — no version",              INFO, INFO),
    ("response header — deprecated header present (public-key-pins)", HIGH, MEDIUM),
    ("response header — deprecated header present (x-xss-protection)", MEDIUM, LOW),
    ("response header — x-xss-protection: 0",     INFO, INFO),
    ("response header — deprecated header present", LOW, LOW),
    ("response header — internal infrastructure disclosed", MEDIUM, LOW),
    ("response header — etag may disclose inode",  LOW, LOW),
    ("response header — dns prefetch disabled",    INFO, INFO),
    ("response header — x-dns-prefetch-control not set", LOW, LOW),

    # ── Cookie advanced ───────────────────────────────────────────────────────
    ("cookie — __secure- prefix violation",        CRITICAL, HIGH),
    ("cookie — __host- prefix violation",          CRITICAL, HIGH),
    ("cookie — samesite=none without secure",      HIGH, MEDIUM),
    ("cookie — sensitive cookie missing httponly", HIGH, MEDIUM),
    ("cookie — overly broad domain attribute",     MEDIUM, LOW),
    ("cookie advanced —",                          INFO, INFO),

    # ── Redirect chain ────────────────────────────────────────────────────────
    ("redirect chain — redirect loop",             CRITICAL, HIGH),
    ("redirect chain — http leg before https",     HIGH, MEDIUM),
    ("redirect chain — https→http→https",          HIGH, MEDIUM),
    ("redirect chain — final destination is http", HIGH, MEDIUM),
    ("redirect chain — excessive redirects",       MEDIUM, LOW),
    ("redirect chain — many redirects",            LOW, LOW),
    ("redirect chain —",                           INFO, INFO),

    # ── robots.txt ────────────────────────────────────────────────────────────
    ("robots.txt — critical paths disclosed",      HIGH, MEDIUM),
    ("robots.txt — sensitive paths disclosed",     MEDIUM, LOW),
    ("robots.txt — file not found",                LOW, LOW),
    ("robots.txt — full site blocked",             LOW, LOW),
    ("robots.txt —",                               INFO, INFO),

    # ── DNS advanced ──────────────────────────────────────────────────────────
    ("dns — no caa record",                        MEDIUM, LOW),
    ("dns — caa record allows any ca",             MEDIUM, LOW),
    ("dns — caa record configured",                INFO, INFO),
    ("dns — dnssec not enabled",                   MEDIUM, LOW),
    ("dns — dnssec partially configured",          LOW, LOW),
    ("dns — dnssec enabled",                       INFO, INFO),
    ("dns — single nameserver",                    LOW, LOW),
    ("dns — all nameservers from same provider",   LOW, LOW),
    ("dns — nameservers are diverse",              INFO, INFO),

    # ── Admin exposure ────────────────────────────────────────────────────────
    ("admin exposure — .env file",                 CRITICAL, HIGH),
    ("admin exposure — wordpress config",          CRITICAL, HIGH),
    ("admin exposure — web.config backup",         CRITICAL, HIGH),
    ("admin exposure — phpmyadmin",                CRITICAL, HIGH),
    ("admin exposure — adminer",                   CRITICAL, HIGH),
    ("admin exposure — tomcat manager",            CRITICAL, HIGH),
    ("admin exposure — spring boot env dump",      CRITICAL, HIGH),
    ("admin exposure — spring boot heap dump",     CRITICAL, HIGH),
    ("admin exposure — aws instance metadata",     CRITICAL, HIGH),
    ("admin exposure — admin panel",               HIGH, MEDIUM),
    ("admin exposure — laravel telescope",         HIGH, MEDIUM),
    ("admin exposure — laravel horizon",           HIGH, MEDIUM),
    ("admin exposure — symfony profiler",          HIGH, MEDIUM),
    ("admin exposure — yii2 debug module",         HIGH, MEDIUM),
    ("admin exposure — apache server-status",      HIGH, MEDIUM),
    ("admin exposure — apache server-info",        HIGH, MEDIUM),
    ("admin exposure —",                           MEDIUM, LOW),
    ("admin exposure — no sensitive paths",        INFO, INFO),

    # ── HTML comments ─────────────────────────────────────────────────────────
    ("html comment — password/credential",         CRITICAL, HIGH),
    ("html comment — api key in comment",          CRITICAL, HIGH),
    ("html comment — aws key pattern",             CRITICAL, HIGH),
    ("html comment — database connection",         CRITICAL, HIGH),
    ("html comment — disabled security check",     HIGH, MEDIUM),
    ("html comment — stack trace fragment",        HIGH, MEDIUM),
    ("html comment — todo with sensitive hint",    MEDIUM, LOW),
    ("html comment — fixme with sensitive hint",   MEDIUM, LOW),
    ("html comment — internal ip address",         MEDIUM, LOW),
    ("html comment — localhost reference",         MEDIUM, LOW),
    ("html comment — server path disclosure",      MEDIUM, LOW),
    ("html comment —",                             LOW, LOW),
    ("html comments — no sensitive data",          INFO, INFO),

    # ── DNS security ──────────────────────────────────────────────────────────
    ("dnssec — not configured",                    MEDIUM, LOW),
    ("dnssec — configured",                        INFO, INFO),
    ("subdomain surface",                          INFO, INFO),

    # ── JS libraries ──────────────────────────────────────────────────────────
    ("js library — outdated",                      HIGH, MEDIUM),
    ("js libraries — versions appear current",     INFO, INFO),
    ("js libraries — no detectable",               INFO, INFO),

    # ── Sensitive URL params ───────────────────────────────────────────────────
    ("sensitive url parameter",                    MEDIUM, LOW),
    ("sensitive url parameters — none detected",   INFO, INFO),

    # ── Exposed files ─────────────────────────────────────────────────────────
    ("exposed file — swagger",                     HIGH, MEDIUM),
    ("exposed file — openapi",                     HIGH, MEDIUM),
    ("exposed file — api docs",                    HIGH, MEDIUM),
    ("exposed file — api spec",                    HIGH, MEDIUM),
    ("exposed file — spec swagger",                HIGH, MEDIUM),
    ("exposed file — package.json",                MEDIUM, LOW),
    ("exposed file — package-lock.json",           MEDIUM, LOW),
    ("exposed file — yarn.lock",                   MEDIUM, LOW),
    ("exposed file — composer",                    MEDIUM, LOW),
    ("exposed file — requirements.txt",            MEDIUM, LOW),
    ("exposed file — pipfile",                     MEDIUM, LOW),
    ("exposed file — gemfile",                     MEDIUM, LOW),
    ("exposed file — go.",                         MEDIUM, LOW),
    ("exposed file — pom.xml",                     MEDIUM, LOW),
    ("exposed file — build.gradle",                MEDIUM, LOW),
    ("exposed file — cargo.toml",                  MEDIUM, LOW),
    ("exposed file — github actions",              MEDIUM, LOW),
    ("exposed file — gitlab",                      MEDIUM, LOW),
    ("exposed file — jenkinsfile",                 MEDIUM, LOW),
    ("exposed file — travis",                      MEDIUM, LOW),
    ("exposed file — circleci",                    MEDIUM, LOW),
    ("exposed file — azure pipelines",             MEDIUM, LOW),
    ("exposed file — drone",                       MEDIUM, LOW),
    ("exposed file — bitbucket",                   MEDIUM, LOW),
    ("exposed file — codebuild",                   MEDIUM, LOW),
    ("exposed file — cloud build",                 MEDIUM, LOW),
    ("exposed files — none found",                 INFO, INFO),

    # ── Rate limiting ──────────────────────────────────────────────────────────
    ("rate limiting — not detected",               MEDIUM, LOW),
    ("rate limiting — enforced",                   INFO, INFO),

    # ── JWT security ──────────────────────────────────────────────────────────
    ("jwt security — alg:none",                    CRITICAL, HIGH),
    ("jwt security — symmetric algorithm",         MEDIUM, LOW),
    ("jwt security — no expiry",                   MEDIUM, LOW),
    ("jwt security — long-lived token",            LOW, LOW),
    ("jwt security — algorithm and expiry",        INFO, INFO),
    ("jwt security — no tokens detected",          INFO, INFO),

    # ── WAF detection ─────────────────────────────────────────────────────────
    ("waf/cdn —",                                  INFO, INFO),      # PASS or WARN
    ("waf/cdn — none detected",                    LOW, LOW),

    # ── CORS ─────────────────────────────────────────────────────────────────
    ("cors — reflected origin with credentials",   CRITICAL, HIGH),
    ("cors — null origin with credentials",        CRITICAL, HIGH),
    ("cors — reflected origin without credentials", HIGH, MEDIUM),
    ("cors — null origin accepted",                HIGH, MEDIUM),
    ("cors — subdomain-wildcard acao reflection",  MEDIUM, LOW),
    ("cors — wildcard access-control-allow-origin", MEDIUM, LOW),
    ("cors — wildcard acao with credentials",      MEDIUM, LOW),
    ("cors — policy",                              INFO, INFO),      # PASS

    # ── security.txt ─────────────────────────────────────────────────────────
    ("security.txt — missing",                     LOW, LOW),
    ("security.txt — incomplete",                  LOW, LOW),
    ("security.txt — present",                     INFO, INFO),     # PASS

    # ── Error pages ───────────────────────────────────────────────────────────
    ("error page — stack trace",                   HIGH, MEDIUM),
    ("error page — framework/server version",      MEDIUM, LOW),
    ("error page — information disclosure",        INFO, INFO),     # PASS

    # ── GraphQL ───────────────────────────────────────────────────────────────
    ("graphql — introspection enabled",          HIGH, MEDIUM),
    ("graphql — playground/ide exposed",         MEDIUM, LOW),
    ("graphql — query batching enabled",         LOW, LOW),
    ("graphql — no endpoint detected",           INFO, INFO),

    # ── HTTP methods ──────────────────────────────────────────────────────────
    ("http methods — dangerous method",          HIGH, MEDIUM),
    ("http methods — write method",              MEDIUM, LOW),
    ("http methods",                             INFO, INFO),

    # ── Open ports ────────────────────────────────────────────────────────────
    ("open ports — 3306/mysql",                  CRITICAL, HIGH),
    ("open ports — 5432/postgresql",             CRITICAL, HIGH),
    ("open ports — 6379/redis",                  CRITICAL, HIGH),
    ("open ports — 27017/mongodb",               CRITICAL, HIGH),
    ("open ports — 9200/elasticsearch",          CRITICAL, HIGH),
    ("open ports — 5984/couchdb",                CRITICAL, HIGH),
    ("open ports — 11211/memcached",             CRITICAL, HIGH),
    ("open ports — 3389/rdp",                    CRITICAL, HIGH),
    ("open ports — 2375/docker api",             CRITICAL, HIGH),
    ("open ports — 10250/kubelet",               CRITICAL, HIGH),
    ("open ports — 4848/glassfish",              CRITICAL, HIGH),
    ("open ports — 7001/weblogic",               CRITICAL, HIGH),
    ("open ports — 8161/activemq",               CRITICAL, HIGH),
    ("open ports — 4369/erlang",                 CRITICAL, HIGH),
    ("open ports — 23/telnet",                   CRITICAL, HIGH),
    ("open ports — 21/ftp",                      MEDIUM, LOW),
    ("open ports — 22/ssh",                      LOW, LOW),
    ("open ports — 25/smtp",                     MEDIUM, LOW),
    ("open ports — 8080/http alt",               MEDIUM, LOW),
    ("open ports — 8443/https alt",              LOW, LOW),
    ("open ports — 9090/prometheus",             MEDIUM, LOW),
    ("open ports — 9000/php-fpm",                MEDIUM, LOW),
    ("open ports — 5601/kibana",                 MEDIUM, LOW),
    ("open ports — 2376/docker tls",             MEDIUM, LOW),
    ("open ports — 15672/rabbitmq",              MEDIUM, LOW),
    ("open ports — no dangerous ports",          INFO, INFO),

    # ── Email / DNS ───────────────────────────────────────────────────────────
    ("email security — spf record missing",      HIGH, MEDIUM),
    ("email security — spf policy too permissive", HIGH, MEDIUM),
    ("email security — dmarc record missing",    HIGH, MEDIUM),
    ("email security — dmarc policy is p=none",  HIGH, MEDIUM),
    ("email security — dmarc policy is quarantine", MEDIUM, LOW),
    ("email security — dmarc reporting not configured", LOW, LOW),
    ("email security — dkim not detected",       MEDIUM, LOW),
    ("email security — dkim key may be weak",    MEDIUM, LOW),
    ("email security — spf policy is ~all",      MEDIUM, LOW),
    ("email security — spf",                     INFO, INFO),     # PASS
    ("email security — dmarc",                   INFO, INFO),     # PASS
    ("email security — dkim",                    INFO, INFO),     # PASS
    ("dns — caa records missing",                LOW, LOW),
    ("dns — caa records",                        INFO, INFO),

    # ── Access control ────────────────────────────────────────────────────────
    ("access control — admin interface publicly accessible", HIGH, HIGH),
    ("access control — admin login page discoverable", MEDIUM, LOW),
    ("access control — robots.txt leaks admin path", LOW, LOW),
    ("access control — admin interface exposure",    INFO, INFO),  # PASS

    # ── GDPR ─────────────────────────────────────────────────────────────────
    ("gdpr — tracking cookies set without consent", HIGH, MEDIUM),
    ("gdpr — tracking cookies with consent ui",     LOW, LOW),
    ("gdpr — no tracking cookies",                  INFO, INFO),

    # ── PII ───────────────────────────────────────────────────────────────────
    ("pii disclosure — phone numbers / credit cards", MEDIUM, LOW),

    # ── LOW ───────────────────────────────────────────────────────────────────
    ("email addresses",                          LOW, LOW),
    ("html comments",                            LOW, LOW),
    ("meta generator",                           LOW, LOW),
    ("meta '",                                   LOW, LOW),
    ("deprecated",                               LOW, LOW),
    ("duplicate",                                LOW, LOW),
    ("long expiry",                              LOW, LOW),
    ("wildcard domain",                          LOW, LOW),
    ("partitioned",                              LOW, LOW),
    ("missing security prefix",                  LOW, LOW),
    ("session cookie",                           LOW, LOW),
    ("password autocomplete",                    LOW, LOW),
    ("password maxlength",                       LOW, LOW),
    ("password field type",                      LOW, LOW),
    ("login — https",                            LOW, LOW),
    ("login — form method",                      LOW, LOW),

    # ── Phase 56+ additions ───────────────────────────────────────────────────

    # CORS Advanced
    ("cors advanced — arbitrary origin reflected with credentials",  CRITICAL, HIGH),
    ("cors advanced — http origin trusted for https",               HIGH, MEDIUM),
    ("cors advanced — arbitrary origin reflected",                  HIGH, MEDIUM),
    ("cors advanced — null origin accepted",                        HIGH, MEDIUM),
    ("cors advanced — arbitrary subdomain trusted",                 MEDIUM, LOW),
    ("cors advanced — missing vary: origin",                        LOW, LOW),
    ("cors advanced — no origin validation issues",                 INFO, INFO),
    ("cors — origin reflected without credentials",                 MEDIUM, LOW),

    # API auth / API security / API versioning / API surface
    ("api auth — sensitive endpoint",                               HIGH, HIGH),
    ("api auth — http basic authentication over non-https",         HIGH, MEDIUM),
    ("api auth — api key",                                          HIGH, HIGH),
    ("api auth — 401 response missing www-authenticate",            MEDIUM, LOW),
    ("api auth — returns 200 with authentication error",            MEDIUM, LOW),
    ("api auth — no authentication weaknesses",                     INFO, INFO),
    ("api auth — no response",                                      INFO, INFO),
    ("api security — stack trace",                                  HIGH, MEDIUM),
    ("api security — database error message",                       HIGH, MEDIUM),
    ("api security — server version exposed",                       MEDIUM, LOW),
    ("api security — missing strict-transport-security",            MEDIUM, LOW),
    ("api security — cache-control does not prevent caching",       LOW, LOW),
    ("api security — missing cache-control",                        LOW, LOW),
    ("api security — content-type missing charset",                 LOW, LOW),
    ("api security — unusually large response",                     LOW, LOW),
    ("api security headers — all checks passed",                    INFO, INFO),
    ("api security headers — endpoint unresponsive",                INFO, INFO),
    ("api security headers — no api endpoints found",               INFO, INFO),
    ("api security headers — no response",                          INFO, INFO),
    ("api surface — routes without security scheme",                HIGH, MEDIUM),
    ("api surface — sensitive field names in schema",               MEDIUM, LOW),
    ("api surface — openapi specification exposed",                 MEDIUM, LOW),
    ("api surface — swagger ui exposed",                            MEDIUM, LOW),
    ("api surface — documentation exposed",                         LOW, LOW),
    ("api surface — no exposed documentation",                      INFO, INFO),
    ("api versioning — returns data where",                         HIGH, HIGH),
    ("api versioning — vtest_value returns data where",             HIGH, HIGH),
    ("api versioning — missing security headers present in",        MEDIUM, LOW),
    ("api versioning — deprecated",                                 MEDIUM, LOW),
    ("api versioning — unversioned api endpoint",                   MEDIUM, LOW),
    ("api versioning — version enumeration hint",                   LOW, LOW),
    ("api versioning — target unreachable",                         INFO, INFO),
    ("api collection — publicly accessible",                        HIGH, HIGH),
    ("api collection — no postman",                                 INFO, INFO),
    ("api collection — target unreachable",                         INFO, INFO),

    # Account enumeration
    ("account enumeration — 'user not found'",                      HIGH, MEDIUM),
    ("account enumeration — success message only",                  HIGH, MEDIUM),
    ("account enumeration — different http status codes",           MEDIUM, LOW),
    ("account enumeration — response size differs",                 MEDIUM, LOW),
    ("account enumeration — no auth endpoints found",               INFO, INFO),
    ("account enumeration — no response",                           INFO, INFO),
    ("account enumeration — responses indistinguishable",           INFO, INFO),

    # Admin endpoint
    ("admin endpoint exposed",                                      HIGH, HIGH),

    # Business logic
    ("business logic — idor risk (sequential object ids)",          HIGH, MEDIUM),
    ("business logic — client-submitted price",                     HIGH, MEDIUM),
    ("business logic — privilege escalation parameter",             HIGH, MEDIUM),
    ("business logic — numeric object ids in links",                MEDIUM, LOW),
    ("business logic — cart/basket endpoint accessible",            MEDIUM, LOW),
    ("business logic — quantity field without min",                 LOW, LOW),
    ("business logic — no obvious issues",                          INFO, INFO),
    ("business logic — no response",                                INFO, INFO),

    # CI/CD exposure
    ("ci/cd exposure — hardcoded secret",                           CRITICAL, HIGH),
    ("ci/cd exposure — publicly accessible",                        HIGH, HIGH),
    ("ci/cd exposure — accessible",                                 HIGH, HIGH),
    ("ci/cd exposure — no pipeline configuration",                  INFO, INFO),
    ("ci/cd exposure — target unreachable",                         INFO, INFO),

    # CSTI
    ("csti — angularjs",                                            HIGH, MEDIUM),
    ("csti — angular bypasssecuritytrust",                          HIGH, MEDIUM),
    ("csti — react dangerouslysetinnerhtml",                        HIGH, MEDIUM),
    ("csti — vue.js v-html",                                        HIGH, MEDIUM),
    ("csti — handlebars triple-stache",                             HIGH, MEDIUM),
    ("csti — nunjucks env.renderstring",                            HIGH, MEDIUM),
    ("csti — ng-bind-html",                                         MEDIUM, LOW),
    ("csti — underscore/lodash",                                    MEDIUM, LOW),
    ("csti — unsafe template pattern",                              MEDIUM, LOW),
    ("csti — target unreachable",                                   INFO, INFO),

    # Client-side storage
    ("client-side storage — password written",                      HIGH, HIGH),
    ("client-side storage — jwt/auth token stored",                 HIGH, MEDIUM),
    ("client-side storage — pii or payment data",                   HIGH, MEDIUM),
    ("client-side storage — auth token assigned",                   HIGH, MEDIUM),
    ("client-side storage — sensitive data written",                MEDIUM, LOW),
    ("client-side storage — auth token read from",                  MEDIUM, LOW),
    ("client-side storage — sensitive key name",                    MEDIUM, LOW),
    ("client-side storage — indexeddb object store",                MEDIUM, LOW),
    ("client-side storage — no sensitive data",                     INFO, INFO),
    ("client-side storage — target unreachable",                    INFO, INFO),

    # Cloud metadata
    ("cloud metadata — ssrf to aws imds succeeded",                 CRITICAL, HIGH),
    ("cloud metadata — kubernetes service account token path",      CRITICAL, HIGH),
    ("cloud metadata — metadata endpoint in js bundle",             HIGH, MEDIUM),
    ("cloud metadata — metadata endpoint reference in page",        HIGH, MEDIUM),
    ("cloud metadata — no ssrf or metadata",                        INFO, INFO),

    # Command injection
    ("command injection — os command output",                       CRITICAL, HIGH),
    ("command injection — timing delay",                            HIGH, HIGH),
    ("command injection — shell error message",                     HIGH, MEDIUM),
    ("command injection — no indicators",                           INFO, INFO),
    ("command injection — no response",                             INFO, INFO),
    ("command injection — no vulnerable",                           INFO, INFO),

    # Content injection
    ("content injection — css injection via",                       MEDIUM, LOW),
    ("content injection — unescaped html in parameter",             MEDIUM, LOW),
    ("content injection — no indicators",                           INFO, INFO),
    ("content injection — no reflectable",                          INFO, INFO),
    ("content injection — no response",                             INFO, INFO),

    # Cookie specific attribute findings (not covered by earlier rules)
    ("cookie 'test_value' — secure",                                INFO, INFO),  # PASS
    ("cookie 'test_value' — __host- prefix violation",              MEDIUM, LOW),
    ("cookie 'test_value' — __host- prefix",                        INFO, INFO),  # PASS
    ("cookie 'test_value' — __secure- prefix violation",            MEDIUM, LOW),
    ("cookie 'test_value' — __secure- prefix",                      INFO, INFO),  # PASS
    ("cookie 'test_value' — expiry",                                LOW, LOW),

    # Cross-domain policy
    ("cross-domain policy — crossdomain.xml allows all origins (*)",  HIGH, HIGH),
    ("cross-domain policy — clientaccesspolicy.xml allows all",     HIGH, HIGH),
    ("cross-domain policy — crossdomain.xml allows http from https",MEDIUM, MEDIUM),
    ("cross-domain policy — crossdomain.xml allows headers from all",MEDIUM, MEDIUM),
    ("cross-domain policy — crossdomain.xml uses wildcard",         MEDIUM, LOW),
    ("cross-domain policy — crossdomain.xml present (review",       LOW, LOW),
    ("cross-domain policy — clientaccesspolicy.xml present (review",LOW, LOW),
    ("cross-domain policy — clientaccesspolicy.xml exposes all",    HIGH, HIGH),
    ("cross-domain policy — no permissive",                         INFO, INFO),
    ("cross-domain policy — target unreachable",                    INFO, INFO),

    # Dependency confusion
    ("dependency confusion — internal-looking package names",        HIGH, MEDIUM),
    ("dependency confusion — manifest exposed",                     MEDIUM, LOW),
    ("dependency confusion — no manifest files",                    INFO, INFO),
    ("dependency confusion — no response",                          INFO, INFO),

    # Deserialization
    ("deserialization — asp.net viewstate without mac",             CRITICAL, HIGH),
    ("deserialization — java serialized object in cookie",          CRITICAL, HIGH),
    ("deserialization — java serialized object in response",        CRITICAL, HIGH),
    ("deserialization — java serialization library in error",       HIGH, MEDIUM),
    ("deserialization — php serialized object in cookie",           HIGH, MEDIUM),
    ("deserialization — php serialized object in form",             HIGH, MEDIUM),
    ("deserialization — python pickle",                             HIGH, MEDIUM),
    ("deserialization — node-serialize pattern",                    HIGH, MEDIUM),
    ("deserialization — no insecure deserialization",               INFO, INFO),

    # Developer artifact
    ("developer artifact — exposed",                                HIGH, HIGH),
    ("developer artifact — no sensitive developer files",           INFO, INFO),
    ("developer artifact — target unreachable",                     INFO, INFO),

    # EL injection
    ("el injection — spel",                                         CRITICAL, HIGH),
    ("el injection — ognl",                                         CRITICAL, HIGH),
    ("el injection — spring4shell",                                 CRITICAL, HIGH),
    ("el injection — apache commons jexl",                          HIGH, MEDIUM),
    ("el injection — thymeleaf",                                    HIGH, MEDIUM),
    ("el injection — struts2 debug",                                HIGH, MEDIUM),
    ("el injection — struts2",                                      HIGH, MEDIUM),
    ("el injection — potentially vulnerable spring",                HIGH, MEDIUM),
    ("el injection — potentially vulnerable struts2",               HIGH, MEDIUM),
    ("el injection — unprocessed",                                  MEDIUM, LOW),
    ("el injection — spring boot whitelabel",                       LOW, LOW),
    ("el injection — no expression language",                       INFO, INFO),
    ("el injection — target unreachable",                           INFO, INFO),

    # Exposed file
    ("exposed file — test_value",                                   HIGH, HIGH),

    # Fetch Metadata
    ("fetch metadata — api endpoint accepts cross-site",            HIGH, MEDIUM),
    ("fetch metadata — form action endpoint accepts cross-site",    HIGH, MEDIUM),
    ("fetch metadata — missing cross-origin-embedder-policy",       MEDIUM, LOW),
    ("fetch metadata — missing cross-origin-opener-policy",         MEDIUM, LOW),
    ("fetch metadata — unusual cross-origin-opener-policy",         LOW, LOW),
    ("fetch metadata — coop/coep/corp headers present",             INFO, INFO),
    ("fetch metadata — target unreachable",                         INFO, INFO),

    # File inclusion
    ("file inclusion — lfi confirmed",                              CRITICAL, HIGH),
    ("/etc/passwd",                                                 CRITICAL, HIGH),
    ("win.ini content via",                                         CRITICAL, HIGH),
    ("php filter wrapper accepted",                                 HIGH, MEDIUM),
    ("php include error reveals",                                   HIGH, MEDIUM),
    ("file inclusion — no file-path parameters",                    INFO, INFO),
    ("file inclusion — no indicators",                              INFO, INFO),
    ("file inclusion — no response",                                INFO, INFO),

    # File upload
    ("file upload — http put method enabled",                       HIGH, MEDIUM),
    ("file upload — dangerous mime types",                          HIGH, MEDIUM),
    ("file upload — wildcard accept (*/*)",                         HIGH, MEDIUM),
    ("file upload — no csrf token on upload",                       MEDIUM, LOW),
    ("file upload — no content-type restriction",                   MEDIUM, LOW),
    ("file upload — server-side upload path disclosed",             MEDIUM, LOW),
    ("file upload — server file path in content-disposition",       MEDIUM, LOW),
    ("file upload — no upload forms",                               INFO, INFO),

    # Framework config
    ("framework config — publicly accessible",                      HIGH, HIGH),
    ("framework admin endpoints — none exposed",                    INFO, INFO),
    ("framework config — no configuration files",                   INFO, INFO),
    ("framework config — target unreachable",                       INFO, INFO),

    # GraphQL Advanced / depth / field suggestion
    ("graphql advanced — introspection enabled in production",      HIGH, HIGH),
    ("graphql advanced — ide/playground exposed in production",     HIGH, HIGH),
    ("graphql advanced — ide exposed",                              HIGH, HIGH),
    ("graphql advanced — stack trace in error",                     HIGH, MEDIUM),
    ("graphql advanced — query batching enabled",                   MEDIUM, LOW),
    ("graphql advanced — sensitive field name in schema",           MEDIUM, LOW),
    ("graphql advanced — no issues detected",                       INFO, INFO),
    ("graphql alias amplification",                                 MEDIUM, LOW),
    ("graphql depth limiting — deep query accepted without limit",  MEDIUM, LOW),
    ("graphql depth limiting — enforced",                           INFO, INFO),
    ("graphql depth limiting — no endpoint detected",               INFO, INFO),
    ("graphql depth limiting — no issues detected",                 INFO, INFO),
    ("graphql depth limiting — no response",                        INFO, INFO),
    ("graphql field suggestion — schema enumerable via error",      HIGH, MEDIUM),
    ("graphql field suggestion — stack trace or file paths",        HIGH, MEDIUM),
    ("graphql field suggestion — internal type names",              MEDIUM, LOW),
    ("graphql field suggestion — no schema enumeration",            INFO, INFO),
    ("graphql field suggestion — target unreachable",               INFO, INFO),
    ("graphql — introspection enabled",                             HIGH, HIGH),
    ("graphql — no endpoint detected",                              INFO, INFO),

    # HTTP Parameter Pollution
    ("http parameter pollution — array notation",                   MEDIUM, LOW),
    ("http parameter pollution — no issues",                        INFO, INFO),
    ("http parameter pollution — no response",                      INFO, INFO),

    # HTTP verb tampering
    ("http verb tampering — trace method enabled",                  MEDIUM, MEDIUM),
    ("http verb tampering — debug method enabled",                  HIGH, MEDIUM),
    ("http verb tampering — arbitrary method",                      MEDIUM, LOW),
    ("http verb tampering — delete override accepted",              MEDIUM, LOW),
    ("http verb tampering — no issues",                             INFO, INFO),
    ("http verb tampering — no response",                           INFO, INFO),

    # HTTP/2
    ("http/2 — server version potentially vulnerable",              HIGH, HIGH),
    ("http/2 — http/2 detected without rate limiting",              MEDIUM, LOW),
    ("http/2 — h2c (cleartext",                                     LOW, LOW),
    ("http/2 — alt-svc protocol advertisement",                     LOW, LOW),
    ("http/2 — no http/2 security issues",                          INFO, INFO),

    # IDOR
    ("idor — adjacent api resource",                                HIGH, HIGH),
    ("idor — parameter",                                            HIGH, HIGH),
    ("idor — no indicators",                                        INFO, INFO),
    ("idor — no response",                                          INFO, INFO),

    # Info disclosure
    ("info disclosure",                                             MEDIUM, LOW),

    # JS file analysis
    ("js file analysis — postmessage listener without origin",      HIGH, MEDIUM),
    ("js file analysis — fetch with credentials to cross-origin",   HIGH, MEDIUM),
    ("js file analysis — dom sink:",                                HIGH, MEDIUM),
    ("js file analysis — prototype pollution pattern",              HIGH, MEDIUM),
    ("js file analysis — document.domain relaxation",               MEDIUM, LOW),
    ("js file analysis — no dangerous dom sink",                    INFO, INFO),
    ("js file analysis — no same-origin js files",                  INFO, INFO),
    ("js file analysis — target unreachable",                       INFO, INFO),

    # JSON injection
    ("json injection — parameter",                                  HIGH, MEDIUM),
    ("json injection — html/js injection",                          MEDIUM, LOW),
    ("json injection — jsonp callback parameter not validated",      MEDIUM, LOW),
    ("json injection — json-like data in html event handler",       MEDIUM, LOW),
    ("json injection — __proto__",                                  MEDIUM, LOW),
    ("json injection — unescaped html tags in json",                MEDIUM, LOW),
    ("json injection — no vulnerabilities",                         INFO, INFO),
    ("json injection — target unreachable",                         INFO, INFO),

    # JWT Advanced
    ("jwt advanced — jwt token in url",                             HIGH, HIGH),
    ("jwt advanced — www-authenticate bearer realm uses http",      MEDIUM, LOW),
    ("jwt advanced — no jwt security issues",                       INFO, INFO),
    ("jwt advanced — no issues detected",                           INFO, INFO),

    # K8s
    ("k8s — kubernetes api response on main url",                   CRITICAL, HIGH),
    ("k8s — accessible",                                            HIGH, HIGH),
    ("k8s — no exposed",                                            INFO, INFO),

    # LDAP injection
    ("ldap injection — authentication bypass",                      CRITICAL, HIGH),
    ("ldap injection — ldap error triggered by metacharacter",      HIGH, MEDIUM),
    ("ldap injection — ldap error message leaked",                  HIGH, MEDIUM),
    ("ldap injection — no indicators",                              INFO, INFO),
    ("ldap injection — no login form",                              INFO, INFO),
    ("ldap injection — no response",                                INFO, INFO),

    # LLM prompt injection
    ("llm prompt injection — accessible llm api endpoint",          HIGH, HIGH),
    ("llm prompt injection — llm error response leaks",             HIGH, MEDIUM),
    ("llm prompt injection — html form action targeting chat",      MEDIUM, LOW),
    ("llm prompt injection — chat widget detected",                 LOW, LOW),
    ("llm prompt injection — no exposed llm endpoint",              INFO, INFO),
    ("llm prompt injection — target unreachable",                   INFO, INFO),

    # Link security
    ("link security — target='_blank' links missing",               MEDIUM, LOW),
    ("link security — window.open('_blank')",                       MEDIUM, LOW),
    ("link security — external iframe embedded without sandbox",    MEDIUM, LOW),
    ("link security — dns-prefetch/preconnect to tracking",         LOW, LOW),
    ("link security — no opener hijacking",                         INFO, INFO),
    ("link security — target unreachable",                          INFO, INFO),

    # Log injection
    ("log injection — log4shell jndi",                              CRITICAL, HIGH),
    ("log injection — crlf in test_value injects response headers", HIGH, HIGH),
    ("log injection — response splitting",                          HIGH, HIGH),
    ("log injection — value reflected in response body",            MEDIUM, LOW),
    ("log injection — crlf payload",                                HIGH, MEDIUM),
    ("log injection — no reflection detected",                      INFO, INFO),
    ("log injection — no response",                                 INFO, INFO),

    # Login — remaining
    ("login — form uses get",                                       MEDIUM, LOW),
    ("login — no account lockout signal",                           MEDIUM, LOW),
    ("login — form submits over http",                              HIGH, MEDIUM),

    # Management endpoint
    ("management endpoint accessible",                              HIGH, HIGH),

    # Mass assignment
    ("mass assignment — privileged fields accepted",                HIGH, HIGH),
    ("mass assignment — privileged field",                          HIGH, HIGH),
    ("mass assignment — no indicators",                             INFO, INFO),
    ("mass assignment — no response",                               INFO, INFO),

    # Mobile deep link
    ("mobile deep link — assetlinks.json missing sha-256",          MEDIUM, LOW),
    ("mobile deep link — assetlinks.json discloses",                LOW, LOW),
    ("mobile deep link — apple-app-site-association discloses",     LOW, LOW),
    ("mobile deep link — assetlinks.json present",                  INFO, INFO),
    ("mobile deep link — apple-app-site-association present",       INFO, INFO),

    # NoSQL injection
    ("nosql injection — couchdb admin api exposed",                 CRITICAL, HIGH),
    ("nosql injection — mongodb operator in url",                   HIGH, HIGH),
    ("nosql injection — mongodb operator in form",                  HIGH, HIGH),
    ("nosql injection — database error message exposed",            HIGH, MEDIUM),
    ("nosql injection — no indicators",                             INFO, INFO),

    # OAuth Advanced / OAuth
    ("oauth — client_secret hardcoded",                             CRITICAL, HIGH),
    ("oauth — state parameter missing",                             HIGH, MEDIUM),
    ("oauth — implicit flow in use",                                HIGH, MEDIUM),
    ("oauth — open or localhost redirect_uri",                      MEDIUM, LOW),
    ("oauth — token in url fragment",                               MEDIUM, LOW),
    ("oauth advanced — authorization code flow without pkce",       HIGH, MEDIUM),
    ("oauth advanced — oidc flow missing nonce",                    HIGH, MEDIUM),
    ("oauth advanced — pkce uses plain method",                     MEDIUM, LOW),
    ("oauth advanced — dynamic client registration endpoint",       MEDIUM, LOW),
    ("oauth advanced — over-privileged scope",                      MEDIUM, LOW),
    ("oauth advanced — device authorization flow endpoint",         MEDIUM, LOW),
    ("oauth advanced — no authorization code flows",                INFO, INFO),
    ("oauth advanced — no issues detected",                         INFO, INFO),
    ("oauth advanced — no response",                                INFO, INFO),
    ("oauth/oidc — discovery endpoint exposed",                     LOW, LOW),
    ("oauth/oidc — no flows detected",                              INFO, INFO),
    ("oauth/oidc — no obvious",                                     INFO, INFO),

    # Open ports — generic
    ("open ports — test_value/test_value",                          MEDIUM, LOW),

    # OpenAPI exposure
    ("openapi exposure — potential secret/api key in spec",         CRITICAL, HIGH),
    ("openapi exposure — api documentation ui accessible without auth", HIGH, HIGH),
    ("openapi exposure — internal/staging server url",              HIGH, MEDIUM),
    ("openapi exposure — machine-readable api spec accessible",     MEDIUM, LOW),
    ("openapi exposure — multiple api versions documented",         MEDIUM, LOW),
    ("openapi exposure — documentation endpoints found but protected", LOW, LOW),
    ("openapi exposure — no documentation endpoints found",         INFO, INFO),
    ("openapi exposure — no response",                              INFO, INFO),

    # Password reset
    ("password reset — weak/short reset token",                     CRITICAL, HIGH),
    ("password reset — reset token exposed in url",                 HIGH, HIGH),
    ("password reset — host header usage for reset link",           HIGH, MEDIUM),
    ("password reset — no csrf protection on reset",                HIGH, MEDIUM),
    ("password reset — user enumeration via different error",       MEDIUM, LOW),
    ("password reset — form uses get method",                       MEDIUM, LOW),
    ("password reset — no reset flow",                              INFO, INFO),
    ("password reset — target unreachable",                         INFO, INFO),

    # Path confusion
    ("path confusion — access control bypass",                      HIGH, HIGH),
    ("path confusion — spring boot actuator bypass",                HIGH, HIGH),
    ("path confusion — no url normalization bypass",                INFO, INFO),
    ("path confusion — target unreachable",                         INFO, INFO),

    # Path traversal
    ("path traversal — traversal sequence in parameter",            HIGH, MEDIUM),
    ("path traversal — high-risk file/path parameter name",         MEDIUM, LOW),
    ("path traversal — medium-risk directory/path parameter",       LOW, LOW),
    ("path traversal — no lfi/traversal parameters",                INFO, INFO),

    # Prototype pollution
    ("prototype pollution — vulnerable library version",            HIGH, MEDIUM),
    ("prototype pollution — direct __proto__ assignment",           HIGH, MEDIUM),
    ("prototype pollution — unsafe merge pattern",                  HIGH, MEDIUM),
    ("prototype pollution — eval() with string concatenation",      HIGH, MEDIUM),
    ("prototype pollution — no indicators",                         INFO, INFO),
    ("prototype pollution — no external js",                        INFO, INFO),

    # RFD
    ("rfd — executable file extension in content-disposition",      HIGH, HIGH),
    ("rfd — probe value reflected as executable filename",          HIGH, HIGH),
    ("rfd — user-controlled executable filename",                   HIGH, HIGH),
    ("rfd — jsonp callback reflected in attachment",                HIGH, MEDIUM),
    ("rfd — script-like content prefix in downloadable",            MEDIUM, LOW),
    ("rfd — user-controlled filename",                              MEDIUM, LOW),
    ("rfd — no reflected file download",                            INFO, INFO),
    ("rfd — target unreachable",                                    INFO, INFO),

    # Race condition
    ("race condition — token/coupon redemption endpoint lacks idempotency",   HIGH, HIGH),
    ("race condition — endpoint lacks idempotency protection",      HIGH, MEDIUM),
    ("race condition — high-risk post endpoint lacks",              HIGH, MEDIUM),
    ("race condition — high-risk endpoint lacks",                   HIGH, MEDIUM),
    ("race condition — numeric amount endpoint, verify",            MEDIUM, LOW),
    ("race condition — endpoint, verify atomic",                    MEDIUM, LOW),
    ("race condition — idempotency key header supported",           INFO, INFO),
    ("race condition — no toctou-vulnerable",                       INFO, INFO),
    ("race condition — protection present",                         INFO, INFO),
    ("race condition — target unreachable",                         INFO, INFO),

    # Request smuggling
    ("request smuggling — server accepts ambiguous transfer-encoding", HIGH, HIGH),
    ("request smuggling — dual cl+te",                              HIGH, HIGH),
    ("request smuggling — suspicious transfer-encoding",            HIGH, MEDIUM),
    ("request smuggling — potentially vulnerable server version",   HIGH, MEDIUM),
    ("request smuggling — multi-hop proxy chain",                   MEDIUM, LOW),
    ("request smuggling — no indicators",                           INFO, INFO),

    # SAML
    ("saml — sso flow over unencrypted http",                       HIGH, HIGH),
    ("saml — assertion visible in page source",                     HIGH, MEDIUM),
    ("saml — sso endpoint found",                                   LOW, LOW),
    ("saml — metadata endpoint exposed",                            LOW, LOW),
    ("saml/sso — no saml flows",                                    INFO, INFO),
    ("saml/sso — no obvious",                                       INFO, INFO),

    # SCIM
    ("scim — exposed without authentication",                       HIGH, HIGH),
    ("scim — accessible (auth required)",                           MEDIUM, LOW),
    ("scim/idm — no exposed",                                       INFO, INFO),

    # SSRF Advanced / SSRF
    ("ssrf advanced — ssrf-prone query parameters",                 HIGH, HIGH),
    ("ssrf advanced — url-accepting form parameters",               HIGH, HIGH),
    ("ssrf advanced — xml content type accepted",                   HIGH, MEDIUM),
    ("ssrf advanced — import/webhook endpoint accessible",          HIGH, MEDIUM),
    ("ssrf advanced — private ip addresses in response",            HIGH, HIGH),
    ("ssrf advanced — no ssrf-prone patterns",                      INFO, INFO),
    ("ssrf advanced — no response",                                 INFO, INFO),
    ("ssrf — cloud metadata endpoint accessible via",               CRITICAL, HIGH),
    ("ssrf — high-risk parameter names present",                    HIGH, MEDIUM),
    ("ssrf — internal connection error via",                        HIGH, MEDIUM),
    ("ssrf — moderate-risk parameter names present",                MEDIUM, LOW),
    ("ssrf — parameter already carries url value",                  LOW, LOW),
    ("ssrf — no url-accepting parameters",                          INFO, INFO),
    ("ssrf — no high-risk parameters",                              INFO, INFO),
    ("ssrf — no indicators",                                        INFO, INFO),
    ("ssrf — no response",                                          INFO, INFO),

    # SSTI (additional)
    ("ssti — werkzeug interactive debugger",                        CRITICAL, HIGH),
    ("ssti — template engine version disclosed",                    MEDIUM, LOW),
    ("ssti — template syntax visible in page source",               MEDIUM, LOW),
    ("ssti — template engine error exposed",                        HIGH, MEDIUM),
    ("ssti — test_value",                                           HIGH, HIGH),

    # Sensitive data exposure
    ("sensitive data exposure — pii parameter",                     HIGH, HIGH),
    ("sensitive data exposure — credential parameter",              HIGH, HIGH),
    ("sensitive data exposure — session token",                     HIGH, HIGH),
    ("sensitive data exposure — credential",                        HIGH, HIGH),
    ("sensitive data exposure — internal path in header",           MEDIUM, LOW),
    ("sensitive data exposure — email address in html comment",     LOW, LOW),
    ("sensitive data exposure — password field without autocomplete",LOW, LOW),
    ("sensitive data exposure — no issues",                         INFO, INFO),
    ("sensitive data exposure — no response",                       INFO, INFO),

    # Server-Timing
    ("server-timing — sensitive information disclosed",             HIGH, MEDIUM),
    ("server-timing — header present (review",                      LOW, LOW),
    ("server-timing — no sensitive information disclosed",          INFO, INFO),
    ("server-timing — target unreachable",                          INFO, INFO),

    # Service worker security
    ("service worker — pwa manifest start_url uses insecure http",  MEDIUM, LOW),
    ("service worker — root scope '/' intercepts all requests",     MEDIUM, LOW),
    ("service worker — pwa manifest scope='/' covers entire origin",MEDIUM, LOW),
    ("service worker — fetch interception without",                 LOW, LOW),
    ("service worker security — no issues",                         INFO, INFO),
    ("service worker security — no response",                       INFO, INFO),

    # Session management
    ("session management — session id in url",                      HIGH, HIGH),
    ("session management — predictable/weak session id",            HIGH, HIGH),
    ("session management — login form uses get method",             MEDIUM, LOW),
    ("session management — no logout mechanism found",              MEDIUM, LOW),
    ("session management — remember-me cookie without expiry",      LOW, LOW),
    ("session management — remember-me feature detected",           LOW, LOW),
    ("session management — no issues detected",                     INFO, INFO),

    # Version CVE
    ("version cve — has known",                                     HIGH, HIGH),
    ("version cve — software version banners exposed",              LOW, LOW),
    ("version cve — no version banners exposed",                    INFO, INFO),
    ("version cve — target unreachable",                            INFO, INFO),

    # Weak crypto
    ("weak crypto — http digest authentication uses md5",           HIGH, MEDIUM),
    ("weak crypto — md5-based etag",                                MEDIUM, LOW),
    ("weak crypto — md5-length token",                              MEDIUM, LOW),
    ("weak crypto — weak cipher referenced",                        MEDIUM, LOW),
    ("weak crypto — low-entropy session/token",                     MEDIUM, LOW),
    ("weak crypto — no response",                                   INFO, INFO),
    ("weak crypto — no weak algorithms",                            INFO, INFO),

    # Web cache deception
    ("web cache deception — cache hit on sensitive",                HIGH, HIGH),
    ("web cache deception — cacheable response on authenticated",   HIGH, HIGH),
    ("web cache deception — dynamic content cached at static url",  HIGH, HIGH),
    ("web cache deception — no indicators",                         INFO, INFO),

    # WebAuthn
    ("webauthn — rpid contains wildcard",                           HIGH, MEDIUM),
    ("webauthn — sms otp fallback alongside passkey",               MEDIUM, LOW),
    ("webauthn — http magic link used as auth fallback",            MEDIUM, LOW),
    ("webauthn — passkey ui present but autocomplete",              LOW, LOW),
    ("webauthn — /.well-known/webauthn returns unexpected",         LOW, LOW),
    ("webauthn — /.well-known/webauthn discovery endpoint",         INFO, INFO),
    ("webauthn — conditional ui",                                   INFO, INFO),
    ("webauthn — not implemented",                                  INFO, INFO),
    ("webauthn security — target unreachable",                      INFO, INFO),

    # WebSocket
    ("websocket — endpoint reachable without authentication",       HIGH, HIGH),
    ("websocket — unencrypted ws:// endpoint",                      HIGH, MEDIUM),
    ("websocket — wildcard origin accepted",                        HIGH, MEDIUM),
    ("websocket — no issues detected",                              INFO, INFO),

    # XML endpoint
    ("xml endpoint — wsdl/soap service exposed",                    HIGH, HIGH),
    ("xml endpoint — parser error message exposed",                 MEDIUM, LOW),
    ("xml endpoint — doctype/dtd reference",                        MEDIUM, LOW),
    ("xml endpoint — soap/xml service indicators",                  LOW, LOW),
    ("xml endpoint — form with xml mime type",                      LOW, LOW),
    ("xml endpoint — page served as test_value",                    LOW, LOW),
    ("xml/xxe — no xml endpoints",                                  INFO, INFO),

    # XSLeak
    ("xsleak — timing-allow-origin: * exposes",                     HIGH, MEDIUM),
    ("xsleak — cross-origin-opener-policy set to unsafe",           MEDIUM, LOW),
    ("xsleak — authenticated page missing vary: cookie",            MEDIUM, LOW),
    ("xsleak — cross-origin-embedder-policy (coep) missing",        MEDIUM, LOW),
    ("xsleak — cross-origin-opener-policy (coop) missing",          MEDIUM, LOW),
    ("xsleak — cross-origin-resource-policy (corp) missing",        MEDIUM, LOW),
    ("xsleak — cross-site leak mitigations in place",               INFO, INFO),
    ("xsleak — target unreachable",                                 INFO, INFO),

    # XSSI
    ("xssi — json array response missing anti-xssi prefix",        HIGH, MEDIUM),
    ("xssi — json response missing application/json",               MEDIUM, LOW),
    ("xssi — no cross-site script inclusion",                       INFO, INFO),
    ("xssi — target unreachable",                                   INFO, INFO),

    # XXE injection
    ("xxe injection — disclosed via external entity",               CRITICAL, HIGH),
    ("xxe injection — xml parser error suggests",                   HIGH, MEDIUM),
    ("xxe injection — dtd processing attempted",                    HIGH, MEDIUM),
    ("xxe injection — no xml-accepting endpoint",                   INFO, INFO),
    ("xxe injection — no indicators",                               INFO, INFO),
    ("xxe injection — no response",                                 INFO, INFO),

    # gRPC
    ("grpc — reflection api exposed",                               HIGH, HIGH),
    ("grpc — endpoint found at",                                    MEDIUM, LOW),
    ("grpc — grpc content type on main",                            LOW, LOW),
    ("grpc — grpc protocol headers detected",                       LOW, LOW),
    ("grpc — health check endpoint accessible",                     LOW, LOW),
    ("grpc — no grpc endpoints",                                    INFO, INFO),

    # Cache poisoning
    ("cache poisoning — reflected unkeyed header",                  HIGH, HIGH),
    ("cache poisoning — unkeyed header reflected in response",      HIGH, HIGH),
    ("cache poisoning — cacheable response with no vary",           MEDIUM, LOW),

    # CRLF injection
    ("crlf injection — response splitting",                         HIGH, HIGH),
    ("crlf injection — marker reflected in response body",          HIGH, HIGH),
    ("crlf injection — no injection points",                        INFO, INFO),
    ("crlf injection — no response",                                INFO, INFO),

    # Clickjacking remaining
    ("clickjacking — page has no framing protection",               MEDIUM, MEDIUM),
    ("clickjacking — sensitive page frameable",                     MEDIUM, MEDIUM),
    ("clickjacking — only javascript frame-busting",                LOW, LOW),
    ("clickjacking — no response",                                  INFO, INFO),
    ("clickjacking — page is protected against framing",            INFO, INFO),

    # DOM
    ("dom — external scripts without sri",                          MEDIUM, LOW),
    ("dom — external scripts sri",                                  INFO, INFO),

    # Certificate Transparency
    ("certificate transparency — subdomains found in ct logs",      LOW, LOW),
    ("certificate transparency — no additional subdomains",         INFO, INFO),

    # Rate limiting remaining
    ("rate limiting — missing on sensitive endpoints",              HIGH, MEDIUM),
    ("rate limiting — missing on some sensitive endpoints",         MEDIUM, LOW),
    ("rate limiting — no rate limit headers",                       MEDIUM, LOW),
    ("rate limiting — headers and controls detected",               INFO, INFO),
    ("rate limiting — headers present on main",                     INFO, INFO),
    ("rate limiting — no response from target",                     INFO, INFO),
    ("rate limiting — enforced",                                    INFO, INFO),
    ("rate limiting — not detected",                                MEDIUM, LOW),

    # Redirect chain
    ("redirect chain — redirect loop",                              MEDIUM, MEDIUM),
    ("redirect chain — excessive redirects",                        LOW, LOW),
    ("redirect chain — many redirects",                             LOW, LOW),
    ("redirect chain — https throughout",                           INFO, INFO),
    ("redirect chain — redirect hop(s) (acceptable)",               INFO, INFO),
    ("redirect chain — test_value redirect hop",                    INFO, INFO),

    # GDPR remaining
    ("gdpr — cookies set on first load before consent",             HIGH, MEDIUM),
    ("gdpr — no privacy policy link",                               MEDIUM, LOW),
    ("gdpr — no tracking scripts detected",                         INFO, INFO),
    ("gdpr — no tracking cookies",                                  INFO, INFO),
    ("gdpr — privacy policy link present",                          INFO, INFO),
    ("gdpr — cookie consent management platform",                   INFO, INFO),
    ("gdpr — tracking cookies with consent ui",                     INFO, INFO),

    # Email advanced / Email
    ("email — spf allows all senders (+all)",                       HIGH, MEDIUM),
    ("email — spf lookup limit exceeded",                           MEDIUM, LOW),
    ("email — spf approaching lookup limit",                        LOW, LOW),
    ("email — spf neutral (?all)",                                  MEDIUM, LOW),
    ("email — spf strict (-all)",                                   INFO, INFO),
    ("email — dmarc fully enforced (p=reject)",                     INFO, INFO),
    ("email — dmarc p=quarantine",                                  LOW, LOW),
    ("email — dmarc partial enforcement",                           MEDIUM, LOW),
    ("email — dmarc subdomain policy not set",                      LOW, LOW),
    ("email — mta-sts not configured",                              LOW, LOW),
    ("email — mta-sts policy file unreachable",                     LOW, LOW),
    ("email — mta-sts configured",                                  INFO, INFO),
    ("email — tls-rpt not configured",                              LOW, LOW),
    ("email — tls-rpt configured",                                  INFO, INFO),
    ("email — dane/tlsa not configured",                            LOW, LOW),
    ("email — dane/tlsa configured",                                INFO, INFO),
    ("email — bimi not configured",                                 LOW, LOW),
    ("email — bimi configured",                                     INFO, INFO),

    # TLS deep remaining
    ("tls — md5 certificate signature",                             HIGH, HIGH),
    ("tls — sha-1 certificate signature",                           HIGH, MEDIUM),
    ("tls — certificate expired",                                   HIGH, HIGH),
    ("tls — certificate expiring imminently",                       HIGH, MEDIUM),
    ("tls — certificate expiring soon",                             MEDIUM, MEDIUM),
    ("tls — certificate expiry",                                    LOW, LOW),
    ("tls — hsts not preload-ready",                                LOW, LOW),
    ("tls — hsts preload ready",                                    INFO, INFO),
    ("tls — no forward secrecy",                                    HIGH, MEDIUM),
    ("tls — forward secrecy",                                       INFO, INFO),
    ("tls — weak ec key size",                                      HIGH, MEDIUM),
    ("tls — key size",                                              LOW, LOW),
    ("tls — certificate signature algorithm",                       LOW, LOW),

    # SSL remaining
    ("ssl — certificate expiry",                                    MEDIUM, MEDIUM),
    ("ssl — self-signed certificate",                               HIGH, HIGH),
    ("ssl — certificate chain invalid",                             HIGH, HIGH),
    ("ssl — certificate authority",                                 MEDIUM, LOW),
    ("ssl — sans mismatch",                                         HIGH, HIGH),
    ("ssl — sans coverage",                                         LOW, LOW),
    ("ssl — no subject alternative names",                          MEDIUM, MEDIUM),
    ("ssl — tls version",                                           MEDIUM, LOW),

    # Access control remaining
    ("access control — admin interface exposure",                   MEDIUM, LOW),

    # CMS detection
    ("cms detection — not identified",                              INFO, INFO),
    ("cms — test_value detected",                                   INFO, INFO),
    ("cms — test_value test_value detected",                        INFO, INFO),

    # Permissions-Policy remaining
    ("permissions-policy header missing",                           LOW, LOW),
    ("permissions-policy — test_value allowed for all",             LOW, LOW),
    ("permissions-policy — test_value not restricted",              LOW, LOW),
    ("permissions-policy — test_value partially restricted",        INFO, INFO),
    ("permissions-policy — test_value blocked",                     INFO, INFO),
    ("permissions-policy — test_value restricted to self",          INFO, INFO),
    ("permissions-policy — configured",                             INFO, INFO),
    ("permissions-policy — header absent",                          LOW, LOW),
    ("permissions-policy — only deprecated feature-policy",        LOW, LOW),

    # Response header
    ("response header — etag may disclose inode number",            LOW, LOW),
    ("response header — deprecated header present",                 LOW, LOW),
    ("response header — dns prefetch disabled",                     INFO, INFO),
    ("response header — x-dns-prefetch-control not set",            INFO, INFO),
    ("response header — x-xss-protection: 0 (correct)",            INFO, INFO),

    # Sensitive URL parameters
    ("sensitive url parameter — test_value",                        MEDIUM, LOW),
    ("sensitive url parameters — none detected",                    INFO, INFO),
    ("sensitive url parameter —",                                   MEDIUM, LOW),

    # SCA
    ("sca — no known vulnerabilities",                              INFO, INFO),
    ("sca — vulnerable dependencies in",                            HIGH, HIGH),

    # SRI advanced
    ("sri advanced — integrity= without crossorigin",               MEDIUM, LOW),
    ("sri advanced — 100% coverage",                                INFO, INFO),
    ("sri — all external resources have integrity",                 INFO, INFO),
    ("sri — no external resources",                                 INFO, INFO),

    # Subdomain surface
    ("subdomain surface — active subdomains found",                 LOW, LOW),
    ("subdomain surface — no common subdomains exposed",            INFO, INFO),

    # Supply chain
    ("supply chain — no known trackers detected",                   INFO, INFO),
    ("supply chain — no third-party resources",                     INFO, INFO),

    # Threat intelligence
    ("threat intelligence — virustotal:",                           HIGH, HIGH),
    ("threat intelligence — no api keys configured",                INFO, INFO),

    # WAF/CDN
    ("waf/cdn — none detected",                                     LOW, LOW),
    ("waf/cdn — test_value detected",                               INFO, INFO),

    # COEP / COOP / CORP headers present (positive)
    ("coep — cross-origin-embedder-policy set",                     INFO, INFO),
    ("coop — cross-origin-opener-policy set",                       INFO, INFO),
    ("corp — cross-origin-resource-policy set",                     INFO, INFO),
    ("coep header missing",                                         MEDIUM, LOW),
    ("coop header missing",                                         MEDIUM, LOW),
    ("corp header missing",                                         MEDIUM, LOW),

    # CORS — policy (general)
    ("cors — policy",                                               MEDIUM, LOW),

    # CSP advanced positive findings
    ("csp advanced — trusted types enforced",                       INFO, INFO),
    ("csp advanced — base-uri restriction configured",              INFO, INFO),
    ("csp advanced — form-action restriction configured",           INFO, INFO),
    ("csp advanced — frame-ancestors 'none'",                       INFO, INFO),
    ("csp advanced — frame-ancestors 'self'",                       INFO, INFO),
    ("csp advanced — frame-ancestors allows specific",              INFO, INFO),
    ("csp advanced — upgrade-insecure-requests configured",         INFO, INFO),
    ("csp advanced — violation reporting configured",               INFO, INFO),

    # Error page info disclosure
    ("error page — information disclosure",                         LOW, LOW),

    # HTML comments pass
    ("html comments — no sensitive data",                           INFO, INFO),
    ("html comment — test_value",                                   MEDIUM, LOW),

    # HTTP methods general
    ("http methods",                                                MEDIUM, LOW),

    # JS libraries
    ("js libraries — no detectable versions",                       INFO, INFO),
    ("js libraries — versions appear current",                      INFO, INFO),
    ("js secrets — none detected",                                  INFO, INFO),

    # JWT security pass findings
    ("jwt security — algorithm and expiry",                         INFO, INFO),
    ("jwt security — no tokens detected",                           INFO, INFO),

    # Open ports pass
    ("open ports — no dangerous ports exposed",                     INFO, INFO),

    # Robots.txt
    ("robots.txt — test_value sitemap(s) declared",                 INFO, INFO),
    ("robots.txt",                                                  LOW, LOW),

    # Security.txt
    ("security.txt — present and valid",                            INFO, INFO),
    ("security.txt — missing",                                      LOW, LOW),
    ("security.txt — incomplete",                                   LOW, LOW),

    # Typosquatting
    ("typosquatting — no registered lookalike domains",             INFO, INFO),

    # DNS
    ("dns — all nameservers from same provider",                    LOW, LOW),
    ("dns — nameservers are diverse",                               INFO, INFO),
    ("dns — single nameserver (no redundancy)",                     LOW, LOW),
    ("dns — dnssec enabled",                                        INFO, INFO),
    ("dns — caa record configured",                                 INFO, INFO),
    ("dns — caa records",                                           INFO, INFO),
    ("dnssec — configured",                                         INFO, INFO),

    # Cloud storage
    ("cloud storage — no public buckets detected",                  INFO, INFO),

    # Cookie advanced pass
    ("cookie advanced — all cookies pass",                          INFO, INFO),
    ("cookie advanced — no cookies set",                            INFO, INFO),

    # Response headers pass
    ("response headers — no version/technology disclosure",         INFO, INFO),

    # Form positive findings
    ("form — .well-known/change-password configured",               INFO, INFO),
    ("form — csrf tokens present",                                  INFO, INFO),
    ("form — password fields allow password managers",              INFO, INFO),
    ("form — sensitive page not cached",                            INFO, INFO),

    # Header reflection
    ("header reflection — test_value",                              MEDIUM, LOW),

    # Exposed files pass
    ("exposed files — none found",                                  INFO, INFO),

    # SRI pass
    ("sri — external resources without integrity hash",             MEDIUM, LOW),

    # Phase 57 — Catch-all rules for test_value-containing finding types
    # These use shorter prefixes that match regardless of the variable part
    ("ai api exposure — ",                                          HIGH, HIGH),
    ("api auth — '",                                                MEDIUM, LOW),
    ("api collection — test_value",                                 HIGH, HIGH),
    ("api versioning — deprecation header",                         INFO, INFO),
    ("ci/cd exposure — test_value",                                 HIGH, HIGH),
    ("ci/cd exposure — ",                                           HIGH, HIGH),
    ("unsafe-eval",                                                 HIGH, MEDIUM),
    ("unsafe-inline",                                               HIGH, MEDIUM),
    ("jsonp/angularjs bypass host",                                 HIGH, MEDIUM),
    ("data: uri in script-src",                                     HIGH, MEDIUM),
    ("wildcard (*) in script-src",                                  HIGH, MEDIUM),
    ("csv injection — csv response lacks content-disposition",      MEDIUM, LOW),
    ("csv injection — dde formula command",                         HIGH, HIGH),
    ("csv injection — unescaped formula-starting character",        HIGH, HIGH),
    ("csv injection — no formula injection",                        INFO, INFO),
    ("csv injection — target unreachable",                          INFO, INFO),
    ("dependency confusion — test_value manifest",                  MEDIUM, LOW),
    ("dependency confusion — internal-looking",                     HIGH, MEDIUM),
    ("developer artifact — test_value exposed",                     HIGH, HIGH),
    ("framework config — test_value",                               HIGH, HIGH),
    ("http verb tampering — 'test_value'",                          MEDIUM, LOW),
    ("http verb tampering — test_value:",                           MEDIUM, LOW),
    ("k8s — test_value accessible",                                 HIGH, HIGH),
    ("log injection — test_value value",                            MEDIUM, LOW),
    ("password reset — possible host header",                       HIGH, MEDIUM),
    ("race condition — test_value endpoint lacks idempotency",      HIGH, MEDIUM),
    ("race condition — test_value endpoint, verify",                MEDIUM, LOW),
    ("race condition — test_value protection on token",             HIGH, MEDIUM),
    ("race condition — test_value protection present",              INFO, INFO),
    ("scim — test_value exposed without",                           HIGH, HIGH),
    ("scim — test_value accessible",                                MEDIUM, LOW),
    ("version cve — test_value",                                    HIGH, HIGH),
    ("xxe injection — test_value disclosed",                        CRITICAL, HIGH),
]


def classify_severity(result_type: str, status: str) -> str:
    """Return severity level for a single result."""
    if status == "PASS":
        return INFO

    t = result_type.lower()
    for substring, on_fail, on_warn in _RULES:
        if substring in t:
            return on_fail if status == "FAIL" else on_warn

    # Default
    return MEDIUM if status == "FAIL" else LOW


def deduction_for(severity: str, status: str) -> int:
    """Return the point deduction for a (severity, status) pair."""
    return _DEDUCTIONS.get((severity, status), 0)


# ── Score dataclass ───────────────────────────────────────────────────────────

@dataclass
class ScanScore:
    score:      int                      # 0-100
    grade:      str                      # A+ … F
    breakdown:  Dict[str, int]           # counts per severity level
    deductions: Dict[str, int]           # points deducted per severity level
    top_issues: List[Dict[str, Any]]     # top findings, ordered by severity
    total_deducted: int


def _grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 65: return "B"
    if score >= 50: return "C"
    if score >= 30: return "D"
    return "F"


def score_results(all_results: Dict[str, List[Dict[str, Any]]]) -> ScanScore:
    """
    Analyse all scanner results, compute 0-100 score and severity breakdown.

    Args:
        all_results: dict mapping module name → list of result dicts

    Returns:
        ScanScore with score, grade, breakdown, deductions, and top issues
    """
    breakdown:  Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    deductions: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    annotated:  List[Dict[str, Any]] = []

    for module, results in all_results.items():
        for r in results:
            status   = r.get("status", "PASS")
            rtype    = r.get("type", "")
            severity = classify_severity(rtype, status)
            pts      = deduction_for(severity, status)

            enriched = {**r, "severity": severity, "deduction": pts, "module": module}
            annotated.append(enriched)

            if status != "PASS":
                breakdown[severity]  += 1
                deductions[severity] += pts

    total_deducted = sum(
        min(deductions[s], _SEVERITY_CAPS[s]) for s in SEVERITY_ORDER
    )
    final_score    = max(0, 100 - total_deducted)

    # Build prioritised top-issues list (critical first, then high, then medium)
    priority_map = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    issues = [
        r for r in annotated
        if r.get("status") in ("FAIL", "WARN") and r["severity"] in (CRITICAL, HIGH, MEDIUM)
    ]
    issues.sort(key=lambda r: (priority_map[r["severity"]], r.get("status") != "FAIL"))
    top_issues = issues[:8]

    return ScanScore(
        score          = final_score,
        grade          = _grade(final_score),
        breakdown      = breakdown,
        deductions     = deductions,
        top_issues     = top_issues,
        total_deducted = total_deducted,
    )
