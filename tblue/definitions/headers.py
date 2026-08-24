"""
Security header definitions, validators, and fix guidance.
Each header has a validate() function that returns a list of issues
found in the header's value. Empty list means the value looks good.
"""

SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "severity": "FAIL",
        "desc": "Prevents XSS by whitelisting trusted content sources",
        "fix": "Add a CSP header that defines trusted sources. Example: Content-Security-Policy: default-src 'self'",
        "validate": lambda v: (
            (["unsafe-inline weakens XSS protection"] if "unsafe-inline" in v else []) +
            (["unsafe-eval allows arbitrary JS execution"] if "unsafe-eval" in v else []) +
            (["Wildcard * allows any source"] if "* " in v or v.strip() == "*" else []) +
            (["Missing script-src or default-src directive"] if "default-src" not in v and "script-src" not in v else [])
        )
    },
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "severity": "FAIL",
        "desc": "Forces HTTPS connections — prevents protocol downgrade attacks",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "validate": lambda v: (
            (["max-age directive missing"] if "max-age" not in v else
             (["max-age should be at least 180 days (15552000)"]
              if int(v.split("max-age=")[1].split(";")[0].strip()) < 15552000 else [])) +
            (["includeSubDomains recommended"] if "includesubdomains" not in v.lower() else []) +
            (["preload recommended for full HSTS"] if "preload" not in v else [])
        )
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "severity": "FAIL",
        "desc": "Prevents clickjacking by blocking iframe embedding",
        "fix": "Add: X-Frame-Options: DENY (or SAMEORIGIN if you embed your own iframes)",
        "validate": lambda v: (
            [] if v.strip().upper() in ["DENY", "SAMEORIGIN"]
            else [f"Value '{v.strip()}' is not valid — use DENY or SAMEORIGIN"]
        )
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "severity": "FAIL",
        "desc": "Stops browsers from MIME-sniffing responses",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "validate": lambda v: (
            [] if v.strip().lower() == "nosniff"
            else ["Value must be 'nosniff'"]
        )
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "severity": "WARN",
        "desc": "Controls how much referrer information is sent with requests",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "validate": lambda v: (
            [] if v.strip().lower() in [
                "no-referrer",
                "no-referrer-when-downgrade",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "same-origin",
            ]
            else [f"Value '{v.strip()}' may leak referrer data to external sites"]
        )
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "severity": "WARN",
        "desc": "Controls access to browser features like camera, microphone, and location",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "validate": lambda v: (
            ["Wildcard * grants all origins access to sensitive browser features"]
            if "*" in v else []
        )
    },
    {
        "name": "X-XSS-Protection",
        "key": "x-xss-protection",
        "severity": "WARN",
        "desc": "Legacy XSS filter for older browsers — superseded by CSP",
        "fix": "Add: X-XSS-Protection: 1; mode=block",
        "validate": lambda v: (
            [] if v.strip() == "1; mode=block"
            else ["Recommended value is '1; mode=block'"]
        )
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "severity": "WARN",
        "desc": "Isolates your browsing context to prevent cross-origin attacks",
        "fix": "Add: Cross-Origin-Opener-Policy: same-origin",
        "validate": lambda v: (
            [] if v.strip().lower() == "same-origin"
            else ["Recommended value is 'same-origin'"]
        )
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "key": "cross-origin-embedder-policy",
        "severity": "WARN",
        "desc": "Prevents loading cross-origin resources without explicit permission",
        "fix": "Add: Cross-Origin-Embedder-Policy: require-corp",
        "validate": lambda v: (
            [] if v.strip().lower() == "require-corp"
            else ["Recommended value is 'require-corp'"]
        )
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "key": "cross-origin-resource-policy",
        "severity": "WARN",
        "desc": "Controls which sites can load your resources",
        "fix": "Add: Cross-Origin-Resource-Policy: same-site",
        "validate": lambda v: (
            [] if v.strip().lower() in ["same-site", "same-origin", "cross-origin"]
            else ["Value should be same-site, same-origin, or cross-origin"]
        )
    },
    {
        "name": "Cache-Control",
        "key": "cache-control",
        "severity": "WARN",
        "desc": "Controls caching of sensitive responses — important for authenticated pages and APIs",
        "fix": "Add: Cache-Control: no-store, no-cache for authenticated pages and API endpoints",
        "validate": lambda v: (
            [] if any(d in v.lower() for d in ("no-store", "private"))
            else ["Cache-Control should include no-store or private for sensitive pages and API endpoints"]
        )
    },
]

# Headers that should NOT be present (deprecated/harmful if set).
# Checked separately — absence is the correct state.
DEPRECATED_HEADERS = [
    {
        "name": "Feature-Policy",
        "key": "feature-policy",
        "desc": "Deprecated predecessor to Permissions-Policy — still recognised by some browsers",
        "fix": "Remove Feature-Policy and use Permissions-Policy: camera=(), microphone=(), geolocation=() instead",
    },
]
