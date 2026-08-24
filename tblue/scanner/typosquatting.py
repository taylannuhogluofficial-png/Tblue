"""
Typosquatting / lookalike domain detector.

Generates common typo variants of the target domain, resolves them via DNS,
and checks MX records. A typosquatted domain with an MX record means someone
has set up mail infrastructure — almost certainly for phishing.

All checks are DNS-only (no HTTP requests to suspicious domains).
No external API required.
"""

from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# Common TLD swaps
_ALTERNATIVE_TLDS = [
    "co", "net", "org", "io", "ai", "app", "dev",
    "info", "biz", "online", "site", "web", "us", "uk",
]

# Homoglyph substitutions (visually similar characters)
_HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["à", "á", "â", "ã", "ä", "å"],
    "e": ["è", "é", "ê", "ë"],
    "i": ["ì", "í", "î", "ï", "1", "l"],
    "o": ["ò", "ó", "ô", "õ", "ö", "0"],
    "u": ["ù", "ú", "û", "ü"],
    "l": ["1", "i"],
    "0": ["o"],
}

_MAX_VARIANTS = 200  # cap total variants to avoid absurd scan time


def _import_dns():
    try:
        import dns.resolver
        return dns.resolver
    except ImportError:
        return None


def _has_mx(resolver, domain: str) -> bool:
    try:
        resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False


def _resolves(resolver, domain: str) -> bool:
    try:
        resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def _split_domain(fqdn: str):
    """Split 'example.com' → ('example', 'com')."""
    parts = fqdn.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return fqdn, ""


def _generate_variants(name: str, tld: str) -> Set[str]:
    variants: Set[str] = set()

    # 1. Character omission
    for i in range(len(name)):
        variants.add(name[:i] + name[i + 1:] + "." + tld)

    # 2. Character transposition (swap adjacent)
    for i in range(len(name) - 1):
        t = list(name)
        t[i], t[i + 1] = t[i + 1], t[i]
        variants.add("".join(t) + "." + tld)

    # 3. Character doubling
    for i in range(len(name)):
        variants.add(name[:i] + name[i] + name[i:] + "." + tld)

    # 4. Adjacent keyboard substitutions (qwerty)
    keyboard = {
        "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg",
        "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
        "a": "qsz", "s": "awdx", "d": "sefc", "f": "drgv", "g": "ftbh",
        "h": "gynb", "j": "hkum", "k": "jlin", "l": "kop",
        "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
        "b": "vghn", "n": "bhjm", "m": "njk",
    }
    for i, ch in enumerate(name):
        for sub in keyboard.get(ch, ""):
            variants.add(name[:i] + sub + name[i + 1:] + "." + tld)

    # 5. TLD swap
    for alt_tld in _ALTERNATIVE_TLDS:
        if alt_tld != tld:
            variants.add(name + "." + alt_tld)

    # 6. Common prefix/suffix tricks
    for pfx in ["my", "get", "the", "try", "use", "go"]:
        variants.add(pfx + name + "." + tld)
    for sfx in ["app", "io", "hq", "inc", "api", "site"]:
        variants.add(name + sfx + "." + tld)

    # 7. Hyphenation
    for i in range(1, len(name)):
        variants.add(name[:i] + "-" + name[i:] + "." + tld)

    # Remove the real domain and empty strings
    variants.discard(name + "." + tld)
    variants.discard("." + tld)
    return variants


class TyposquattingScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resolver = _import_dns()
        if resolver is None:
            logger.warning("dnspython not installed — skipping typosquatting checks")
            return self.results

        host   = urlparse(url).hostname or ""
        domain = host.lstrip("www.") if host.startswith("www.") else host
        if not domain:
            return self.results

        name, tld = _split_domain(domain)
        if not name or not tld:
            return self.results

        variants = list(_generate_variants(name, tld))[:_MAX_VARIANTS]
        logger.info(f"Checking {len(variants)} typosquatting variants for {domain}")

        registered: List[str] = []
        with_mx:    List[str] = []

        for variant in variants:
            try:
                if _resolves(resolver, variant):
                    registered.append(variant)
                    if _has_mx(resolver, variant):
                        with_mx.append(variant)
            except Exception:
                continue

        if with_mx:
            mx_list = ", ".join(with_mx[:10])
            more    = f" (+ {len(with_mx) - 10} more)" if len(with_mx) > 10 else ""
            log_fail(logger, f"Typosquatted domains with MX records: {mx_list}")
            self.results.append(self._result(url,
                "Typosquatting — registered lookalike domains with mail servers",
                "FAIL",
                detail=(
                    f"{len(with_mx)} typosquatted variant(s) of {domain} are registered "
                    f"AND have mail servers (MX records): {mx_list}{more}. "
                    "These are almost certainly phishing infrastructure targeting your users. "
                    "Mail sent FROM these domains impersonates your brand. "
                    "Actions: (1) Report to your domain registrar and relevant abuse contacts. "
                    "(2) Consider registering the most dangerous variants yourself. "
                    "(3) Publish DMARC p=reject to prevent spoofing FROM your real domain. "
                    "(4) Alert your users to watch for emails from similar domains."
                ),
                extra={"typosquat_mx_domains": with_mx}
            ))
        elif registered:
            reg_list = ", ".join(registered[:10])
            more     = f" (+ {len(registered) - 10} more)" if len(registered) > 10 else ""
            log_warn(logger, f"Registered typosquatted domains: {reg_list}")
            self.results.append(self._result(url,
                "Typosquatting — registered lookalike domains detected",
                "WARN",
                detail=(
                    f"{len(registered)} typosquatted variant(s) of {domain} are registered: "
                    f"{reg_list}{more}. "
                    "These could be used for phishing, traffic interception, or brand confusion. "
                    "Consider monitoring or registering high-risk variants."
                ),
                extra={"typosquat_registered_domains": registered}
            ))
        else:
            log_pass(logger, f"No registered typosquatted domains found for {domain}")
            self.results.append(self._result(url,
                "Typosquatting — no registered lookalike domains detected",
                "PASS",
                detail=f"Checked {len(variants)} typo variants of {domain} — none resolve in DNS."))

        return self.results

    def _result(self, url, result_type, status, detail="", extra=None):
        r = super()._result(url, result_type, status, detail=detail)
        if extra:
            r.update(extra)
        return r
