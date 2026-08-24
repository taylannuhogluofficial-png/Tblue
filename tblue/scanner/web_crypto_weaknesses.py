"""Web Crypto API weaknesses — Math.random() for secrets, weak key parameters, insecure IV generation."""
import re
from .base import BaseScanner

_MATH_RANDOM_CRYPTO_RE = re.compile(
    r'(?:Math\.random\s*\(\s*\))'
    r'(?:[^;{]{0,60})'
    r'(?:token|secret|key|password|salt|nonce|iv|csrf|auth)',
    re.I,
)

_MATH_RANDOM_AS_CRYPTO_RE = re.compile(
    r'(?:token|key|secret|password|nonce|salt|iv|csrf)\s*[=+]'
    r'[^;{]{0,60}Math\.random\s*\(',
    re.I,
)

_WEAK_KEY_GEN_RE = re.compile(
    r'generateKey\s*\(\s*\{[^}]*'
    r'(?:"name"\s*:\s*"(?:AES-CBC|AES-ECB|DES|RC4|RC2)"|'
    r'"length"\s*:\s*(?:40|56|64|80|112|128)\b)',
    re.I,
)

_ECB_MODE_RE = re.compile(
    r'(?:"name"\s*:\s*"AES-ECB"|AES/ECB)',
    re.I,
)

_STATIC_IV_RE = re.compile(
    r'new\s+Uint8Array\s*\(\s*\[(?:\s*\d+\s*,\s*){7,}\d+\s*\]\s*\)'
    r'[^;]{0,100}'
    r'(?:iv|nonce)',
    re.I,
)

_STATIC_IV_ASSIGN_RE = re.compile(
    r'(?:iv|nonce)\s*=\s*new\s+Uint8Array\s*\(\s*\[',
    re.I,
)

_WEAK_HASH_RE = re.compile(
    r'(?:createHash|digest)\s*\(\s*["\'](?:md5|sha1|sha-1)["\']|'
    r'(?:"name"\s*:\s*"SHA-1")',
    re.I,
)

_INSECURE_RANDOM_SEED_RE = re.compile(
    r'(?:Date\.now|new Date\(\)\.getTime|performance\.now)\s*\(\s*\)'
    r'[^;]{0,60}'
    r'(?:random|seed|key|token)',
    re.I,
)

_SUBTLE_CRYPTO_RE = re.compile(r'(?:crypto\.subtle|SubtleCrypto)', re.I)
_CRYPTO_GET_RANDOM_RE = re.compile(r'crypto\.getRandomValues\s*\(', re.I)


class WebCryptoWeaknessesScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_crypto_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""

        if _MATH_RANDOM_CRYPTO_RE.search(body) or _MATH_RANDOM_AS_CRYPTO_RE.search(body):
            results.append(self._result(url, "web_crypto_math_random_for_secrets", "FAIL",
                                        detail="Math.random() used near security-sensitive variable (token/key/password/iv) — "
                                               "Math.random() is NOT cryptographically secure; use crypto.getRandomValues()"))

        if _ECB_MODE_RE.search(body):
            results.append(self._result(url, "web_crypto_ecb_mode", "FAIL",
                                        detail="AES-ECB mode detected — ECB reveals patterns in plaintext; "
                                               "use AES-GCM or AES-CBC with unique IV instead"))

        if _WEAK_KEY_GEN_RE.search(body):
            results.append(self._result(url, "web_crypto_weak_key_params", "WARN",
                                        detail="WebCrypto generateKey() with weak algorithm or key size — "
                                               "use AES-GCM with 256-bit keys or RSA-OAEP with 2048+ bit keys"))

        if _STATIC_IV_ASSIGN_RE.search(body) or _STATIC_IV_RE.search(body):
            results.append(self._result(url, "web_crypto_static_iv", "FAIL",
                                        detail="Static/hardcoded IV array for encryption — "
                                               "IV must be unique and random per encryption operation; "
                                               "reusing IV with AES-GCM enables key recovery attacks"))

        if _WEAK_HASH_RE.search(body):
            results.append(self._result(url, "web_crypto_weak_hash", "WARN",
                                        detail="MD5 or SHA-1 hashing detected — these are broken for security purposes; "
                                               "use SHA-256 or stronger"))

        if _INSECURE_RANDOM_SEED_RE.search(body):
            results.append(self._result(url, "web_crypto_timestamp_as_random", "WARN",
                                        detail="Date.now() or performance.now() used as randomness source — "
                                               "timestamps are predictable; use crypto.getRandomValues()"))

        if not results:
            uses_subtle = bool(_SUBTLE_CRYPTO_RE.search(body))
            uses_random = bool(_CRYPTO_GET_RANDOM_RE.search(body))
            if uses_subtle or uses_random:
                results.append(self._result(url, "web_crypto_api_used_safely", "PASS",
                                            detail="WebCrypto API used but no obvious weakness patterns detected"))
            else:
                results.append(self._result(url, "web_crypto_not_used", "PASS",
                                            detail="No WebCrypto API usage detected on this page"))
        return results
