"""Cryptographic Weakness Passive scanner — passive detection of weak cryptography in source and responses."""
import re
from .base import BaseScanner

_CW_ANY_RE = re.compile(
    r'(?:md5|sha1|sha-1|des|3des|rc4|ecb|'
    r'Math\.random|Math\.floor\s*\(\s*Math\.random|'
    r'createCipher(?:iv)?\s*\(|createHash\s*\()',
    re.I,
)

_CW_WEAK_HASH_RE = re.compile(
    r'(?:md5\s*\([^)]{0,200}\)|'
    r'sha1\s*\([^)]{0,200}\)|'
    r'createHash\s*\(\s*["\'](?:md5|sha1|sha-1)["\'])',
    re.I,
)

_CW_WEAK_CIPHER_RE = re.compile(
    r'(?:createCipher(?:iv)?\s*\(\s*["\'](?:des|3des|rc4|aes-128-ecb|aes-256-ecb|bf|blowfish)["\']|'
    r'\bDES\b|\bRC4\b|\bBlowfish\b)',
    re.I,
)

_CW_ECB_MODE_RE = re.compile(
    r'(?:ECB|AES/ECB|AES-ECB|ecb\s*mode|'
    r'Cipher\.getInstance\s*\([^)]{0,100}ECB)',
    re.I,
)

_CW_MATH_RANDOM_SECURITY_RE = re.compile(
    r'(?:token|secret|key|password|session|csrf|nonce|salt)'
    r'[^;\n]{0,200}Math\.random\s*\(\s*\)|'
    r'Math\.random\s*\(\s*\)[^;\n]{0,200}'
    r'(?:token|secret|key|password|session|csrf|nonce|salt)',
    re.I,
)

_CW_HARDCODED_IV_RE = re.compile(
    r'(?:iv\s*=\s*["\'][0-9a-fA-F]{16,}["\']|'
    r'Buffer\.from\s*\(["\'][0-9a-fA-F]{16,}["\'](?:\s*,\s*["\']hex["\'])?\s*\))',
    re.I,
)

_CW_SHORT_KEY_RE = re.compile(
    r'(?:generateKeyPair\s*\(\s*["\']rsa["\'][^)]{0,200}(?:512|1024)\b|'
    r'modulus_bits\s*=\s*(?:512|1024)\b)',
    re.I,
)

_CW_INSECURE_RANDOM_SEED_RE = re.compile(
    r'(?:seed\s*\(\s*(?:Date\.now\s*\(\s*\)|time\.time\s*\(\s*\))|'
    r'srand\s*\(\s*time\s*\()',
    re.I,
)


class CryptographicWeaknessPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cryptographic_weakness_not_used", "PASS")]

        body = resp.text
        if not _CW_ANY_RE.search(body):
            return [self._result(url, "cryptographic_weakness_not_used", "PASS")]

        findings = []

        if _CW_WEAK_HASH_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_weak_hash", "FAIL",
                detail="MD5 or SHA-1 hash function used — both are cryptographically broken; MD5 has known collision attacks (Flame malware); SHA-1 has SHAttered chosen-prefix collisions. Use SHA-256 or SHA-3 minimum for integrity, bcrypt/argon2 for passwords.",
            ))

        if _CW_WEAK_CIPHER_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_weak_cipher", "FAIL",
                detail="Weak cipher (DES, 3DES, RC4, Blowfish) detected — DES is 56-bit and brute-forceable in hours; RC4 has known biases exploited in BEAST/CRIME/POODLE attacks; 3DES vulnerable to Sweet32 birthday attack. Use AES-256-GCM.",
            ))

        if _CW_ECB_MODE_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_ecb_mode", "FAIL",
                detail="AES-ECB (Electronic Code Book) mode detected — ECB is deterministic and pattern-preserving; identical plaintext blocks produce identical ciphertext blocks; the 'ECB penguin' shows structural data is visible in ciphertext. Use AES-GCM or AES-CBC with random IV.",
            ))

        if _CW_MATH_RANDOM_SECURITY_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_math_random_for_secret", "FAIL",
                detail="Math.random() used to generate token, secret, key, or session ID — Math.random() is a PRNG with only ~52 bits of state, predictable from output; attacker can predict future values to forge CSRF tokens, session IDs, or API keys.",
            ))

        if _CW_HARDCODED_IV_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_hardcoded_iv", "WARN",
                detail="Hardcoded IV (initialization vector) detected — reusing a fixed IV with the same key breaks AES-CBC and AES-GCM security; with CBC, same IV+key reveals if two messages share a common prefix; with GCM, IV reuse completely breaks authentication.",
            ))

        if _CW_SHORT_KEY_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_short_rsa_key", "FAIL",
                detail="RSA key size of 512 or 1024 bits — 512-bit RSA was factored in 1999; 1024-bit is within reach of nation-state attackers; NIST recommends minimum 2048-bit RSA, preferably 3072-bit or ECC P-256 equivalent.",
            ))

        if _CW_INSECURE_RANDOM_SEED_RE.search(body):
            findings.append(self._result(
                url, "cryptographic_weakness_time_based_seed", "WARN",
                detail="PRNG seeded with current time (Date.now(), time.time(), srand(time())) — time-based seeds are predictable within a small window; attacker who knows approximate seed time can enumerate all possible states and predict generated values.",
            ))

        return findings or [self._result(url, "cryptographic_weakness_safe", "PASS")]
