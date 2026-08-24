"""
Deserialization Indicator Scanner.

Detects signs of insecure deserialization without sending payloads:

1. Java serialized object magic bytes in HTTP responses (0xACED0005)
2. PHP serialize() patterns in cookies, hidden fields, or URL params
3. .NET ViewState without MAC validation (base64 decoded, no __VIEWSTATEGENERATOR)
4. Python pickle indicators in response Content-Type or body
5. Java serialization content types (application/x-java-serialized-object)
6. Java deserialization libraries in stack traces (Apache Commons, Kryo, XStream)
7. Node.js/JS serialization: node-serialize, serialize-javascript patterns

Insecure deserialization (OWASP A08:2021) is a critical vulnerability class
enabling remote code execution when attacker-controlled data is deserialized.

All checks are passive read-only analysis.
"""

import re
import base64
from typing import Any, Dict, List
from urllib.parse import unquote

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Java serialized object magic: 0xACED (stream) + 0x0005 (version 5)
_JAVA_MAGIC_B64 = "rO0"  # base64 of \xac\xed\x00
_JAVA_MAGIC_HEX = re.compile(r"aced0005", re.I)

# PHP serialize patterns: O:6:"Object":1:{s:3:"key";s:5:"value";}
_PHP_SERIALIZE_RE = re.compile(
    r"""(?:^|[;,&\s])
    [Ooa]:\d+:"[\w\\]+":\d+:\{|
    s:\d+:"[^"]*";|
    a:\d+:\{|
    i:\d+;|
    b:[01];
    """,
    re.X,
)

# .NET ViewState (base64, usually starts with specific bytes)
_VIEWSTATE_RE = re.compile(r'__VIEWSTATE[^"]*"\s+value="([^"]{50,})"', re.I)
_VIEWSTATE_GENERATOR_RE = re.compile(r'__VIEWSTATEGENERATOR[^"]*"\s+value="([^"]{4,})"', re.I)
_EVENTVALIDATION_RE = re.compile(r'__EVENTVALIDATION[^"]*"\s+value="([^"]{20,})"', re.I)

# Python pickle: pickled objects are binary, but class patterns sometimes visible
_PICKLE_CONTENT_TYPE_RE = re.compile(r"application/x-pickle|application/pickle", re.I)

# XStream, Kryo, Java serialization in stack traces / error messages
_JAVA_DESER_LIB_RE = re.compile(
    r"com\.thoughtworks\.xstream|"
    r"com\.esotericsoftware\.kryo|"
    r"org\.apache\.commons\.collections\.functors|"
    r"com\.sun\.org\.apache\.xalan|"
    r"java\.io\.ObjectInputStream|"
    r"java\.io\.ObjectOutputStream|"
    r"java\.io\.Serializable|"
    r"readObject\(\)|writeObject\(\)|"
    r"ClassPathXmlApplicationContext|"
    r"org\.codehaus\.groovy\.runtime",
    re.I,
)

# node-serialize / serialize-javascript patterns
_NODE_SERIALIZE_RE = re.compile(
    r"_\$\$ND_FUNC\$\$_|"
    r"node-serialize|"
    r"require\('serialize-javascript'\)|"
    r"serialize-javascript",
    re.I,
)

# Content-Type indicating serialized Java
_JAVA_CONTENT_TYPE_RE = re.compile(
    r"application/x-java-serialized-object|"
    r"application/octet-stream",
    re.I,
)


def _is_java_serialized_b64(value: str) -> bool:
    """Check if a base64 string decodes to Java serialized object magic bytes."""
    try:
        # Pad if necessary
        padded = value + "=" * (4 - len(value) % 4)
        decoded = base64.b64decode(padded, validate=False)
        return decoded[:4] == b"\xac\xed\x00\x05"
    except Exception:
        return False


class DeserializationScanner(BaseScanner):
    """Detect insecure deserialization indicators through passive response analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        content_type = resp.headers.get("content-type", "")

        # ── 1. Java serialized content type ───────────────────────────────────
        if _JAVA_CONTENT_TYPE_RE.search(content_type) and "octet-stream" in content_type.lower():
            if body and _is_java_serialized_b64(body.strip()[:20]) or _JAVA_MAGIC_HEX.search(body):
                log_fail(logger, f"Java serialized object served as response body: {url}")
                self.results.append(self._result(
                    url, "Deserialization — Java serialized object in response", "FAIL",
                    detail=(
                        "The server returned a Java serialized object (Content-Type: "
                        "application/x-java-serialized-object or binary content with "
                        "magic bytes 0xACED0005). Sending a crafted serialized payload "
                        "to this endpoint may trigger remote code execution via gadget chains. "
                        "Fix: replace Java serialization with JSON/XML; use allowlists for "
                        "deserialized classes; upgrade Apache Commons Collections to 3.2.2+/4.1+; "
                        "apply SerialKiller or NotSoSerial JVM agent."
                    )
                ))

        # ── 2. Java magic bytes in cookies ────────────────────────────────────
        for cookie_name, cookie_val in resp.cookies.items():
            decoded_val = unquote(cookie_val)
            if decoded_val.startswith(_JAVA_MAGIC_B64) or _is_java_serialized_b64(decoded_val[:20]):
                log_fail(logger, f"Java serialized object in cookie '{cookie_name}'")
                self.results.append(self._result(
                    url, f"Deserialization — Java serialized object in cookie ({cookie_name})", "FAIL",
                    detail=(
                        f"Cookie '{cookie_name}' appears to contain a base64-encoded Java "
                        "serialized object (starts with rO0B / 0xACED0005). "
                        "This is a classic deserialization vulnerability pattern — "
                        "modifying this cookie with a gadget chain payload may achieve RCE. "
                        "Fix: never serialize Java objects into cookies; use signed JWT or "
                        "server-side sessions with opaque session IDs."
                    )
                ))

        # ── 3. Java deserialization library signatures in responses ───────────
        deser_match = _JAVA_DESER_LIB_RE.search(body)
        if deser_match:
            snippet = deser_match.group(0)[:80]
            log_fail(logger, f"Java deserialization library exposed in response: {snippet}")
            self.results.append(self._result(
                url, "Deserialization — Java serialization library in error response", "FAIL",
                detail=(
                    f"Java deserialization/serialization class references found in response: "
                    f"'{snippet}'. This indicates server-side Java deserialization and may "
                    "reveal the deserialization library version (often vulnerable to "
                    "Apache Commons Collections, Spring, or Groovy gadget chains). "
                    "Fix: suppress stack traces in production; apply CVE patches for "
                    "commons-collections, commons-beanutils; use SerialKiller JVM agent."
                )
            ))

        # ── 4. PHP serialized object in response or cookies ───────────────────
        soup = BeautifulSoup(body, "html.parser")
        # Check hidden fields
        for inp in soup.find_all("input", {"type": "hidden"}):
            val = inp.attrs.get("value", "")
            if _PHP_SERIALIZE_RE.search(val):
                name = inp.attrs.get("name", "unknown")
                log_fail(logger, f"PHP serialized object in hidden field '{name}'")
                self.results.append(self._result(
                    url, f"Deserialization — PHP serialized object in form field ({name})", "FAIL",
                    detail=(
                        f"Hidden form field '{name}' contains a PHP serialized object "
                        f"pattern: O:...:{{...}}. PHP unserialize() on attacker-controlled "
                        "data can trigger object injection attacks leading to RCE via "
                        "magic methods (__wakeup, __destruct, __toString). "
                        "Fix: replace serialization with JSON; validate and sign any "
                        "data round-tripped through the client."
                    )
                ))

        for cookie_name, cookie_val in resp.cookies.items():
            decoded_val = unquote(cookie_val)
            if _PHP_SERIALIZE_RE.search(decoded_val):
                log_fail(logger, f"PHP serialized object in cookie '{cookie_name}'")
                self.results.append(self._result(
                    url, f"Deserialization — PHP serialized object in cookie ({cookie_name})", "FAIL",
                    detail=(
                        f"Cookie '{cookie_name}' contains a PHP serialized object. "
                        "Deserializing attacker-modified cookies can lead to object injection "
                        "and remote code execution via PHP magic method chains. "
                        "Fix: use signed, encrypted session tokens instead of serialized objects."
                    )
                ))

        # ── 5. .NET ViewState without MAC validation ──────────────────────────
        vs_match = _VIEWSTATE_RE.search(body)
        if vs_match:
            has_generator = bool(_VIEWSTATE_GENERATOR_RE.search(body))
            has_validation = bool(_EVENTVALIDATION_RE.search(body))
            if not has_generator or not has_validation:
                log_warn(logger, "ASP.NET ViewState found without MAC validation indicators")
                self.results.append(self._result(
                    url, "Deserialization — ASP.NET ViewState without MAC validation", "WARN",
                    detail=(
                        "ASP.NET ViewState found without __VIEWSTATEGENERATOR or "
                        "__EVENTVALIDATION. Without MAC (Message Authentication Code) "
                        "validation, attackers can craft malicious ViewState payloads "
                        "that trigger .NET deserialization gadget chains (ObjectStateFormatter). "
                        "Fix: ensure EnableViewStateMac=true (default in .NET 4.5.2+); "
                        "set machineKey in web.config with explicit validationKey; "
                        "upgrade to .NET 4.8+ which enables ViewState MAC by default."
                    )
                ))

        # ── 6. Python pickle indicators ───────────────────────────────────────
        if _PICKLE_CONTENT_TYPE_RE.search(content_type):
            log_fail(logger, f"Python pickle content type in response: {content_type}")
            self.results.append(self._result(
                url, "Deserialization — Python pickle content type in response", "FAIL",
                detail=(
                    f"Response Content-Type is '{content_type}' (Python pickle format). "
                    "Pickle deserialization of untrusted data executes arbitrary Python code. "
                    "Fix: never use pickle for untrusted data; use JSON/MessagePack instead; "
                    "if pickle is required, use hmac.compare_digest to verify a HMAC signature."
                )
            ))

        # ── 7. Node.js serialize patterns ────────────────────────────────────
        if _NODE_SERIALIZE_RE.search(body):
            log_warn(logger, "node-serialize / serialize-javascript pattern detected")
            self.results.append(self._result(
                url, "Deserialization — node-serialize pattern detected in response", "WARN",
                detail=(
                    "A node-serialize or serialize-javascript pattern was found. "
                    "node-serialize < 0.0.4 has a known RCE vulnerability (CVE-2017-5941) "
                    "via IIFE (Immediately Invoked Function Expression) payloads in "
                    "_$$ND_FUNC$$_ properties. "
                    "Fix: update node-serialize to a patched version; prefer JSON.parse "
                    "for client data; never serialize functions."
                )
            ))

        if not self.results:
            log_pass(logger, f"No deserialization indicators found on {url}")
            self.results.append(self._result(
                url, "Deserialization — no insecure deserialization indicators", "PASS",
                detail="No Java serialized objects, PHP serialize patterns, or ViewState issues found."
            ))

        return self.results
