"""Deserialization Gadget Passive scanner — passive detection of insecure deserialization indicators."""
import re
from .base import BaseScanner

_DG_ANY_RE = re.compile(
    r'(?:serialize|unserialize|pickle|marshal|ObjectInputStream|'
    r'readObject|fromJSON|JSON\.parse|'
    r'O:\d+:|rO0AB|aced0005)',
    re.I,
)

_DG_PHP_SERIAL_RE = re.compile(
    r'O:\d+:"[A-Za-z_][A-Za-z0-9_\\]{0,200}":\d+:\{',
)

_DG_JAVA_SERIAL_RE = re.compile(
    r'(?:rO0AB[a-zA-Z0-9+/]{10,}|aced0005[0-9a-f]{4,})',
    re.I,
)

_DG_PICKLE_RE = re.compile(
    r'(?:pickle\.loads?\s*\(|cPickle\.|'
    r'gASV[a-zA-Z0-9+/]{10,})',
    re.I,
)

_DG_UNSERIALIZE_FROM_PARAM_RE = re.compile(
    r'unserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|'
    r'base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE))',
    re.I,
)

_DG_OBJECT_INPUT_STREAM_RE = re.compile(
    r'new\s+ObjectInputStream\s*\(\s*(?:request\.|'
    r'getInputStream\s*\(\s*\)|socket\.getInputStream)',
    re.I,
)

_DG_YAML_LOAD_RE = re.compile(
    r'(?:yaml\.load\s*\([^,)]{0,200}(?:searchParams|request|userInput)|'
    r'Yaml\(\s*\)\.load\s*\()',
    re.I,
)

_DG_ERROR_GADGET_RE = re.compile(
    r'(?:__PHP_Incomplete_Class|'
    r'java\.io\.IOException.*readObject|'
    r'org\.apache\.commons\.collections|'
    r'com\.sun\.org\.apache\.xalan)',
    re.I,
)


class DeserializationGadgetPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "deserialization_gadget_not_used", "PASS")]

        body = resp.text
        if not _DG_ANY_RE.search(body):
            return [self._result(url, "deserialization_gadget_not_used", "PASS")]

        findings = []

        if _DG_PHP_SERIAL_RE.search(body):
            findings.append(self._result(
                url, "deserialization_php_object_in_response", "FAIL",
                detail='PHP serialized object (O:N:"ClassName") in response — if this data is returned to client and later submitted back to unserialize(), attacker crafts a malicious class instance; PHP object injection enables RCE via magic method chains.',
            ))

        if _DG_JAVA_SERIAL_RE.search(body):
            findings.append(self._result(
                url, "deserialization_java_serial_in_response", "FAIL",
                detail="Java serialized stream (aced0005 magic bytes or base64 rO0AB) in response — Java deserialization of attacker-controlled bytes via Apache Commons Collections or similar gadget chains enables RCE.",
            ))

        if _DG_PICKLE_RE.search(body):
            findings.append(self._result(
                url, "deserialization_pickle_in_response", "FAIL",
                detail="Python pickle.loads() call or pickle bytestream in response — pickle deserialization of attacker-controlled data executes arbitrary Python code via __reduce__; never deserialize untrusted pickle data.",
            ))

        if _DG_UNSERIALIZE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "deserialization_unserialize_from_param", "FAIL",
                detail="PHP unserialize() called directly with $_GET/$_POST/base64_decode($_GET) — classic PHP object injection; attacker sends crafted serialized PHP object with malicious magic methods (__destruct, __wakeup, __toString).",
            ))

        if _DG_OBJECT_INPUT_STREAM_RE.search(body):
            findings.append(self._result(
                url, "deserialization_objectinputstream_from_request", "FAIL",
                detail="Java ObjectInputStream wrapping request.getInputStream() — deserializes raw bytes from HTTP request body; without allowlist filtering, any gadget chain available on the classpath is exploitable.",
            ))

        if _DG_YAML_LOAD_RE.search(body):
            findings.append(self._result(
                url, "deserialization_yaml_load_unsafe", "WARN",
                detail="yaml.load() (unsafe) called with user-controlled input — PyYAML's unsafe load() executes Python objects specified in YAML (!!python/object/apply); use yaml.safe_load() instead.",
            ))

        if _DG_ERROR_GADGET_RE.search(body):
            findings.append(self._result(
                url, "deserialization_gadget_class_in_response", "WARN",
                detail="Known deserialization gadget class (__PHP_Incomplete_Class, Apache Commons Collections) in response — presence of gadget classes in serialized streams or error messages confirms exploitable gadget chain is on classpath.",
            ))

        return findings or [self._result(url, "deserialization_gadget_safe", "PASS")]
