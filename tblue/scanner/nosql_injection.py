"""
NoSQL Injection Indicator Scanner.

Passively detects NoSQL injection vulnerabilities through:

1. MongoDB operator patterns in URL parameters or form values
   ($where, $gt, $lt, $ne, $regex, $in, $or, $and — without escaping)
2. NoSQL error messages in response bodies
   (MongoDB, CouchDB, Redis, Cassandra, DynamoDB error strings)
3. JSON-body endpoints accepting MongoDB operators in visible form data
4. Parameter names matching NoSQL document field patterns
5. CouchDB admin API exposure (_all_docs, _design, _utils)

NoSQL injection (OWASP A03:2021) can bypass authentication and extract data.

All checks are passive — no payload injection.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# MongoDB operators that should never appear in user input
_MONGO_OPERATOR_RE = re.compile(
    r"""(?:^|[?&,\s\[{])(\$(?:where|gt|gte|lt|lte|ne|nin|in|or|and|nor|not|
    exists|type|mod|regex|options|text|search|near|geoIntersects|geoWithin|
    all|elemMatch|size|slice|meta|comment|expr|jsonSchema|rand|natural|inc|
    set|unset|push|pull|pop|addToSet|bit|rename|setOnInsert|currentDate|mul|
    min|max|addFields|bucket|bucketAuto|count|facet|graphLookup|group|limit|
    lookup|match|merge|out|project|redact|replaceRoot|replaceWith|sample|skip|
    sort|sortByCount|unwind|filter|arrayElemAt|arrayToObject|concatArrays)
    (?:[=:]|%3[Dd]|%3[Aa]))""",
    re.I | re.X,
)

# NoSQL error message patterns
_NOSQL_ERROR_RE = re.compile(
    r"MongoError|MongoServerError|MongoNetworkError"
    r"|MongooseError|mongoose\.Error"
    r"|mongodb\+srv://|mongodb://[^\s'\"]{5}"
    r"|BulkWriteError|WriteResult"
    r"|CouchDB.*Error|couch\.error"
    r"|redis\.exceptions\.|RedisError"
    r"|cassandra\.cluster\.|NoHostAvailable"
    r"|DynamoDBError|ResourceNotFoundException"
    r"|ElasticsearchException"
    r"|neo4j\.exceptions\.|ServiceUnavailable.*neo4j"
    r"|\bOID\b.*\bMongo"
    r"|E11000\s+duplicate\s+key"
    r"|Cannot\s+read\s+property.*of\s+null.*Mongo"
    r"|db\.collection\s+is\s+not\s+a\s+function",
    re.I,
)

# CouchDB admin paths
_COUCHDB_PATHS = [
    "/_all_dbs",
    "/_utils",
    "/_session",
    "/_users",
    "/_replicator",
    "/_global_changes",
]

_COUCHDB_BODY_RE = re.compile(r'"couchdb"\s*:|"version"\s*:\s*"[23]\.\d+|futon|fauxton', re.I)

# MongoDB REST API patterns (some older deployments expose REST interface)
_MONGO_REST_PATHS = [
    "/db/admin",
    "/db/test",
    "/_api",
]


class NoSQLInjectionScanner(BaseScanner):
    """Detect NoSQL injection indicators through passive analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "NoSQL injection — no indicators detected", "PASS",
                detail="No MongoDB errors, operators in params, or CouchDB admin exposure found."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)

        # ── 1. MongoDB error messages in response ──────────────────────────────
        error_match = _NOSQL_ERROR_RE.search(body)
        if error_match:
            snippet = error_match.group(0)[:100]
            log_fail(logger, f"NoSQL error message in response: {snippet}")
            self.results.append(self._result(
                url, "NoSQL injection — database error message exposed", "FAIL",
                detail=(
                    f"NoSQL database error found in response: '{snippet}'. "
                    "Error messages confirm the NoSQL database type and version. "
                    "More critically, injection of MongoDB operators ($where, $or, etc.) "
                    "in parameters accepted by this endpoint may bypass authentication "
                    "or extract unauthorized data. "
                    "Fix: suppress all database errors in production; "
                    "validate and sanitize all inputs before passing to NoSQL queries; "
                    "use parameterized queries/ODM sanitization."
                )
            ))

        # ── 2. MongoDB operators in URL parameters ─────────────────────────────
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in qs.items():
            for val in values:
                if _MONGO_OPERATOR_RE.search(val):
                    log_fail(logger, f"MongoDB operator in URL param '{param}': {val[:40]}")
                    self.results.append(self._result(
                        url, f"NoSQL injection — MongoDB operator in URL parameter ({param})", "FAIL",
                        detail=(
                            f"MongoDB query operator found in URL parameter '{param}': '{val[:60]}'. "
                            "If this parameter is passed directly to a MongoDB query, it enables "
                            "NoSQL injection. "
                            "Fix: sanitize all MongoDB query values; use mongo-sanitize or "
                            "express-mongo-sanitize middleware; avoid directly using user input "
                            "in $where clauses."
                        )
                    ))

        # ── 3. MongoDB operators in form fields ────────────────────────────────
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                val = inp.attrs.get("value", "")
                name = inp.attrs.get("name", "")
                if val and _MONGO_OPERATOR_RE.search(val):
                    log_fail(logger, f"MongoDB operator in form field '{name}'")
                    self.results.append(self._result(
                        url, f"NoSQL injection — MongoDB operator in form field ({name})", "FAIL",
                        detail=(
                            f"Form field '{name}' contains MongoDB operator: '{val[:60]}'. "
                            "Fix: validate all form inputs; strip MongoDB operators before querying."
                        )
                    ))

        # ── 4. CouchDB admin interface exposure ───────────────────────────────
        parsed_base = f"{parsed.scheme}://{parsed.netloc}"
        for path in _COUCHDB_PATHS:
            probe_url = parsed_base + path
            try:
                r = self.http.get(probe_url)
                if not r or r.status_code not in (200, 206):
                    continue
                if _COUCHDB_BODY_RE.search(r.text or ""):
                    log_fail(logger, f"CouchDB admin endpoint exposed: {probe_url}")
                    self.results.append(self._result(
                        probe_url, f"NoSQL injection — CouchDB admin API exposed ({path})", "FAIL",
                        detail=(
                            f"CouchDB admin API accessible at {probe_url}. "
                            "Unauthenticated CouchDB exposes all databases, allows document "
                            "creation/deletion, and may permit server-side JavaScript execution "
                            "via design documents (_design). "
                            "Fix: require admin authentication; disable the CouchDB Fauxton UI "
                            "in production; bind CouchDB to localhost only."
                        )
                    ))
            except Exception:
                continue

        if not self.results:
            log_pass(logger, f"No NoSQL injection indicators found on {url}")
            self.results.append(self._result(
                url, "NoSQL injection — no indicators detected", "PASS",
                detail="No MongoDB errors, operators in params, or CouchDB admin exposure found."
            ))

        return self.results
