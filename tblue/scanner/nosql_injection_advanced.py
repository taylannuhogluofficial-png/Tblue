"""NoSQL Injection Advanced scanner — passive detection of NoSQL injection patterns in JavaScript and responses."""
import re
from .base import BaseScanner

_NOSQL_ANY_RE = re.compile(
    r'(?:mongoose|mongodb|MongoClient|MongoError|db\.collection|'
    r'\$where|\$ne|\$gt|\$regex|\.find\s*\(|\.aggregate\s*\(|'
    r'Redis\.|redis\.get|couchdb|dynamodb)',
    re.I,
)

_NOSQL_WHERE_FROM_PARAM_RE = re.compile(
    r'\$where\s*:\s*["\'][^"\']{0,200}'
    r'(?:searchParams|location\.hash|req\.body|userInput)|'
    r'db\.[a-zA-Z_]+\.find\s*\(\s*\{\s*\$where\s*:\s*'
    r'(?:searchParams|req\.body)',
    re.I,
)

_NOSQL_OPERATOR_INJECTION_RE = re.compile(
    r'(?:req\.body|req\.query|searchParams)[^;]{0,200}'
    r'(?:\$gt|\$lt|\$ne|\$gte|\$lte|\$in|\$nin|\$regex|'
    r'\$or|\$and|\$not|\$exists)',
    re.I,
)

_NOSQL_FIND_FROM_PARAM_RE = re.compile(
    r'\.find\s*\(\s*(?:req\.body|req\.query|JSON\.parse\s*\('
    r'(?:req\.body|searchParams))',
    re.I,
)

_NOSQL_AGGREGATE_INJECTION_RE = re.compile(
    r'\.aggregate\s*\(\s*\[[^\]]{0,500}'
    r'(?:req\.body|req\.query|searchParams)',
    re.I,
)

_NOSQL_ERROR_DISCLOSURE_RE = re.compile(
    r'(?:MongoError|MongoNetworkError|CastError|'
    r'ValidationError.*mongoose|BSONError|'
    r'redis\.exceptions\.|RedisError|CouchDB.*error)',
    re.I,
)

_NOSQL_MAPREDUCE_INJECTION_RE = re.compile(
    r'(?:mapReduce|mapreduce)\s*\([^)]{0,200}'
    r'(?:req\.body|searchParams|userInput)',
    re.I,
)


class NoSQLInjectionAdvancedScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "nosql_injection_advanced_not_used", "PASS")]

        body = resp.text
        if not _NOSQL_ANY_RE.search(body):
            return [self._result(url, "nosql_injection_advanced_not_used", "PASS")]

        findings = []

        if _NOSQL_WHERE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "nosql_injection_where_from_param", "FAIL",
                detail="MongoDB $where operator receiving URL parameter or req.body — $where evaluates a JavaScript function server-side; attacker-controlled $where expression executes arbitrary JavaScript in MongoDB context, bypassing document-level authorization.",
            ))

        if _NOSQL_OPERATOR_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "nosql_injection_operator_from_param", "FAIL",
                detail="MongoDB query operator ($gt, $lt, $ne, $in, $regex) sourced from req.body/req.query — attacker sends {password: {$ne: null}} to bypass password checks; {$regex: '.*'} to return all documents; classic NoSQL injection via operator injection.",
            ))

        if _NOSQL_FIND_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "nosql_injection_find_from_param", "FAIL",
                detail="MongoDB .find() receiving raw req.body or JSON.parse(req.body) as query — entire attacker-supplied object used as MongoDB query selector; enables operator injection and authorization bypass without any input sanitization.",
            ))

        if _NOSQL_AGGREGATE_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "nosql_injection_aggregate_from_param", "WARN",
                detail="MongoDB .aggregate() pipeline stage includes req.body or URL parameter — attacker-controlled pipeline stage can add $lookup to join sensitive collections, $unwind to enumerate records, or $out to write to new collections.",
            ))

        if _NOSQL_MAPREDUCE_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "nosql_injection_mapreduce_from_param", "FAIL",
                detail="MongoDB mapReduce() receiving user input — mapReduce executes JavaScript in MongoDB context; attacker-controlled map/reduce functions enable server-side JavaScript execution and data exfiltration.",
            ))

        if _NOSQL_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "nosql_injection_error_disclosure", "WARN",
                detail="MongoDB/Redis/CouchDB error message in response (MongoError, CastError, ValidationError) — exposes database type, version, schema field names, and query structure; enables precise query crafting for injection attacks.",
            ))

        return findings or [self._result(url, "nosql_injection_advanced_safe", "PASS")]
