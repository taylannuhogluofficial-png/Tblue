"""
MongoDB / CouchDB / Firebase exposure scanner.

Probes for publicly accessible NoSQL database instances.
Unauthenticated access allows full data exfiltration and
in some cases arbitrary data modification.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_MONGO_HTTP_PATHS = [
    ":28017/",
    ":27017/",
]

_COUCH_PATHS = [
    ":5984/",
    ":5984/_all_dbs",
]

_FIREBASE_RE  = re.compile(r'"rules"\s*:\s*\{|"\.read"\s*:\s*"?true"?', re.I)
_COUCH_RE     = re.compile(r'"couchdb"\s*:\s*"Welcome"', re.I)
_MONGO_HTTP_RE = re.compile(
    r"(mongod|MongoDB|db\.collection|listDatabases|REST interface)", re.I
)

_MONGO_PORTS  = [27017, 27018, 28017]
_COUCH_PORTS  = [5984, 5985]

# Firebase REST API patterns
_FIREBASE_DB_RE = re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com", re.I)


class MongoDBExposureScanner(BaseScanner):
    """Detect publicly exposed MongoDB, CouchDB, and Firebase databases."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed  = urlparse(url)
        host    = parsed.hostname or parsed.netloc.split(":")[0]
        base    = parsed.scheme + "://" + parsed.netloc
        found   = False

        # CouchDB HTTP API
        for port in _COUCH_PORTS:
            for path in ["/", "/_all_dbs"]:
                probe = f"http://{host}:{port}{path}"
                resp  = self.http.get(probe)
                if resp is None:
                    continue
                body = resp.text or ""

                if resp.status_code == 401:
                    self.results.append(self._result(
                        probe, "couchdb_auth_enforced", "PASS",
                        detail=f"CouchDB on port {port} requires authentication."
                    ))
                    found = True
                    break
                elif resp.status_code == 200 and _COUCH_RE.search(body):
                    found = True
                    self.results.append(self._result(
                        probe, "couchdb_unauthenticated_access", "FAIL",
                        detail=f"CouchDB on {host}:{port} accessible without authentication. "
                               "Full database listing and document read/write possible. "
                               "Enable CouchDB authentication via require_valid_user=true in local.ini."
                    ))
                elif resp.status_code == 200 and path == "/_all_dbs" and body.startswith("["):
                    found = True
                    try:
                        import json
                        dbs = json.loads(body)
                        self.results.append(self._result(
                            probe, "couchdb_database_listing", "FAIL",
                            detail=f"CouchDB /_all_dbs returns {len(dbs)} database(s) without auth: "
                                   f"{dbs[:5]}. Full data exfiltration possible via /<db>/_all_docs."
                        ))
                    except Exception:
                        pass

        # MongoDB HTTP Interface (deprecated but still encountered)
        for port in [28017]:
            probe = f"http://{host}:{port}/"
            resp  = self.http.get(probe)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                if _MONGO_HTTP_RE.search(body):
                    found = True
                    self.results.append(self._result(
                        probe, "mongodb_http_interface_exposed", "FAIL",
                        detail=f"MongoDB HTTP interface on port {port} is publicly accessible. "
                               "REST API allows database enumeration without auth. "
                               "Disable with --nohttpinterface or remove --rest flag."
                    ))

        # Firebase Realtime Database — check for public read rules
        resp = self.http.get(url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            fb_matches = _FIREBASE_DB_RE.findall(body)
            if fb_matches:
                for fb_url in set(fb_matches[:3]):
                    rules_url = fb_url.rstrip("/") + "/.json?shallow=true"
                    fb_resp = self.http.get(rules_url)
                    if fb_resp and fb_resp.status_code == 200 and fb_resp.text not in ("null", ""):
                        found = True
                        self.results.append(self._result(
                            rules_url, "firebase_public_read", "FAIL",
                            detail=f"Firebase Realtime Database at {fb_url} allows unauthenticated read. "
                                   "Set database rules to require auth: "
                                   '{"rules": {".read": "auth != null", ".write": "auth != null"}}.'
                        ))

        # Check page source for MongoDB connection string patterns
        if resp and resp.status_code == 200:
            body = resp.text or ""
            mongo_conn_re = re.compile(
                r"mongodb(\+srv)?://[^\"'\s<>]{5,}", re.I
            )
            matches = mongo_conn_re.findall(body)
            if matches:
                found = True
                self.results.append(self._result(
                    url, "mongodb_connection_string_exposed", "FAIL",
                    detail=f"MongoDB connection string detected in page source: "
                           f"{len(matches)} occurrence(s). Connection strings contain credentials "
                           "and internal hostnames — remove from client-side code immediately."
                ))

        if not found:
            self.results.append(self._result(
                url, "mongodb_not_exposed", "PASS",
                detail="No publicly accessible MongoDB/CouchDB/Firebase exposure detected."
            ))

        return self.results
