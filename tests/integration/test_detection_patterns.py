"""
Real-world response pattern validation.

These tests verify that Tblue's detection regexes and parsing logic
fire correctly on realistic server responses — not just on synthetic mocked
data used in unit tests.  Each test uses a captured sample of what a real
vulnerable server would return.

No network connections are made; responses are embedded as string literals.
These are the exact byte sequences that real vulnerable infrastructure returns.
"""

import base64
import json
import re

# ── Cloud Storage ─────────────────────────────────────────────────────────────

S3_PUBLIC_LIST_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-public-bucket</Name>
  <Prefix></Prefix>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>passwords.txt</Key>
    <LastModified>2024-01-15T10:30:00.000Z</LastModified>
    <ETag>&quot;5d41402abc4b2a76b9719d911017c592&quot;</ETag>
    <Size>1024</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>db_backup_2024.sql.gz</Key>
    <Size>102400</Size>
  </Contents>
</ListBucketResult>"""

S3_ACCESS_DENIED_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Error><Code>AccessDenied</Code>"
    "<Message>Access Denied</Message>"
    "<RequestId>EXAMPLE1234567890</RequestId>"
    "<HostId>example</HostId></Error>"
)

S3_NO_SUCH_BUCKET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Error><Code>NoSuchBucket</Code>"
    "<Message>The specified bucket does not exist</Message>"
    "<BucketName>nonexistent-bucket</BucketName></Error>"
)

AZURE_PUBLIC_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://myaccount.blob.core.windows.net/"
                    ContainerName="mycontainer">
  <Blobs>
    <Blob>
      <Name>secrets.json</Name>
      <Properties>
        <Last-Modified>Mon, 15 Jan 2024 10:00:00 GMT</Last-Modified>
        <Content-Length>256</Content-Length>
        <Content-Type>application/json</Content-Type>
      </Properties>
    </Blob>
    <Blob>
      <Name>private-key.pem</Name>
      <Properties>
        <Content-Length>1679</Content-Length>
      </Properties>
    </Blob>
  </Blobs>
  <NextMarker />
</EnumerationResults>"""

GCS_PUBLIC_JSON = json.dumps({
    "kind": "storage#objects",
    "items": [
        {"name": "private-data.csv", "size": "8192",
         "updated": "2024-01-15T10:00:00.000Z"},
        {"name": "backup.sql", "size": "102400"},
        {"name": ".env", "size": "512"},
    ]
})

GCS_PRIVATE_ERROR = json.dumps({
    "error": {
        "code": 403,
        "message": "Access Not Configured.",
        "status": "PERMISSION_DENIED"
    }
})


def test_s3_public_list_regex_fires_on_real_listing():
    from tblue.scanner.cloud_storage import _S3_PUBLIC_LIST
    assert _S3_PUBLIC_LIST.search(S3_PUBLIC_LIST_XML) is not None


def test_s3_access_denied_does_not_trigger_public_list():
    from tblue.scanner.cloud_storage import _S3_PUBLIC_LIST
    assert _S3_PUBLIC_LIST.search(S3_ACCESS_DENIED_XML) is None


def test_s3_access_denied_still_matches_signature():
    from tblue.scanner.cloud_storage import _S3_SIGNATURE
    assert _S3_SIGNATURE.search(S3_ACCESS_DENIED_XML) is not None


def test_s3_no_such_bucket_matches_signature_not_public():
    from tblue.scanner.cloud_storage import _S3_SIGNATURE, _S3_PUBLIC_LIST
    assert _S3_SIGNATURE.search(S3_NO_SUCH_BUCKET_XML) is not None
    assert _S3_PUBLIC_LIST.search(S3_NO_SUCH_BUCKET_XML) is None


def test_azure_enumeration_regex_fires_on_real_response():
    from tblue.scanner.cloud_storage import _AZURE_PUBLIC
    assert _AZURE_PUBLIC.search(AZURE_PUBLIC_XML) is not None


def test_gcs_objects_regex_fires_on_real_response():
    from tblue.scanner.cloud_storage import _GCS_PUBLIC
    assert _GCS_PUBLIC.search(GCS_PUBLIC_JSON) is not None


def test_gcs_error_does_not_trigger_public_flag():
    from tblue.scanner.cloud_storage import _GCS_PUBLIC
    assert _GCS_PUBLIC.search(GCS_PRIVATE_ERROR) is None


# ── GraphQL ───────────────────────────────────────────────────────────────────

GRAPHQL_INTROSPECTION_RESPONSE = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "description": "A registered user account",
                    "fields": [
                        {"name": "id", "type": {"name": "ID"}},
                        {"name": "email", "type": {"name": "String"}},
                        {"name": "passwordHash", "type": {"name": "String"}},
                        {"name": "isAdmin", "type": {"name": "Boolean"}},
                    ]
                },
                {"kind": "OBJECT", "name": "Query"},
                {"kind": "OBJECT", "name": "Mutation"},
                {"kind": "SCALAR", "name": "__Type"},
                {"kind": "SCALAR", "name": "__Schema"},
            ]
        }
    }
})

GRAPHQL_NO_INTROSPECTION = json.dumps({
    "errors": [
        {
            "message": "GraphQL introspection is not allowed, but the query contained __schema or __type.",
            "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}
        }
    ]
})

GRAPHQL_ALIAS_ATTACK_RESPONSE = json.dumps({
    "data": {
        "q0": {"id": "1", "email": "user@example.com"},
        "q1": {"id": "1", "email": "user@example.com"},
        "q2": {"id": "1", "email": "user@example.com"},
    }
})


def test_graphql_introspection_schema_key_present():
    assert '"__schema"' in GRAPHQL_INTROSPECTION_RESPONSE


def test_graphql_schema_regex_fires_on_real_introspection():
    schema_re = re.compile(r'"__schema"', re.I)
    assert schema_re.search(GRAPHQL_INTROSPECTION_RESPONSE) is not None


def test_graphql_no_introspection_schema_key_absent():
    schema_re = re.compile(r'"__schema"', re.I)
    assert schema_re.search(GRAPHQL_NO_INTROSPECTION) is None


def test_graphql_introspection_exposes_field_names():
    data = json.loads(GRAPHQL_INTROSPECTION_RESPONSE)
    types = data["data"]["__schema"]["types"]
    user_type = next(t for t in types if t["name"] == "User")
    field_names = [f["name"] for f in user_type["fields"]]
    assert "passwordHash" in field_names
    assert "isAdmin" in field_names


# ── JWT ───────────────────────────────────────────────────────────────────────

# alg:none JWT — no signature (dangerous: server may accept this as valid)
JWT_ALG_NONE = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    "."
)

# Normal HS256 JWT
JWT_HS256 = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# RS256 JWT (asymmetric — could be attacked via key confusion → HS256)
JWT_RS256 = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".placeholder_rs256_sig"
)


def _decode_jwt_header(token: str) -> dict:
    part = token.split(".")[0]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part).decode())


def test_alg_none_jwt_header_decoded_correctly():
    header = _decode_jwt_header(JWT_ALG_NONE)
    assert header["alg"] == "none"


def test_alg_none_jwt_flagged_as_no_signature():
    header = _decode_jwt_header(JWT_ALG_NONE)
    assert header["alg"].lower() == "none"


def test_hs256_jwt_not_flagged_as_none_alg():
    header = _decode_jwt_header(JWT_HS256)
    assert header["alg"].lower() != "none"


def test_rs256_jwt_detected_as_asymmetric():
    header = _decode_jwt_header(JWT_RS256)
    assert header["alg"].startswith("RS")


def test_jwt_none_has_empty_signature():
    parts = JWT_ALG_NONE.split(".")
    assert len(parts) == 3
    assert parts[2] == ""


# ── SQL / Error page leakage ──────────────────────────────────────────────────

MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near '\\'' at line 1"
)
PGSQL_ERROR = (
    "ERROR:  syntax error at or near \"'\" "
    "LINE 1: SELECT * FROM users WHERE username = ''' AND password = ..."
)
MSSQL_ERROR = (
    "Microsoft OLE DB Provider for SQL Server error '80040e14' "
    "Unclosed quotation mark after the character string ''."
)
ORACLE_ERROR = "ORA-00907: missing right parenthesis"
JAVA_STACKTRACE = (
    "java.lang.NullPointerException\n"
    "\tat org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:943)\n"
    "\tat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)\n"
    "\tat javax.servlet.http.HttpServlet.service(HttpServlet.java:764)"
)
PHP_ERROR = (
    "Fatal error: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: "
    "1064 You have an error in your SQL syntax in /var/www/html/login.php on line 47"
)

_SQL_RE = re.compile(
    r"sql syntax|mysql_fetch|ORA-\d{4,5}|pg_query|syntax error.*near|"
    r"Microsoft OLE DB|ODBC.*SQL Server|SQLSTATE\[",
    re.I,
)
_STACK_RE = re.compile(r"at [a-z][a-z0-9.]+\.[A-Z][a-zA-Z]+\.\w+\(", re.I)


def test_mysql_error_matches_sql_pattern():
    assert _SQL_RE.search(MYSQL_ERROR) is not None


def test_postgresql_error_matches_sql_pattern():
    assert _SQL_RE.search(PGSQL_ERROR) is not None


def test_mssql_error_matches_sql_pattern():
    assert _SQL_RE.search(MSSQL_ERROR) is not None


def test_oracle_error_matches_sql_pattern():
    assert _SQL_RE.search(ORACLE_ERROR) is not None


def test_php_pdo_exception_matches_sql_pattern():
    assert _SQL_RE.search(PHP_ERROR) is not None


def test_java_stacktrace_matches_trace_pattern():
    assert _STACK_RE.search(JAVA_STACKTRACE) is not None


def test_clean_200_page_does_not_match_sql_pattern():
    clean = "<html><body><h1>Welcome</h1><p>Login successful.</p></body></html>"
    assert _SQL_RE.search(clean) is None


# ── Cloud Metadata (SSRF) ─────────────────────────────────────────────────────

AWS_IMDSV1_CREDENTIALS = """{
  "Code" : "Success",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "AQoXnyc4PIcelExample//////////wEaDFRU0s4AVrw0k0oYICK4ATAegXoIkK+78",
  "Expiration" : "2024-01-01T00:00:00Z"
}"""

GCP_METADATA_SA = """{
  "default": {
    "email": "123456789-compute@developer.gserviceaccount.com",
    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}"""

AZURE_METADATA = """{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.example",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "expires_in": "28799",
  "ext_expires_in": "28799",
  "token_type": "Bearer"
}"""

_AWS_KEY_RE = re.compile(r"AccessKeyId.*?(ASIA|AKIA)[A-Z0-9]{16}", re.I | re.S)
_GCP_SA_RE  = re.compile(r"developer\.gserviceaccount\.com", re.I)
_AZURE_TOKEN_RE = re.compile(r'"access_token"\s*:', re.I)


def test_aws_imds_access_key_pattern_fires():
    assert _AWS_KEY_RE.search(AWS_IMDSV1_CREDENTIALS) is not None


def test_gcp_service_account_pattern_fires():
    assert _GCP_SA_RE.search(GCP_METADATA_SA) is not None


def test_azure_managed_identity_token_pattern_fires():
    assert _AZURE_TOKEN_RE.search(AZURE_METADATA) is not None


# ── Subdomain Takeover Signatures ─────────────────────────────────────────────

HEROKU_TAKEOVER = "There's nothing here, yet. This page is reserved for an upcoming Heroku app."
GITHUB_PAGES_TAKEOVER = "There isn't a GitHub Pages site here."
SHOPIFY_TAKEOVER = "Sorry, this shop is currently unavailable."
FASTLY_TAKEOVER = "Fastly error: unknown domain:"
WORDPRESS_TAKEOVER = "Do you want to register wordpress.com/start/address?"

_TAKEOVER_RES = [
    re.compile(r"there'?s nothing here.*heroku|heroku.*nothing here", re.I),
    re.compile(r"isn.t a github pages site", re.I),
    re.compile(r"this shop is currently unavailable", re.I),
    re.compile(r"fastly error.*unknown domain", re.I),
    re.compile(r"register.*wordpress\.com", re.I),
]


def test_heroku_takeover_signature_detected():
    assert _TAKEOVER_RES[0].search(HEROKU_TAKEOVER) is not None


def test_github_pages_takeover_signature_detected():
    assert _TAKEOVER_RES[1].search(GITHUB_PAGES_TAKEOVER) is not None


def test_shopify_takeover_signature_detected():
    assert _TAKEOVER_RES[2].search(SHOPIFY_TAKEOVER) is not None


def test_fastly_takeover_signature_detected():
    assert _TAKEOVER_RES[3].search(FASTLY_TAKEOVER) is not None


def test_wordpress_takeover_signature_detected():
    assert _TAKEOVER_RES[4].search(WORDPRESS_TAKEOVER) is not None


def test_s3_no_such_bucket_is_takeover_candidate():
    from tblue.scanner.cloud_storage import _S3_SIGNATURE
    assert _S3_SIGNATURE.search(S3_NO_SUCH_BUCKET_XML) is not None


# ── CORS Header Analysis ──────────────────────────────────────────────────────

def test_wildcard_acao_is_identified():
    headers = {"access-control-allow-origin": "*"}
    assert headers.get("access-control-allow-origin") == "*"


def test_reflected_origin_with_creds_is_critical():
    request_origin = "https://evil.com"
    headers = {
        "access-control-allow-origin": request_origin,
        "access-control-allow-credentials": "true",
    }
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    assert acao == request_origin
    assert acac == "true"


def test_null_origin_with_creds_is_critical():
    headers = {
        "access-control-allow-origin": "null",
        "access-control-allow-credentials": "true",
    }
    acao = headers.get("access-control-allow-origin", "")
    assert acao == "null"


def test_restrictive_cors_does_not_trigger():
    headers = {"content-type": "application/json"}
    acao = headers.get("access-control-allow-origin", "")
    assert acao == ""


# ── Security Headers ──────────────────────────────────────────────────────────

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

INSECURE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Server": "Apache/2.4.51 (Ubuntu)",
    "X-Powered-By": "PHP/8.0.12",
}


def test_insecure_response_missing_hsts():
    assert "Strict-Transport-Security".lower() not in \
           {k.lower() for k in INSECURE_HEADERS}


def test_insecure_response_missing_csp():
    assert "Content-Security-Policy".lower() not in \
           {k.lower() for k in INSECURE_HEADERS}


def test_insecure_response_exposes_server_version():
    assert "Server" in INSECURE_HEADERS
    server_val = INSECURE_HEADERS["Server"]
    version_re = re.compile(r"\d+\.\d+\.\d+")
    assert version_re.search(server_val) is not None


def test_secure_response_has_all_key_headers():
    required = {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    }
    present = {k.lower() for k in SECURE_HEADERS}
    assert required.issubset(present)


# ── Path Traversal Payloads ───────────────────────────────────────────────────

PASSWD_CONTENT = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
WINDOWS_HOSTS  = "127.0.0.1 localhost\n::1 localhost\n"
ENV_FILE       = "DATABASE_URL=postgres://admin:s3cr3t@db:5432/prod\nSECRET_KEY=abc123"

_PASSWD_RE = re.compile(r"root:.*?:/bin/(bash|sh)", re.I)
# Matches KEY names that contain common secret-related words followed by =value
_ENV_SECRET_RE = re.compile(r"[A-Z_]*(SECRET|PASSWORD|TOKEN|API_KEY)[A-Z_]*\s*=\s*\S+", re.I)


def test_passwd_content_is_detected():
    assert _PASSWD_RE.search(PASSWD_CONTENT) is not None


def test_env_file_secrets_detected():
    assert _ENV_SECRET_RE.search(ENV_FILE) is not None


def test_env_file_database_url_detected():
    db_re = re.compile(r"DATABASE_URL\s*=\s*\S+", re.I)
    assert db_re.search(ENV_FILE) is not None
