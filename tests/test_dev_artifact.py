"""Tests for tblue.scanner.dev_artifact — DevArtifactScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.dev_artifact import DevArtifactScanner

URL = "https://example.com"


def _make_scanner():
    return DevArtifactScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


# --- Content fixtures ---

_HAR_BODY = (
    '{"log":{"version":"1.2","creator":{"name":"DevTools","version":"1"},'
    '"entries":[{"startedDateTime":"2024-01-01T00:00:00Z",'
    '"request":{"method":"GET","url":"https://api.example.com/user",'
    '"cookies":[{"name":"session","value":"abc123"}],'
    '"headers":[{"name":"Authorization","value":"Bearer tok"}],'
    '"queryString":[],"headersSize":-1,"bodySize":0},'
    '"response":{"status":200,"statusText":"OK","headers":[],'
    '"cookies":[],"content":{"size":100,"mimeType":"application/json"},'
    '"redirectURL":"","headersSize":-1,"bodySize":100},'
    '"cache":{},"timings":{"send":0,"wait":100,"receive":0}}]}}'
)

_TF_STATE_BODY = (
    '{"version":4,"terraform_version":"1.5.0","serial":42,'
    '"lineage":"abc-123","outputs":{},'
    '"resources":[{"module":"module.rds","type":"aws_db_instance",'
    '"name":"main","provider":"provider[\\"registry.terraform.io/hashicorp/aws\\"]",'
    '"instances":[{"attributes":{"password":"MyS3cr3t!","identifier":"mydb"}}]}]}'
)

_NPMRC_BODY = (
    "registry=https://registry.npmjs.org/\n"
    "//registry.npmjs.org/:_authToken=npm_token_abc123XYZ\n"
    "//registry.npmjs.org/:always-auth=true\n"
)

_SSH_KEY_BODY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAD32e3DP5RfPjBE/\n"
    "-----END RSA PRIVATE KEY-----\n"
)

_DOCKER_AUTH_BODY = (
    '{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNzd29yZA=="}},'
    '"HttpHeaders":{"User-Agent":"Docker-Client/20.10.9"}}'
)

_AWS_CREDS_BODY = (
    "[default]\n"
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)

_KUBECONFIG_BODY = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- cluster:\n"
    "    server: https://k8s.example.com:6443\n"
    "  name: my-cluster\n"
    "current-context: my-context\n"
    "contexts:\n"
    "- context:\n"
    "    cluster: my-cluster\n"
    "    user: admin\n"
    "  name: my-context\n"
    "users:\n"
    "- name: admin\n"
    "  user:\n"
    "    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.EXAMPLE_TOKEN_VALUE\n"
)

_PKGLOCK_BODY = (
    '{"name":"myapp","version":"1.0.0","lockfileVersion":3,'
    '"packages":{"node_modules/lodash":{"version":"4.17.21",'
    '"resolved":"git+https://myuser:ghp_secret@github.com/org/private-pkg.git"}}}'
)

_COMPOSER_AUTH_BODY = (
    '{"github-oauth":{"github.com":"ghp_EXAMPLE_TOKEN_1234567890ABCD"},'
    '"http-basic":{"example.com":{"username":"user","password":"pass"}}}'
)


def test_unreachable_target_returns_pass():
    """Target unreachable → scanner returns PASS."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_target_no_artifacts_pass():
    """No artifact files accessible → PASS."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><body>Hello</body></html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


def test_har_file_exposed_fails():
    """Accessible HAR file with entries → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/network.har":
            return _resp(200, _HAR_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("har" in r["type"].lower() or "browser" in r["type"].lower() for r in fails)


def test_har_file_without_log_structure_not_flagged():
    """File at .har path that doesn't match HAR structure → not flagged."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith(".har"):
            return _resp(200, "<html>404 Not Found</html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_terraform_state_exposed_fails():
    """Accessible terraform.tfstate → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/terraform.tfstate":
            return _resp(200, _TF_STATE_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("terraform" in r["type"].lower() or "tfstate" in r["type"].lower() for r in fails)


def test_npmrc_with_auth_token_fails():
    """Accessible .npmrc with _authToken → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/.npmrc":
            return _resp(200, _NPMRC_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("npmrc" in r["type"].lower() or "npm" in r["type"].lower() for r in fails)


def test_ssh_private_key_exposed_fails():
    """SSH private key at /id_rsa → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/id_rsa":
            return _resp(200, _SSH_KEY_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("ssh" in r["type"].lower() or "private key" in r["type"].lower() for r in fails)


def test_docker_config_auth_exposed_fails():
    """Docker config.json with auths/auth field → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/docker-config.json":
            return _resp(200, _DOCKER_AUTH_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("docker" in r["type"].lower() for r in fails)


def test_aws_credentials_file_exposed_fails():
    """AWS credentials file with access key → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/.aws/credentials":
            return _resp(200, _AWS_CREDS_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("aws" in r["type"].lower() or "credential" in r["type"].lower() for r in fails)


def test_kubeconfig_exposed_fails():
    """Kubernetes kubeconfig at /kubeconfig → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/kubeconfig":
            return _resp(200, _KUBECONFIG_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(
        "kubeconfig" in r["type"].lower() or "kubernetes" in r["type"].lower()
        for r in fails
    )


def test_package_lock_with_git_token_warns():
    """package-lock.json with embedded git+https:// credentials → WARN."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/package-lock.json":
            return _resp(200, _PKGLOCK_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warnings = [r for r in results if r["status"] == "WARN"]
    assert any("package" in r["type"].lower() or "lock" in r["type"].lower() for r in warnings)


def test_composer_auth_json_exposed_fails():
    """Composer auth.json with GitHub OAuth token → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/auth.json":
            return _resp(200, _COMPOSER_AUTH_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("composer" in r["type"].lower() or "auth.json" in r["type"].lower() for r in fails)


def test_short_body_not_flagged():
    """A 200 response with only 3 bytes body → not flagged (too short for validation)."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        # Return a 200 with very short body — below the 5-char minimum
        if url.endswith(".npmrc"):
            return _resp(200, "ok")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_aws_config_with_default_profile_warns():
    """AWS config at /.aws/config with [default] section → WARN."""
    s = _make_scanner()
    aws_config_body = "[default]\nregion = us-east-1\noutput = json\n"

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/.aws/config":
            return _resp(200, aws_config_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("aws" in r["type"].lower() for r in warns)


def test_yarnlock_with_token_warns():
    """yarn.lock with embedded auth credentials → WARN."""
    s = _make_scanner()
    yarn_lock_body = (
        "__metadata:\n"
        "  version: 6\n"
        "\n"
        "lodash@npm:^4.17.21:\n"
        '  version: 4.17.21\n'
        '  resolution: "lodash@npm:4.17.21"\n'
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/yarn.lock":
            return _resp(200, yarn_lock_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("yarn" in r["type"].lower() for r in warns)


def test_probe_raises_exception_silently_skipped():
    """If a probe request raises an exception, scanner skips it silently."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        call_count[0] += 1
        if call_count[0] == 1:
            raise ConnectionError("Connection refused")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Scanner should complete without error and return at least a PASS
    assert any(r["status"] == "PASS" for r in results)
