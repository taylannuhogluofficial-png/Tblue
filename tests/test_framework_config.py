"""Tests for tblue.scanner.framework_config — FrameworkConfigScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.framework_config import FrameworkConfigScanner

URL = "https://example.com"


def _make_scanner():
    return FrameworkConfigScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


# --- Log file fixtures ---
_LARAVEL_LOG = (
    "[2024-01-01 12:00:00] production.ERROR: SQLSTATE[42000]: Syntax error or access violation: "
    "1064 You have an error in your SQL syntax near 'WHERE id = 1'\n"
    "[2024-01-01 12:01:00] production.ERROR: exception 'PDOException' with message "
    "'SQLSTATE[HY000] [2002] Connection refused' in /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connectors/Connector.php:70\n"
    "Stack trace:\n"
    "#0 /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connection.php(332): PDO->query()\n"
)

_ACCESS_LOG = (
    '192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
    '10.0.0.1 - - [01/Jan/2024:12:01:00 +0000] "POST /api/login HTTP/1.1" 401 89 "-" "curl/7.68.0"\n'
)

_AUTH_LOG = (
    "[2024-01-01 12:00:00] DEBUG: Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.TOKEN_VALUE\n"
    "[2024-01-01 12:00:01] DEBUG: session-id: abc123def456ghi789jkl\n"
    "Exception: Invalid token\n"
    "at com.example.AuthFilter.doFilter(AuthFilter.java:45)\n"
)

# --- Config file fixtures ---
_SPRING_PROPS = (
    "spring.application.name=myapp\n"
    "spring.datasource.url=jdbc:mysql://localhost:3306/mydb\n"
    "spring.datasource.username=root\n"
    "spring.datasource.password=SuperSecret123!\n"
    "spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver\n"
    "server.port=8080\n"
)

_SPRING_YAML = (
    "spring:\n"
    "  application:\n"
    "    name: myapp\n"
    "  datasource:\n"
    "    url: jdbc:postgresql://localhost:5432/mydb\n"
    "    username: postgres\n"
    "    password: postgres_secret_password\n"
    "server:\n"
    "  port: 8080\n"
)

_APPSETTINGS = (
    '{\n'
    '  "Logging": {\n'
    '    "LogLevel": {\n'
    '      "Default": "Information"\n'
    '    }\n'
    '  },\n'
    '  "AllowedHosts": "*",\n'
    '  "ConnectionStrings": {\n'
    '    "DefaultConnection": "Server=myserver;Database=mydb;User Id=sa;Password=MyP@ssw0rd;"\n'
    '  }\n'
    '}\n'
)

_RAILS_DB_YML = (
    "default: &default\n"
    "  adapter: postgresql\n"
    "  encoding: unicode\n"
    "  pool: <%= ENV.fetch('RAILS_MAX_THREADS') { 5 } %>\n\n"
    "development:\n"
    "  <<: *default\n"
    "  database: myapp_development\n"
    "  username: postgres\n"
    "  password: dev_password\n\n"
    "production:\n"
    "  <<: *default\n"
    "  database: myapp_production\n"
    "  username: <%= ENV['DB_USER'] %>\n"
    "  password: <%= ENV['DB_PASSWORD'] %>\n"
)

_RAILS_SECRETS = (
    "development:\n"
    "  secret_key_base: abc123def456abc123def456abc123def456abc123def456abc123def456abc123\n\n"
    "production:\n"
    "  secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>\n"
)

_DJANGO_SETTINGS = (
    "SECRET_KEY = 'django-insecure-production-key-abc123xyz456'\n\n"
    "DATABASES = {\n"
    "    'default': {\n"
    "        'ENGINE': 'django.db.backends.postgresql',\n"
    "        'NAME': 'mydb',\n"
    "        'USER': 'myuser',\n"
    "        'PASSWORD': 'mypassword',\n"
    "        'HOST': 'localhost',\n"
    "    }\n"
    "}\n\n"
    "INSTALLED_APPS = [\n"
    "    'django.contrib.admin',\n"
    "]\n"
)

_WEB_CONFIG = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<configuration>\n'
    '  <connectionStrings>\n'
    '    <add name="DefaultConnection"\n'
    '         connectionString="Server=myserver;Database=mydb;password=MyP@ssw0rd;"\n'
    '         providerName="System.Data.SqlClient" />\n'
    '  </connectionStrings>\n'
    '  <system.web>\n'
    '    <compilation debug="false" targetFramework="4.8" />\n'
    '  </system.web>\n'
    '</configuration>\n'
)

_HIBERNATE_CFG = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<!DOCTYPE hibernate-configuration PUBLIC\n'
    '    "-//Hibernate/Hibernate Configuration DTD//EN"\n'
    '    "http://www.hibernate.org/dtd/hibernate-configuration-3.0.dtd">\n'
    '<hibernate-configuration>\n'
    '    <session-factory>\n'
    '        <property name="hibernate.connection.url">jdbc:mysql://localhost:3306/mydb</property>\n'
    '        <property name="hibernate.connection.username">root</property>\n'
    '        <property name="hibernate.connection.password">hibernate_password</property>\n'
    '    </session-factory>\n'
    '</hibernate-configuration>\n'
)

_MASTER_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"


def test_unreachable_returns_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_target_no_files_pass():
    """No sensitive files accessible → PASS."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html>Homepage</html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


def test_laravel_log_exposed_fails():
    """Laravel log with stack traces and SQL errors → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/storage/logs/laravel.log":
            return _resp(200, _LARAVEL_LOG)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(
        "laravel" in r["type"].lower() or "log" in r["type"].lower()
        for r in fails
    )


def test_access_log_exposed_fails():
    """HTTP access log exposed → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/logs/error.log":
            return _resp(200, _ACCESS_LOG)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("log" in r["type"].lower() for r in fails)


def test_log_with_auth_tokens_detected():
    """Log file with Authorization/session tokens → FAIL with auth warning."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/debug.log":
            return _resp(200, _AUTH_LOG)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(r for r in fails)
    # Detail should mention tokens
    detail_text = " ".join(r.get("detail", "") for r in fails)
    assert "token" in detail_text.lower() or "auth" in detail_text.lower() or "session" in detail_text.lower()


def test_spring_boot_properties_exposed_fails():
    """Spring Boot application.properties with datasource password → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/application.properties":
            return _resp(200, _SPRING_PROPS)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(
        "spring" in r["type"].lower() or "application" in r["type"].lower()
        for r in fails
    )


def test_spring_boot_yaml_exposed_fails():
    """Spring Boot application.yml with datasource config → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/application.yml":
            return _resp(200, _SPRING_YAML)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("application" in r["type"].lower() for r in fails)


def test_appsettings_json_exposed_fails():
    """ASP.NET Core appsettings.json with ConnectionStrings → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/appsettings.json":
            return _resp(200, _APPSETTINGS)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("appsettings" in r["type"].lower() or "asp.net" in r["type"].lower() for r in fails)


def test_rails_database_yml_exposed_fails():
    """Rails config/database.yml with credentials → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/config/database.yml":
            return _resp(200, _RAILS_DB_YML)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("rails" in r["type"].lower() or "database" in r["type"].lower() for r in fails)


def test_rails_secrets_yml_exposed_fails():
    """Rails config/secrets.yml with secret_key_base → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/config/secrets.yml":
            return _resp(200, _RAILS_SECRETS)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("secrets" in r["type"].lower() or "rails" in r["type"].lower() for r in fails)


def test_django_settings_exposed_fails():
    """Django settings.py with SECRET_KEY and DATABASE → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/local_settings.py":
            return _resp(200, _DJANGO_SETTINGS)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("django" in r["type"].lower() or "settings" in r["type"].lower() for r in fails)


def test_web_config_with_password_exposed_fails():
    """ASP.NET web.config with password in connectionString → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/web.config":
            return _resp(200, _WEB_CONFIG)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("web.config" in r["type"].lower() or "asp.net" in r["type"].lower() for r in fails)


def test_hibernate_config_exposed_fails():
    """Hibernate cfg.xml with JDBC password → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/hibernate.cfg.xml":
            return _resp(200, _HIBERNATE_CFG)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("hibernate" in r["type"].lower() or "config" in r["type"].lower() for r in fails)


def test_generic_json_at_config_path_not_flagged():
    """Regular JSON at application.properties path without Spring patterns → not flagged."""
    s = _make_scanner()
    generic_body = '{"hello": "world", "status": "ok"}'

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith("application.properties"):
            return _resp(200, generic_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_rails_master_key_exposed_fails():
    """Rails config/master.key (hex key) → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/config/master.key":
            return _resp(200, _MASTER_KEY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("master.key" in r["type"].lower() or "encryption" in r["type"].lower() for r in fails)


def test_rails_credentials_enc_exposed_fails():
    """Rails config/credentials.yml.enc (any non-empty content) → FAIL."""
    s = _make_scanner()
    enc_content = "kABc12DEf34GHij56KLmnop789QRSTuv"  # looks like encrypted blob

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/config/credentials.yml.enc":
            return _resp(200, enc_content)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("credentials" in r["type"].lower() or "encrypted" in r["type"].lower() for r in fails)


def test_laravel_database_php_exposed_fails():
    """Laravel config/database.php with mysql driver → FAIL."""
    s = _make_scanner()
    laravel_db = (
        "<?php\nreturn [\n"
        "    'default' => env('DB_CONNECTION', 'mysql'),\n"
        "    'connections' => [\n"
        "        'mysql' => [\n"
        "            'driver' => 'mysql',\n"
        "            'host' => env('DB_HOST', '127.0.0.1'),\n"
        "            'database' => env('DB_DATABASE', 'laravel'),\n"
        "            'username' => env('DB_USERNAME', 'root'),\n"
        "            'password' => env('DB_PASSWORD', 'secret123'),\n"
        "        ],\n"
        "    ],\n"
        "];\n"
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/config/database.php":
            return _resp(200, laravel_db)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("laravel" in r["type"].lower() or "database" in r["type"].lower() for r in fails)


def test_jpa_persistence_xml_exposed_fails():
    """JPA META-INF/persistence.xml exposed → FAIL."""
    s = _make_scanner()
    persistence_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<persistence version="2.1" xmlns="http://xmlns.jcp.org/xml/ns/persistence">\n'
        '  <persistence-unit name="myPU" transaction-type="RESOURCE_LOCAL">\n'
        '    <class>com.example.MyEntity</class>\n'
        '    <properties>\n'
        '      <property name="javax.persistence.jdbc.url" value="jdbc:mysql://localhost/mydb"/>\n'
        '      <property name="javax.persistence.jdbc.user" value="root"/>\n'
        '      <property name="javax.persistence.jdbc.password" value="jpa_password"/>\n'
        '    </properties>\n'
        '  </persistence-unit>\n'
        '</persistence>\n'
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/META-INF/persistence.xml":
            return _resp(200, persistence_xml)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("persistence" in r["type"].lower() or "jpa" in r["type"].lower() for r in fails)


def test_datasource_properties_with_password_exposed_fails():
    """JDBC datasource.properties with password → FAIL."""
    s = _make_scanner()
    jdbc_props = (
        "dataSource.driverClassName=com.mysql.cj.jdbc.Driver\n"
        "dataSource.url=jdbc:mysql://localhost:3306/mydb\n"
        "dataSource.username=dbuser\n"
        "dataSource.password=jdbc_secret_password\n"
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/datasource.properties":
            return _resp(200, jdbc_props)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("datasource" in r["type"].lower() or "jdbc" in r["type"].lower() for r in fails)


def test_empty_body_not_flagged():
    """Empty body at config path → not flagged."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        return _resp(200, "ok")  # too short (< 5 chars for some paths)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)
