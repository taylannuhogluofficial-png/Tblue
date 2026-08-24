"""Tests for deep TLS/certificate analysis."""

import ssl
import datetime
from unittest.mock import MagicMock
from tblue.scanner.tls_deep import TLSDeepScanner


def make_scanner():
    return TLSDeepScanner(MagicMock())


def _fake_cert(days_until_expiry=90):
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_until_expiry)
    return {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}


def test_skip_non_https():
    scanner = make_scanner()
    results = scanner.scan("http://example.com")
    assert results == []


def test_expiry_pass(monkeypatch):
    scanner = make_scanner()
    cert_info = {"cipher": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256),
                 "cert_der": None, "cert_dict": _fake_cert(90)}
    monkeypatch.setattr(scanner, "_get_cert_info", lambda h, p: cert_info)
    monkeypatch.setattr(scanner, "_check_cipher", lambda h, p: None)
    monkeypatch.setattr(scanner, "_check_forward_secrecy", lambda ci, h: None)
    monkeypatch.setattr(scanner, "_check_key_size", lambda ci, u: None)
    monkeypatch.setattr(scanner, "_check_sig_algo", lambda ci, u: None)
    monkeypatch.setattr(scanner, "_check_hsts_preload", lambda u: None)
    scanner._check_expiry(cert_info, "https://example.com")
    assert any("expiry" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_expiry_warn_soon(monkeypatch):
    scanner = make_scanner()
    cert_info = {"cipher": None, "cert_der": None, "cert_dict": _fake_cert(15)}
    scanner._check_expiry(cert_info, "https://example.com")
    assert any("expiring soon" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_expiry_fail_imminent(monkeypatch):
    scanner = make_scanner()
    cert_info = {"cipher": None, "cert_der": None, "cert_dict": _fake_cert(5)}
    scanner._check_expiry(cert_info, "https://example.com")
    assert any(r["status"] == "FAIL" for r in scanner.results)


def test_expiry_fail_expired(monkeypatch):
    scanner = make_scanner()
    cert_info = {"cipher": None, "cert_der": None, "cert_dict": _fake_cert(-5)}
    scanner._check_expiry(cert_info, "https://example.com")
    assert any("expired" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_forward_secrecy_pass():
    scanner = make_scanner()
    cert_info = {"cipher": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)}
    scanner._check_forward_secrecy(cert_info, "example.com")
    assert any("forward secrecy" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_forward_secrecy_warn():
    scanner = make_scanner()
    cert_info = {"cipher": ("RSA-AES256-CBC-SHA", "TLSv1.2", 256)}
    scanner._check_forward_secrecy(cert_info, "example.com")
    assert any("forward secrecy" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_hsts_preload_ready(monkeypatch):
    scanner = make_scanner()
    resp = MagicMock()
    resp.headers = {"Strict-Transport-Security":
                    "max-age=31536000; includeSubDomains; preload"}
    scanner.http.get = MagicMock(return_value=resp)
    scanner._check_hsts_preload("https://example.com")
    assert any("preload ready" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_hsts_not_preload_ready(monkeypatch):
    scanner = make_scanner()
    resp = MagicMock()
    resp.headers = {"Strict-Transport-Security": "max-age=3600"}
    scanner.http.get = MagicMock(return_value=resp)
    scanner._check_hsts_preload("https://example.com")
    assert any("not preload-ready" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_hsts_preload_none_response_returns_silently():
    # http.get returns None — should return early without crashing
    scanner = make_scanner()
    scanner.http.get = MagicMock(return_value=None)
    scanner._check_hsts_preload("https://example.com")
    assert scanner.results == []


def test_hsts_preload_missing_header_returns_silently():
    # HSTS header absent — early return (base ssl scanner covers it)
    scanner = make_scanner()
    resp = MagicMock()
    resp.headers = {}
    scanner.http.get = MagicMock(return_value=resp)
    scanner._check_hsts_preload("https://example.com")
    assert scanner.results == []


def test_hsts_preload_invalid_max_age_handled():
    # max-age has non-integer value → ValueError caught, max_age stays 0
    scanner = make_scanner()
    resp = MagicMock()
    resp.headers = {"Strict-Transport-Security": "max-age=INVALID; includeSubDomains; preload"}
    scanner.http.get = MagicMock(return_value=resp)
    scanner._check_hsts_preload("https://example.com")
    # max_age stays 0 → not preload-ready WARN
    assert any("not preload-ready" in r["type"].lower() for r in scanner.results)


def test_hsts_preload_exception_swallowed():
    # http.get raises → exception caught, no results
    scanner = make_scanner()
    scanner.http.get = MagicMock(side_effect=Exception("network error"))
    scanner._check_hsts_preload("https://example.com")
    assert scanner.results == []


# ── scan() integration with mocked _get_cert_info ────────────────────────────

def test_scan_https_with_mocked_cert_info(monkeypatch):
    scanner = make_scanner()
    cert_info = {
        "cipher": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256),
        "cert_der": None,
        "cert_dict": _fake_cert(90),
    }
    monkeypatch.setattr(scanner, "_get_cert_info", lambda h, p: cert_info)
    monkeypatch.setattr(scanner, "_check_cipher", lambda h, p: None)
    monkeypatch.setattr(scanner, "_check_key_size", lambda ci, u: None)
    monkeypatch.setattr(scanner, "_check_sig_algo", lambda ci, u: None)
    monkeypatch.setattr(scanner, "_check_hsts_preload", lambda u: None)
    # Let _check_forward_secrecy and _check_expiry run naturally
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)
    assert len(results) > 0


def test_scan_exception_from_get_cert_info_returns_empty():
    scanner = make_scanner()
    from unittest.mock import patch
    with patch.object(scanner, "_get_cert_info", side_effect=Exception("TLS handshake failed")):
        results = scanner.scan("https://example.com")
    assert results == []


# ── _check_cipher ─────────────────────────────────────────────────────────────

def test_check_cipher_strong_cipher_passes(monkeypatch):
    import socket as socket_mod
    scanner = make_scanner()
    mock_ssl_ctx = MagicMock()
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
    mock_ssl_ctx.wrap_socket.return_value = mock_sock
    mock_conn = MagicMock()
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr("tblue.scanner.tls_deep.ssl.create_default_context",
                        lambda: mock_ssl_ctx)
    monkeypatch.setattr("tblue.scanner.tls_deep.socket.create_connection",
                        lambda *a, **kw: mock_conn)
    scanner._check_cipher("example.com", 443)
    # No FAIL for a strong cipher
    assert not any("weak cipher" in r["type"].lower() for r in scanner.results)


def test_check_cipher_weak_cipher_fails(monkeypatch):
    scanner = make_scanner()
    mock_ssl_ctx = MagicMock()
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.cipher.return_value = ("RC4-MD5", "TLSv1.0", 128)
    mock_ssl_ctx.wrap_socket.return_value = mock_sock
    mock_conn = MagicMock()
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr("tblue.scanner.tls_deep.ssl.create_default_context",
                        lambda: mock_ssl_ctx)
    monkeypatch.setattr("tblue.scanner.tls_deep.socket.create_connection",
                        lambda *a, **kw: mock_conn)
    scanner._check_cipher("example.com", 443)
    assert any("weak cipher" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_check_cipher_exception_is_silent(monkeypatch):
    scanner = make_scanner()
    monkeypatch.setattr("tblue.scanner.tls_deep.ssl.create_default_context",
                        lambda: (_ for _ in ()).throw(Exception("SSL error")))
    scanner._check_cipher("example.com", 443)
    assert scanner.results == []


# ── _check_expiry edge cases ──────────────────────────────────────────────────

def test_expiry_no_not_after_returns_silently():
    scanner = make_scanner()
    cert_info = {"cert_dict": {}}  # no notAfter
    scanner._check_expiry(cert_info, "https://example.com")
    assert scanner.results == []


def test_expiry_bad_date_format_returns_silently():
    scanner = make_scanner()
    cert_info = {"cert_dict": {"notAfter": "not a date"}}
    scanner._check_expiry(cert_info, "https://example.com")
    assert scanner.results == []


# ── _check_key_size ───────────────────────────────────────────────────────────

def test_key_size_no_cert_der_returns_silently():
    scanner = make_scanner()
    scanner._check_key_size({"cert_der": None}, "https://example.com")
    assert scanner.results == []


def test_key_size_import_error_is_silent(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "cryptography":
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    scanner = make_scanner()
    scanner._check_key_size({"cert_der": b"fake"}, "https://example.com")
    assert scanner.results == []


# ── _check_sig_algo ───────────────────────────────────────────────────────────

def test_sig_algo_no_cert_der_returns_silently():
    scanner = make_scanner()
    scanner._check_sig_algo({"cert_der": None}, "https://example.com")
    assert scanner.results == []


# ── _get_cert_info (mocked SSL) ────────────────────────────────────────────────

def test_get_cert_info_mocked(monkeypatch):
    mock_ctx = MagicMock()
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
    mock_sock.getpeercert.side_effect = lambda binary_form=False: b"cert_bytes" if binary_form else {"notAfter": "Dec 31 23:59:59 2026 GMT"}
    mock_ctx.wrap_socket.return_value = mock_sock
    mock_conn = MagicMock()
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr("tblue.scanner.tls_deep.ssl.create_default_context", lambda: mock_ctx)
    monkeypatch.setattr("tblue.scanner.tls_deep.socket.create_connection", lambda *a, **kw: mock_conn)
    scanner = make_scanner()
    info = scanner._get_cert_info("example.com", 443)
    assert info["cipher"][0] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert info["cert_der"] == b"cert_bytes"


# ── _check_key_size with real cert ────────────────────────────────────────────

def _mock_crypto_modules():
    """Inject mock cryptography modules into sys.modules so that _check_key_size
    and _check_sig_algo can be tested without the cryptography library installed."""
    import sys
    from unittest.mock import MagicMock, patch

    # Concrete classes that pass isinstance checks
    class MockRSAPublicKey:
        key_size = 2048

    class MockECPublicKey:
        key_size = 256

    class MockSmallRSAKey(MockRSAPublicKey):  # subclass so isinstance passes
        key_size = 1024

    class MockSHA256:
        pass

    class MockSHA1:
        pass

    class MockMD5:
        pass

    mock_rsa = MagicMock()
    mock_rsa.RSAPublicKey = MockRSAPublicKey

    mock_ec = MagicMock()
    mock_ec.EllipticCurvePublicKey = MockECPublicKey

    mock_hashes = MagicMock()
    mock_hashes.SHA1 = MockSHA1
    mock_hashes.MD5 = MockMD5

    return mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, MockSHA1, MockMD5, MockSHA256


def _make_crypto_patch():
    """Return a patch.dict context manager that injects mock cryptography."""
    import sys
    from unittest.mock import MagicMock

    mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, MockSHA1, MockMD5, MockSHA256 = _mock_crypto_modules()

    mock_asym = MagicMock()
    mock_asym.rsa = mock_rsa
    mock_asym.ec = mock_ec

    mock_primitives = MagicMock()
    mock_primitives.asymmetric = mock_asym
    mock_primitives.hashes = mock_hashes

    mock_hazmat = MagicMock()
    mock_hazmat.primitives = mock_primitives

    # x509 module — must be wired to mock_cryptography.x509 so that
    # `from cryptography import x509` returns the same object as sys.modules['cryptography.x509']
    mock_x509 = MagicMock()

    mock_cryptography = MagicMock()
    mock_cryptography.hazmat = mock_hazmat
    mock_cryptography.x509 = mock_x509  # wire so `from cryptography import x509` works

    from unittest.mock import patch
    return (patch.dict('sys.modules', {
        'cryptography': mock_cryptography,
        'cryptography.x509': mock_x509,
        'cryptography.hazmat': mock_hazmat,
        'cryptography.hazmat.primitives': mock_primitives,
        'cryptography.hazmat.primitives.asymmetric': mock_asym,
        'cryptography.hazmat.primitives.asymmetric.rsa': mock_rsa,
        'cryptography.hazmat.primitives.asymmetric.ec': mock_ec,
        'cryptography.hazmat.primitives.hashes': mock_hashes,
    }), mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, MockSHA1, MockMD5, MockSHA256, mock_x509)


def test_check_key_size_adequate_rsa_passes():
    patcher, mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, *rest = _make_crypto_patch()
    mock_x509 = rest[-1]
    with patcher:
        rsa_key = MockRSAPublicKey()
        mock_x509.load_der_x509_certificate.return_value.public_key.return_value = rsa_key
        scanner = make_scanner()
        scanner._check_key_size({"cert_der": b"fake"}, "https://example.com")
    assert any("key size" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_check_key_size_weak_rsa_fails():
    patcher, mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, *rest = _make_crypto_patch()
    mock_x509 = rest[-1]
    with patcher:
        weak_key = MockSmallRSAKey()
        mock_x509.load_der_x509_certificate.return_value.public_key.return_value = weak_key
        scanner = make_scanner()
        scanner._check_key_size({"cert_der": b"fake"}, "https://example.com")
    assert any("weak rsa" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_check_key_size_adequate_ec_passes():
    patcher, mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, *rest = _make_crypto_patch()
    mock_x509 = rest[-1]
    with patcher:
        ec_key = MockECPublicKey()
        mock_x509.load_der_x509_certificate.return_value.public_key.return_value = ec_key
        scanner = make_scanner()
        scanner._check_key_size({"cert_der": b"fake"}, "https://example.com")
    assert any("key size" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_check_key_size_exception_silent():
    patcher, *rest = _make_crypto_patch()
    mock_x509 = rest[-1]
    with patcher:
        mock_x509.load_der_x509_certificate.side_effect = Exception("bad cert")
        scanner = make_scanner()
        scanner._check_key_size({"cert_der": b"garbage"}, "https://example.com")
    assert scanner.results == []


# ── _check_sig_algo with mocked cryptography ─────────────────────────────────

def test_check_sig_algo_sha256_passes():
    patcher, mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, MockSHA1, MockMD5, MockSHA256, mock_x509 = _make_crypto_patch()
    with patcher:
        cert_mock = mock_x509.load_der_x509_certificate.return_value
        cert_mock.signature_hash_algorithm = MockSHA256()
        scanner = make_scanner()
        scanner._check_sig_algo({"cert_der": b"fake"}, "https://example.com")
    assert any("signature algorithm" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_check_sig_algo_sha1_warns():
    patcher, mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, MockSHA1, MockMD5, MockSHA256, mock_x509 = _make_crypto_patch()
    with patcher:
        cert_mock = mock_x509.load_der_x509_certificate.return_value
        cert_mock.signature_hash_algorithm = MockSHA1()
        scanner = make_scanner()
        scanner._check_sig_algo({"cert_der": b"fake"}, "https://example.com")
    assert any("sha-1" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_check_sig_algo_md5_fails():
    patcher, mock_rsa, mock_ec, mock_hashes, MockRSAPublicKey, MockECPublicKey, MockSmallRSAKey, MockSHA1, MockMD5, MockSHA256, mock_x509 = _make_crypto_patch()
    with patcher:
        cert_mock = mock_x509.load_der_x509_certificate.return_value
        cert_mock.signature_hash_algorithm = MockMD5()
        scanner = make_scanner()
        scanner._check_sig_algo({"cert_der": b"fake"}, "https://example.com")
    assert any("md5" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_check_sig_algo_exception_silent():
    patcher, *rest = _make_crypto_patch()
    mock_x509 = rest[-1]
    with patcher:
        mock_x509.load_der_x509_certificate.side_effect = Exception("bad cert")
        scanner = make_scanner()
        scanner._check_sig_algo({"cert_der": b"garbage"}, "https://example.com")
    assert scanner.results == []
