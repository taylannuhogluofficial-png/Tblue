"""Tests for tblue.scanner.deserialization — DeserializationScanner."""

import base64
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.deserialization import DeserializationScanner

URL = "https://example.com"


def _make_scanner():
    return DeserializationScanner(MagicMock())


def _resp(status=200, body="", headers=None, cookies=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = cookies or {}
    return r


def test_none_response():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        assert s.scan(URL) == []


def test_clean_page_passes():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(body="<html><body>Clean</body></html>")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_java_serialized_cookie():
    s = _make_scanner()
    # Java serialized magic bytes 0xACED0005 base64 encoded
    java_magic = base64.b64encode(b"\xac\xed\x00\x05" + b"\x00" * 10).decode()
    cookies = {"session": java_magic}
    mock_cookies = MagicMock()
    mock_cookies.items.return_value = cookies.items()
    r = _resp(body="<html/>", cookies=mock_cookies)
    with patch.object(s.http, "get", return_value=r):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Java serialized" in f["type"] for f in fails)


def test_java_deser_lib_in_body():
    s = _make_scanner()
    body = "Error: org.apache.commons.collections.functors.InvokerTransformer at line 42"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Java serialization library" in f["type"] for f in fails)


def test_xstream_in_body():
    s = _make_scanner()
    body = "com.thoughtworks.xstream.XStreamException: Cannot deserialize object"
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_php_serialized_in_hidden_field():
    s = _make_scanner()
    body = '<html><form><input type="hidden" name="data" value=\'O:4:"User":1:{s:4:"name";s:5:"admin";}\'/></form></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("PHP serialized" in f["type"] for f in fails)


def test_php_serialized_cookie():
    s = _make_scanner()
    php_serialized = 'O:4:"User":1:{s:4:"name";s:5:"admin";}'
    cookies = {"userdata": php_serialized}
    mock_cookies = MagicMock()
    mock_cookies.items.return_value = cookies.items()
    r = _resp(body="<html/>", cookies=mock_cookies)
    with patch.object(s.http, "get", return_value=r):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("PHP serialized" in f["type"] for f in fails)


def test_aspnet_viewstate_without_mac():
    s = _make_scanner()
    vs_value = "A" * 200  # long base64-looking ViewState without VIEWSTATEGENERATOR
    body = f'<html><form><input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="{vs_value}"/></form></html>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("ViewState" in w["type"] for w in warns)


def test_aspnet_viewstate_with_mac_no_warn():
    s = _make_scanner()
    vs_value = "A" * 200
    ev_value = "B" * 50
    body = (
        f'<html><form>'
        f'<input type="hidden" name="__VIEWSTATE" value="{vs_value}"/>'
        f'<input type="hidden" name="__VIEWSTATEGENERATOR" value="ABCD1234"/>'
        f'<input type="hidden" name="__EVENTVALIDATION" value="{ev_value}"/>'
        f'</form></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "ViewState" in r["type"]]
    # With both VIEWSTATEGENERATOR and EVENTVALIDATION, should not flag
    assert not warns


def test_node_serialize_pattern():
    s = _make_scanner()
    body = '<script>var data = {"x":"_$$ND_FUNC$$_function(){return 1;}()"}</script>'
    with patch.object(s.http, "get", return_value=_resp(body=body)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("node-serialize" in w["type"] for w in warns)


def test_python_pickle_content_type():
    s = _make_scanner()
    r = _resp(body="\x80\x04\x95", headers={"content-type": "application/x-pickle"})
    with patch.object(s.http, "get", return_value=r):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("pickle" in f["type"].lower() for f in fails)
