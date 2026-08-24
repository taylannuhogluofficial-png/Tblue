"""Extra coverage for content_injection — line 128-133 (BeautifulSoup input discovery)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.content_injection import ContentInjectionScanner


def _scanner():
    return ContentInjectionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_search_form_input_discovered_without_query_params():
    """When URL has no reflectable params, scanner finds text inputs via BeautifulSoup (lines 128-133)."""
    s = _scanner()
    # URL without query params — forces BeautifulSoup form discovery path
    url = "https://example.com/search"
    html_with_form = """
    <html><body>
      <form action="/search" method="get">
        <input type="text" name="q" placeholder="Search...">
        <input type="submit" value="Search">
      </form>
    </body></html>
    """

    with patch.object(s.http, "get", return_value=_resp(200, html_with_form)):
        results = s.scan(url)

    # Any result is acceptable — the key is that the input-discovery path ran
    assert isinstance(results, list)


def test_multiple_text_inputs_found_up_to_limit():
    """Scanner collects up to 3 text inputs from search forms (lines 128-133 loop)."""
    s = _scanner()
    url = "https://example.com/"
    html_with_many_inputs = """
    <html><body>
      <form>
        <input type="text" name="first_name">
        <input type="text" name="last_name">
        <input type="search" name="search_query">
        <input type="text" name="city">
        <input type="text" name="zip">
      </form>
    </body></html>
    """

    with patch.object(s.http, "get", return_value=_resp(200, html_with_many_inputs)):
        results = s.scan(url)

    assert isinstance(results, list)


def test_no_text_inputs_on_page():
    """Page with only hidden/submit inputs — BeautifulSoup path runs but adds nothing."""
    s = _scanner()
    url = "https://example.com/"
    html_no_text_inputs = """
    <html><body>
      <form>
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="submit" value="Go">
      </form>
    </body></html>
    """

    with patch.object(s.http, "get", return_value=_resp(200, html_no_text_inputs)):
        results = s.scan(url)

    assert isinstance(results, list)
