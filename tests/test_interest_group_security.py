"""Tests for InterestGroupSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.interest_group_security import InterestGroupSecurityScanner


def _scanner():
    s = InterestGroupSecurityScanner.__new__(InterestGroupSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPIIInGroup:
    def test_pii_in_group_membership_fails(self):
        s = _scanner()
        body = "navigator.joinAdInterestGroup({name: user.email, owner: 'https://dsp.example'})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "interest_group_pii_in_membership" in types


class TestBiddingFromParam:
    def test_bidding_url_from_param_fails(self):
        s = _scanner()
        body = "navigator.joinAdInterestGroup({name: 'shoppers', biddingLogicURL: searchParams.get('bidder')})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "interest_group_bidding_url_from_param" in types


class TestAuctionExfil:
    def test_auction_result_exfiltrated_warns(self):
        s = _scanner()
        body = "const result = await navigator.runAdAuction({seller: '/ssp'})\nanalytics('auction', {result})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "interest_group_auction_result_exfil" in types


class TestNotUsed:
    def test_no_interest_group_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "interest_group_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
