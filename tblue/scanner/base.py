"""
Base scanner class — all scanner modules inherit from this.
Provides shared HTTP client, logging, and result structure.
"""

from typing import Optional, List, Dict, Any, TYPE_CHECKING
from requests import Session
from tblue.http import HTTPClient
from tblue.logger import get_logger
from tblue.constants import DEFAULT_TIMEOUT, DEFAULT_RETRIES, DEFAULT_BACKOFF, DEFAULT_RATE_LIMIT

if TYPE_CHECKING:
    from tblue.cache import ResponseCache

logger = get_logger(__name__)


class BaseScanner:
    """
    Base class for all Tblue scanner modules.
    Subclasses must implement the scan() method.
    """

    def __init__(
        self,
        session:    Session,
        timeout:    int      = DEFAULT_TIMEOUT,
        retries:    int      = DEFAULT_RETRIES,
        backoff:    float    = DEFAULT_BACKOFF,
        rate_limit: float    = DEFAULT_RATE_LIMIT,
        cache:      Optional["ResponseCache"] = None,
        **_kwargs: Any,
    ) -> None:
        self.http    = HTTPClient(session, timeout, retries, backoff, rate_limit, cache=cache)
        self.results: List[Dict[str, Any]] = []

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Run the scan against the given URL.
        Must be implemented by each scanner module.

        Args:
            url: target URL to scan

        Returns:
            List of result dicts
        """
        raise NotImplementedError("Each scanner must implement scan(url)")

    def _result(
        self,
        url: str,
        check_type: str,
        status: str,
        method: Optional[str]      = None,
        fields: Optional[List[str]] = None,
        detail: Optional[str]      = None,
    ) -> Dict[str, Any]:
        """
        Build a standard result dict used across all scanners.

        Args:
            url:        the URL that was tested
            check_type: human-readable name of the check
            status:     PASS | FAIL | WARN
            method:     HTTP method used (GET, POST)
            fields:     list of field names tested
            detail:     human-readable explanation and fix guidance

        Returns:
            Standardized result dict
        """
        from tblue.mitre import get_techniques
        return {
            "url":    url,
            "type":   check_type,
            "status": status,
            "method": method or "GET",
            "fields": fields or [],
            "detail": detail or "",
            "mitre":  get_techniques(check_type),
        }
