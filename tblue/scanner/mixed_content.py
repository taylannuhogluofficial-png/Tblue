"""
Mixed content scanner.
Finds HTTP resources loaded on HTTPS pages — a common security gap
that exposes users to man-in-the-middle attacks.
Read-only — parses page source only.
"""

from typing import List, Dict, Any
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail

logger = get_logger(__name__)

# HTML tags and attributes that load external resources
RESOURCE_TAGS = [
    ("script",  "src"),
    ("link",    "href"),
    ("img",     "src"),
    ("iframe",  "src"),
    ("audio",   "src"),
    ("video",   "src"),
    ("source",  "src"),
    ("embed",   "src"),
    ("object",  "data"),
    ("form",    "action"),
]


class MixedContentScanner(BaseScanner):
    """
    Scans HTTPS pages for HTTP resources.
    Mixed content allows attackers to intercept or tamper with
    resources loaded over insecure HTTP connections.
    Read-only — no active probing.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a page for mixed content (HTTP resources on HTTPS page).

        Args:
            url: target HTTPS page URL

        Returns:
            List of result dicts — one per resource type found
        """
        self.results = []

        # only relevant for HTTPS pages
        if not url.startswith("https://"):
            logger.info(f"Skipping mixed content check on HTTP page: {url}")
            return self.results

        resp = self.http.get(url)
        if not resp:
            return self.results

        soup       = BeautifulSoup(resp.text, "html.parser")
        http_resources: List[Dict[str, str]] = []

        for tag_name, attr in RESOURCE_TAGS:
            for tag in soup.find_all(tag_name):
                value = tag.attrs.get(attr, "")
                if value.startswith("http://"):
                    http_resources.append({
                        "tag":   tag_name,
                        "attr":  attr,
                        "value": value,
                    })

        # srcset attributes on img and source tags
        for tag in soup.find_all(["img", "source"]):
            srcset = tag.attrs.get("srcset", "")
            for candidate in srcset.split(","):
                candidate = candidate.strip().split()[0] if candidate.strip() else ""
                if candidate.startswith("http://"):
                    http_resources.append({
                        "tag":   tag.name,
                        "attr":  "srcset",
                        "value": candidate,
                    })

        # form action pointing to HTTP
        for form in soup.find_all("form"):
            action = form.attrs.get("action", "")
            if action.startswith("http://"):
                http_resources.append({
                    "tag":   "form",
                    "attr":  "action",
                    "value": action,
                })

        # also check inline styles for url() references
        for tag in soup.find_all(style=True):
            style = tag.attrs.get("style", "")
            if "http://" in style:
                http_resources.append({
                    "tag":   tag.name,
                    "attr":  "style",
                    "value": style[:120],
                })

        # check CSS link tags for @import with http
        for style_tag in soup.find_all("style"):
            if style_tag.string and "http://" in style_tag.string:
                http_resources.append({
                    "tag":   "style",
                    "attr":  "content",
                    "value": "Inline style block contains http:// reference",
                })

        # check inline scripts for insecure WebSocket (ws://) connections
        for script_tag in soup.find_all("script"):
            if script_tag.string and "ws://" in script_tag.string:
                http_resources.append({
                    "tag":   "script",
                    "attr":  "content",
                    "value": "Inline script uses insecure WebSocket (ws://)",
                })

        if http_resources:
            for resource in http_resources:
                log_fail(
                    logger,
                    f"Mixed content: <{resource['tag']} {resource['attr']}> "
                    f"loads HTTP on {url}"
                )
            self.results.append({
                "url":       url,
                "type":      "Mixed content",
                "status":    "FAIL",
                "method":    "GET",
                "fields":    [r["value"][:80] for r in http_resources],
                "resources": http_resources,
                "detail": (
                    f"Found {len(http_resources)} HTTP resource(s) on an HTTPS page. "
                    "These can be intercepted or tampered with. "
                    "Fix: update all resource URLs to use HTTPS."
                ),
            })
        else:
            log_pass(logger, f"No mixed content found on {url}")
            self.results.append(self._result(
                url, "Mixed content", "PASS",
                detail="All resources loaded over HTTPS."
            ))

        return self.results
