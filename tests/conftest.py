"""
Shared pytest fixtures and plugins for Tblue tests.

Live progress plugin: prints a ✓/✗/s line for each test as it finishes,
so you can watch the list grow in real time even with -n parallel workers.
"""

import sys
import threading
import pytest
import requests
from unittest.mock import MagicMock
from tblue.constants import TEST_MARKER

# ── Live progress reporter ────────────────────────────────────────────────────

_print_lock = threading.Lock()
_counts = {"passed": 0, "failed": 0, "skipped": 0}
_failed_names: list = []


def pytest_runtest_logreport(report):
    """Called after each test phase (setup / call / teardown)."""
    if report.when != "call":
        return

    short = report.nodeid.split("::")[-1]   # just the test function name
    module = report.nodeid.split("::")[0].replace("tests/", "").replace(".py", "")

    with _print_lock:
        if report.passed:
            _counts["passed"] += 1
            n = _counts["passed"] + _counts["failed"] + _counts["skipped"]
            print(f"  \033[32m✓\033[0m [{n:>4}] {module} :: {short}", flush=True)
        elif report.failed:
            _counts["failed"] += 1
            n = _counts["passed"] + _counts["failed"] + _counts["skipped"]
            _failed_names.append(f"{module} :: {short}")
            print(f"  \033[31m✗\033[0m [{n:>4}] {module} :: {short}", flush=True)
        elif report.skipped:
            _counts["skipped"] += 1
            n = _counts["passed"] + _counts["failed"] + _counts["skipped"]
            print(f"  \033[33ms\033[0m [{n:>4}] {module} :: {short}", flush=True)


def pytest_sessionfinish(session, exitstatus):
    """Print a final summary line with pass/fail/skip counts."""
    p = _counts["passed"]
    f = _counts["failed"]
    s = _counts["skipped"]
    total = p + f + s
    color = "\033[32m" if f == 0 else "\033[31m"
    sys.stdout.write(f"\n{color}{'='*60}\033[0m\n")
    sys.stdout.write(f"{color}  {p}/{total} passed  |  {f} failed  |  {s} skipped\033[0m\n")
    if _failed_names:
        sys.stdout.write("\033[31m  Failed:\033[0m\n")
        for name in _failed_names:
            sys.stdout.write(f"    \033[31m✗\033[0m {name}\n")
    sys.stdout.write(f"{color}{'='*60}\033[0m\n\n")
    sys.stdout.flush()


@pytest.fixture
def mock_session():
    """A mock requests session for testing without real network calls."""
    session = MagicMock(spec=requests.Session)
    return session


@pytest.fixture
def mock_response():
    """Factory for mock HTTP responses."""
    def _make(text="", headers=None, status_code=200, url="https://example.com"):
        resp            = MagicMock()
        resp.text       = text
        resp.status_code = status_code
        resp.url        = url
        resp.headers    = headers or {}
        resp.raw        = MagicMock()
        resp.raw.headers = MagicMock()
        resp.raw.headers.getlist = lambda k: []
        return resp
    return _make


@pytest.fixture
def safe_html():
    """Simple HTML page with a safe form — marker should not reflect."""
    return """
    <html><body>
      <form action="/search" method="GET">
        <input name="q" type="text">
        <input type="submit" value="Search">
      </form>
    </body></html>
    """


@pytest.fixture
def reflected_html():
    """HTML page that reflects the test marker — simulates XSS risk."""
    return f"""
    <html><body>
      <p>You searched for: {TEST_MARKER}</p>
      <form action="/search" method="GET">
        <input name="q" type="text">
      </form>
    </body></html>
    """


@pytest.fixture
def malformed_html():
    """Deliberately malformed HTML to test parser resilience."""
    return "<html><body><form><input name='q'><div><p>unclosed"


@pytest.fixture
def empty_html():
    """Completely empty page."""
    return ""


@pytest.fixture
def no_forms_html():
    """Page with no forms."""
    return "<html><body><p>No forms here</p><a href='/about'>About</a></body></html>"
