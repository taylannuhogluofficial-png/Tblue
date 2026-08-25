"""
Shared constants across all Tblue modules.
"""

from typing import Dict

from tblue import __version__

# Single source of truth is tblue/__init__.py. Kept as an alias so the two can
# never drift again — constants.py said 1.0.0 through the whole 1.0.1 release.
VERSION: str = __version__

TEST_MARKER: str = "xssreflectcheck1337"

# Template injection markers: (marker_string, engine_name)
TEMPLATE_MARKERS = [
    ("{{xsstpl1337}}",   "Jinja2/Handlebars"),
    ("${xsstpl1337}",    "EL/JSP/Thymeleaf"),
    ("<%=xsstpl1337%>",  "ERB"),
]

# Terminal colors
RED:    str = "\033[91m"
GREEN:  str = "\033[92m"
YELLOW: str = "\033[93m"
BLUE:   str = "\033[94m"
CYAN:   str = "\033[96m"
BOLD:   str = "\033[1m"
RESET:  str = "\033[0m"

DEFAULT_USER_AGENT: str = (
    f"Tblue/{VERSION} (self-audit; https://github.com/taylannuhogluofficial-png/Tblue)"
)
DEFAULT_TIMEOUT:    int = 8
DEFAULT_DEPTH:      int = 3
DEFAULT_RETRIES:    int = 3
DEFAULT_BACKOFF:    float = 1.5   # seconds between retries
DEFAULT_RATE_LIMIT: float = 0.25  # seconds between requests

GRADE_COLORS: Dict[str, str] = {
    "A+": GREEN,
    "A":  GREEN,
    "B":  GREEN,
    "C":  YELLOW,
    "D":  YELLOW,
    "F":  RED,
}
