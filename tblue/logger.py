"""
Centralized logging for Tblue.
Uses Python's standard logging module instead of print statements.
"""

import logging
import sys
from tblue.constants import RED, GREEN, YELLOW, BLUE, CYAN, BOLD, RESET


class ColorFormatter(logging.Formatter):
    """Custom formatter that adds colors based on log level."""

    FORMATS = {
        logging.DEBUG:    CYAN   + "[%(asctime)s] [DEBUG] " + RESET + "%(message)s",
        logging.INFO:     CYAN   + "[%(asctime)s] [INFO]  " + RESET + "%(message)s",
        logging.WARNING:  YELLOW + "[%(asctime)s] [WARN]  " + RESET + "%(message)s",
        logging.ERROR:    RED    + "[%(asctime)s] [FAIL]  " + RESET + "%(message)s",
        logging.CRITICAL: BOLD   + RED + "[%(asctime)s] [CRIT]  " + RESET + "%(message)s",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with color based on level."""
        fmt = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        return formatter.format(record)


def get_logger(name: str = "tblue") -> logging.Logger:
    """
    Get a named logger with color formatting.
    Call once per module: logger = get_logger(__name__)
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    return logger


def set_level(verbose: bool = False) -> None:
    """Set global log level — DEBUG if verbose, INFO otherwise."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("tblue").setLevel(level)


# Convenience pass/fail log helpers used across modules
def log_pass(logger: logging.Logger, msg: str) -> None:
    """Log a green PASS message."""
    logger.info(GREEN + "✅ " + RESET + msg)


def log_fail(logger: logging.Logger, msg: str) -> None:
    """Log a red FAIL message."""
    logger.error(RED + "❌ " + RESET + msg)


def log_warn(logger: logging.Logger, msg: str) -> None:
    """Log a yellow WARN message."""
    logger.warning(YELLOW + "⚠️  " + RESET + msg)


def log_head(logger: logging.Logger, msg: str) -> None:
    """Log a bold blue section header."""
    logger.info(BOLD + BLUE + "►  " + RESET + msg)
