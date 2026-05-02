"""
logger.py — Structured logging for all DGIC layers.
Replaces all in-memory list-based logging with Python logging module.
"""

import logging
import sys
from config import LOG_LEVEL, LOG_FORMAT


def get_logger(name: str) -> logging.Logger:
    """Get a named logger with consistent formatting."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    return logger
