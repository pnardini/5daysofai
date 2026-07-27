"""
JSON Structured Logger for VendorGuard ADK.
Outputs strictly valid JSON string log lines with automatic PII sanitization.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Custom logging formatter that produces JSON formatted string output with scrubbed PII."""

    def format(self, record: logging.LogRecord) -> str:
        from src.pii_sanitizer import pii_sanitizer

        log_object: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": pii_sanitizer.sanitize_text(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include extra dictionary fields if provided
        if hasattr(record, "payload") and isinstance(record.payload, dict):
            log_object["payload"] = pii_sanitizer.sanitize_data(record.payload)

        if record.exc_info:
            log_object["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_object, ensure_ascii=False)


def setup_logger(name: str = "vendorguard", level: str = "INFO") -> logging.Logger:
    """Configures and returns a logger instance with JSON formatting."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


logger = setup_logger()
