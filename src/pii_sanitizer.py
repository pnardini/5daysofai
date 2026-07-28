"""
PII Redaction Engine & ADK Guardrail Evaluation Integration for VendorGuard ADK.
Ensures zero PII is logged, stored in memory, or sent to external services.
"""

import re
from typing import Any, Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from src.guardrails import GuardrailEvalResult


class PIISanitizer:
    """PII Sanitizer & Guardrail evaluator for scrubbing Personally Identifiable Information (PII)."""

    PATTERNS: Dict[str, re.Pattern] = {
        "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.IGNORECASE),
        "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "IP_ADDRESS": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "API_KEY": re.compile(r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?", re.IGNORECASE),
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    }

    @classmethod
    def evaluate_and_sanitize(cls, text: str) -> Tuple[str, "GuardrailEvalResult"]:
        """Runs ADK-native evaluation and sanitizes text.

        Args:
            text (str): Input raw text string to evaluate and redact.

        Returns:
            Tuple[str, GuardrailEvalResult]: Tuple containing the redacted text string and the ADK Guardrail evaluation result.
        """
        from src.guardrails import ADKNativeEvaluator
        eval_result = ADKNativeEvaluator.evaluate_pii_safety(text)
        sanitized = cls.sanitize_text(text)
        return sanitized, eval_result

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Sanitize a raw string by replacing matching PII patterns with redacted placeholders.

        Args:
            text (str): Input text string.

        Returns:
            str: PII-sanitized text string with redacted placeholders.
        """
        if not text or not isinstance(text, str):
            return text if text is not None else ""

        sanitized = text
        sanitized = cls.PATTERNS["API_KEY"].sub(r"api_key: [REDACTED_SECRET]", sanitized)

        for pii_type, pattern in cls.PATTERNS.items():
            if pii_type == "API_KEY":
                continue
            sanitized = pattern.sub(f"[REDACTED_{pii_type}]", sanitized)

        return sanitized

    @classmethod
    def sanitize_data(cls, data: Any) -> Any:
        """Recursively sanitize nested dictionaries, lists, or primitive types.

        Args:
            data (Any): Arbitrary input data structure (dict, list, string, primitive).

        Returns:
            Any: Data structure with all embedded text strings sanitized for PII.
        """
        if isinstance(data, str):
            return cls.sanitize_text(data)
        elif isinstance(data, dict):
            return {key: cls.sanitize_data(val) for key, val in data.items()}
        elif isinstance(data, list):
            return [cls.sanitize_data(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(cls.sanitize_data(item) for item in data)
        return data


# Global singleton instance
pii_sanitizer = PIISanitizer()
