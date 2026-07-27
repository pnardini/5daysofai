"""
Unit tests for PII Sanitizer engine.
"""

from src.pii_sanitizer import pii_sanitizer


def test_sanitize_email():
    text = "Contact user at john.doe@example.com for info."
    cleaned = pii_sanitizer.sanitize_text(text)
    assert "john.doe@example.com" not in cleaned
    assert "[REDACTED_EMAIL]" in cleaned


def test_sanitize_ssn():
    text = "Employee SSN is 123-45-6789."
    cleaned = pii_sanitizer.sanitize_text(text)
    assert "123-45-6789" not in cleaned
    assert "[REDACTED_SSN]" in cleaned


def test_sanitize_ip_address():
    text = "Client IP address: 192.168.1.50"
    cleaned = pii_sanitizer.sanitize_text(text)
    assert "192.168.1.50" not in cleaned
    assert "[REDACTED_IP_ADDRESS]" in cleaned


def test_sanitize_dict():
    raw_data = {
        "user_email": "alice@test.com",
        "nested": {"ssn": "987-65-4321", "public_id": "item_100"}
    }
    cleaned = pii_sanitizer.sanitize_data(raw_data)
    assert cleaned["user_email"] == "[REDACTED_EMAIL]"
    assert cleaned["nested"]["ssn"] == "[REDACTED_SSN]"
    assert cleaned["nested"]["public_id"] == "item_100"
