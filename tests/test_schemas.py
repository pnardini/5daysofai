"""
Unit tests for Pydantic Tool and UI Schemas.
"""

import pytest
from pydantic import ValidationError
from src.tools.schemas import (
    SOC2AuditInput,
    SOC2AuditOutput,
    VendorRiskCalculationInput,
    SensitivityLevel,
    RiskTier,
)


def test_soc2_audit_input_valid():
    inp = SOC2AuditInput(
        vendor_name="Acme Corp",
        encryption_at_rest=True,
        tls_version="TLS 1.3",
        mfa_enforced=True,
        pentest_frequency_months=12,
        soc2_report_age_months=6
    )
    assert inp.vendor_name == "Acme Corp"


def test_soc2_audit_input_invalid_months():
    with pytest.raises(ValidationError):
        SOC2AuditInput(
            vendor_name="Acme Corp",
            pentest_frequency_months=-5  # Must be >= 1
        )


def test_risk_calculation_input_valid():
    inp = VendorRiskCalculationInput(
        vendor_name="Cloud Vendor",
        soc2_compliance_score=90.0,
        critical_vulnerabilities=0,
        data_sensitivity=SensitivityLevel.HIGH,
        subprocessor_count=2
    )
    assert inp.soc2_compliance_score == 90.0
