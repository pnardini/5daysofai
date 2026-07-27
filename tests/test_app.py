"""
Integration tests for VendorGuard App workflow.
"""

import pytest
from src.app import app_service, EvaluationRequest


@pytest.mark.asyncio
async def test_evaluate_vendor_e2e():
    req = EvaluationRequest(
        vendor_name="E2E Test Vendor",
        data_sensitivity="Medium (Internal Business Data)",
        encryption_at_rest=True,
        tls_version="TLS 1.3",
        mfa_enforced=True,
        pentest_frequency_months=12,
        soc2_report_age_months=6,
        notes="Email test contact@vendor.com"
    )

    response = await app_service.evaluate_vendor(req)

    assert response.vendor_name == "E2E Test Vendor"
    assert response.soc2_audit["compliance_score"] == 100.0
    assert response.risk_assessment["overall_risk_score"] < 50.0
    assert "E2E Test Vendor" in response.executive_summary
    assert "contact@vendor.com" not in response.executive_summary
    assert response.execution_trace_count >= 1
