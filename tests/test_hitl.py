"""
Unit tests for Human-in-the-Loop Pause Hooks.
"""

import pytest
from src.app import app_service, EvaluationRequest


@pytest.mark.asyncio
async def test_hitl_pause_hook_triggered():
    # Submit request with security policy violations (no encryption, no MFA, deprecated TLS)
    req = EvaluationRequest(
        vendor_name="Risky Vendor Inc",
        data_sensitivity="Critical (Regulated / Financial)",
        encryption_at_rest=False,
        tls_version="TLS 1.0",
        mfa_enforced=False,
        pentest_frequency_months=24,
        soc2_report_age_months=24,
        notes="High risk vendor"
    )

    response = await app_service.evaluate_vendor(req)

    assert response.requires_human_approval is True
    assert response.status == "PAUSED_PENDING_HUMAN_APPROVAL"
    assert "HITL Pause Triggered" in response.hitl_trigger_reason
    assert response.evaluation_id in app_service.pending_hitl_evaluations

    # Submit Human decision: APPROVED
    approved_res = app_service.submit_human_decision(
        evaluation_id=response.evaluation_id,
        decision="APPROVED",
        reviewer_notes="Approved by CISO for exception."
    )

    assert approved_res.status == "APPROVED_BY_HUMAN"
    assert approved_res.requires_human_approval is False
    assert approved_res.evaluation_id not in app_service.pending_hitl_evaluations
