"""
Unit tests for ADK-Native Guardrail Evaluations.
"""

from src.guardrails import ADKNativeEvaluator


def test_pii_evaluator_clean():
    eval_res = ADKNativeEvaluator.evaluate_pii_safety("Safe clean prompt")
    assert eval_res.status == "PASSED"
    assert eval_res.safety_score == 1.0
    assert len(eval_res.violations_detected) == 0


def test_pii_evaluator_violations():
    eval_res = ADKNativeEvaluator.evaluate_pii_safety("Contact user@test.com with AKIAIOSFODNN7EXAMPLE")
    assert eval_res.status == "VIOLATION"
    assert eval_res.safety_score < 1.0
    assert "EMAIL_EXPOSURE" in eval_res.violations_detected
    assert "AWS_ACCESS_KEY_EXPOSURE" in eval_res.violations_detected


def test_security_baseline_evaluator_passed():
    eval_res = ADKNativeEvaluator.evaluate_security_baseline(
        encryption_at_rest=True,
        tls_version="TLS 1.3",
        mfa_enforced=True
    )
    assert eval_res.status == "PASSED"
    assert eval_res.safety_score == 1.0


def test_security_baseline_evaluator_violation():
    eval_res = ADKNativeEvaluator.evaluate_security_baseline(
        encryption_at_rest=False,
        tls_version="TLS 1.0",
        mfa_enforced=False
    )
    assert eval_res.status == "VIOLATION"
    assert eval_res.safety_score <= 0.2
    assert "MANDATORY_ENCRYPTION_REST_MISSING" in eval_res.violations_detected
    assert "INSECURE_TLS_PROTOCOL" in eval_res.violations_detected
    assert "MFA_ENFORCEMENT_MISSING" in eval_res.violations_detected
