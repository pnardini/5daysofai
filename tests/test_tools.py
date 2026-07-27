"""
Unit tests for schema-validated Security Tools.
"""

from src.tools.security_tools import audit_soc2_compliance, scan_vulnerabilities, calculate_vendor_risk


def test_audit_soc2_compliance_pass():
    res = audit_soc2_compliance(
        vendor_name="Secure Vendor Inc.",
        encryption_at_rest=True,
        tls_version="TLS 1.3",
        mfa_enforced=True,
        pentest_frequency_months=12,
        soc2_report_age_months=6
    )
    assert res["compliance_score"] == 100.0
    assert res["status"] == "PASSED"
    assert len(res["passed_controls"]) == 5


def test_audit_soc2_compliance_fail():
    res = audit_soc2_compliance(
        vendor_name="Unsafe Vendor",
        encryption_at_rest=False,
        tls_version="TLS 1.0",
        mfa_enforced=False,
        pentest_frequency_months=24,
        soc2_report_age_months=18
    )
    assert res["compliance_score"] < 50.0
    assert res["status"] == "FAILED"
    assert len(res["failed_controls"]) > 0


def test_scan_vulnerabilities():
    res = scan_vulnerabilities(vendor_id="test_vendor")
    assert res["vendor_id"] == "test_vendor"
    assert res["total_vulnerabilities"] >= 0


def test_calculate_vendor_risk():
    res = calculate_vendor_risk(
        vendor_name="High Risk Vendor",
        soc2_compliance_score=50.0,
        critical_vulnerabilities=2,
        data_sensitivity="Critical (Financial / Health / Secrets)",
        subprocessor_count=5
    )
    assert res["overall_risk_score"] > 50.0
    assert "RISK" in res["risk_tier"]
