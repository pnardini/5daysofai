"""
Schema-Validated Tools for VendorGuard ADK.
All tools enforce strict Pydantic inputs and outputs, telemetry instrumentation, and PII protection.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from src.tools.schemas import (
    SOC2AuditInput,
    SOC2AuditOutput,
    VulnerabilityScanInput,
    VulnerabilityScanOutput,
    CVEItem,
    VendorRiskCalculationInput,
    VendorRiskCalculationOutput,
    RiskTier,
    SensitivityLevel,
    MemoryLookupInput,
    MemoryLookupOutput,
)
from src.pii_sanitizer import pii_sanitizer
from src.logger import logger
from src.telemetry import trace_span


@trace_span(name="tool.audit_soc2_compliance", kind="tool")
def audit_soc2_compliance(
    vendor_name: str,
    encryption_at_rest: bool = True,
    tls_version: str = "TLS 1.3",
    mfa_enforced: bool = True,
    pentest_frequency_months: int = 12,
    soc2_report_age_months: int = 6
) -> Dict[str, Any]:
    """Audits a vendor's SOC2 Type II compliance controls and generates a structured evaluation report."""
    # Strict validation via Pydantic model
    input_data = SOC2AuditInput(
        vendor_name=vendor_name,
        encryption_at_rest=encryption_at_rest,
        tls_version=tls_version,
        mfa_enforced=mfa_enforced,
        pentest_frequency_months=pentest_frequency_months,
        soc2_report_age_months=soc2_report_age_months
    )

    passed: List[str] = []
    failed: List[str] = []
    recommendations: List[str] = []
    score = 100.0

    if input_data.encryption_at_rest:
        passed.append("AES-256 Encryption at rest enabled")
    else:
        failed.append("Missing Encryption at Rest")
        recommendations.append("Enforce AES-256 encryption across all storage volumes")
        score -= 25.0

    if "1.3" in input_data.tls_version or "1.2" in input_data.tls_version:
        passed.append(f"Modern TLS Protocol ({input_data.tls_version})")
    else:
        failed.append(f"Outdated TLS Version ({input_data.tls_version})")
        recommendations.append("Upgrade transit security to TLS 1.3")
        score -= 20.0

    if input_data.mfa_enforced:
        passed.append("MFA Enforced across all user accounts")
    else:
        failed.append("MFA Not Enforced")
        recommendations.append("Mandate hardware or TOTP MFA for all employees")
        score -= 30.0

    if input_data.pentest_frequency_months <= 12:
        passed.append(f"Annual Penetration Testing ({input_data.pentest_frequency_months}m cycle)")
    else:
        failed.append(f"Infrequent Penetration Testing ({input_data.pentest_frequency_months}m cycle)")
        recommendations.append("Increase penetration test frequency to at least once per 12 months")
        score -= 15.0

    if input_data.soc2_report_age_months <= 12:
        passed.append(f"Current SOC2 Report ({input_data.soc2_report_age_months}m old)")
    else:
        failed.append(f"Stale SOC2 Report ({input_data.soc2_report_age_months}m old)")
        recommendations.append("Request an updated SOC2 Type II audit report from vendor")
        score -= 10.0

    score = max(0.0, score)
    status = "PASSED" if score >= 80.0 else ("NEEDS_REVIEW" if score >= 60.0 else "FAILED")

    output = SOC2AuditOutput(
        vendor_name=pii_sanitizer.sanitize_text(input_data.vendor_name),
        compliance_score=score,
        status=status,
        passed_controls=passed,
        failed_controls=failed,
        recommendations=recommendations
    )
    
    logger.info(f"Ran SOC2 Audit for {vendor_name}: score={score}, status={status}")
    return output.model_dump()


@trace_span(name="tool.scan_vulnerabilities", kind="tool")
def scan_vulnerabilities(
    vendor_id: str,
    target_endpoint: str = "https://api.vendor.com",
    scan_type: str = "comprehensive"
) -> Dict[str, Any]:
    """Scans vendor public API configuration and endpoints for active security vulnerabilities and CVEs."""
    input_data = VulnerabilityScanInput(
        vendor_id=vendor_id,
        target_endpoint=target_endpoint,
        scan_type=scan_type
    )

    # Simulated deterministic vulnerability inspection engine
    cve_list = [
        CVEItem(cve_id="CVE-2025-1082", severity="MEDIUM", description="Suboptimal HTTP Strict Transport Security header configuration"),
        CVEItem(cve_id="CVE-2024-9921", severity="LOW", description="Verbose server version header disclosed in response")
    ]
    
    output = VulnerabilityScanOutput(
        vendor_id=pii_sanitizer.sanitize_text(input_data.vendor_id),
        total_vulnerabilities=len(cve_list),
        critical_count=0,
        high_count=0,
        medium_count=1,
        low_count=1,
        cve_list=cve_list,
        scan_status="CLEAN_PASS"
    )

    logger.info(f"Completed Vulnerability Scan for {vendor_id}: found {output.total_vulnerabilities} findings")
    return output.model_dump()


@trace_span(name="tool.calculate_vendor_risk", kind="tool")
def calculate_vendor_risk(
    vendor_name: str,
    soc2_compliance_score: float,
    critical_vulnerabilities: int = 0,
    data_sensitivity: str = "High (Confidential / PII)",
    subprocessor_count: int = 3
) -> Dict[str, Any]:
    """Calculates overall vendor risk rating using multi-factor weighted scoring."""
    sens_enum = SensitivityLevel(data_sensitivity) if data_sensitivity in [e.value for e in SensitivityLevel] else SensitivityLevel.HIGH
    
    input_data = VendorRiskCalculationInput(
        vendor_name=vendor_name,
        soc2_compliance_score=soc2_compliance_score,
        critical_vulnerabilities=critical_vulnerabilities,
        data_sensitivity=sens_enum,
        subprocessor_count=subprocessor_count
    )

    # Calculate risk score (0 = lowest risk, 100 = highest risk)
    base_risk = 100.0 - input_data.soc2_compliance_score
    vuln_risk = input_data.critical_vulnerabilities * 20.0
    subprocessor_risk = min(input_data.subprocessor_count * 3.0, 15.0)

    sensitivity_weight = {
        SensitivityLevel.LOW: 0.5,
        SensitivityLevel.MEDIUM: 1.0,
        SensitivityLevel.HIGH: 1.3,
        SensitivityLevel.CRITICAL: 1.6,
    }[input_data.data_sensitivity]

    total_risk = min(100.0, max(0.0, (base_risk + vuln_risk + subprocessor_risk) * sensitivity_weight / 1.3))

    if total_risk < 25.0:
        tier = RiskTier.LOW_RISK
        max_val = 5_000_000
        badge = "GOLD_TRUSTED"
    elif total_risk < 50.0:
        tier = RiskTier.MEDIUM_RISK
        max_val = 1_000_000
        badge = "SILVER_APPROVED"
    elif total_risk < 75.0:
        tier = RiskTier.HIGH_RISK
        max_val = 250_000
        badge = "BRONZE_CONDITIONAL"
    else:
        tier = RiskTier.CRITICAL_RISK
        max_val = 0
        badge = "REJECTED_UNSAFE"

    output = VendorRiskCalculationOutput(
        vendor_name=pii_sanitizer.sanitize_text(input_data.vendor_name),
        overall_risk_score=round(total_risk, 1),
        risk_tier=tier,
        maximum_allowed_contract_value_usd=max_val,
        compliance_badge=badge,
        evaluation_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    logger.info(f"Calculated Risk for {vendor_name}: score={output.overall_risk_score}, tier={output.risk_tier.value}")
    return output.model_dump()
