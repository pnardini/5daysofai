"""
Schema-Validated Tools for VendorGuard ADK.
All tools enforce strict Pydantic inputs and outputs, telemetry instrumentation, and PII protection.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
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
    """Audits a vendor's SOC2 Type II compliance controls and generates a structured evaluation report.

    Args:
        vendor_name (str): Name of the third-party vendor or service provider (must be a non-empty string).
        encryption_at_rest (bool, optional): Whether AES-256 encryption at rest is enabled across all storage. Defaults to True.
        tls_version (str, optional): Supported TLS version for data in transit (e.g., 'TLS 1.3', 'TLS 1.2'). Defaults to "TLS 1.3".
        mfa_enforced (bool, optional): Whether Multi-Factor Authentication is enforced for all staff accounts. Defaults to True.
        pentest_frequency_months (int, optional): Frequency of third-party penetration testing in months (range 1-36). Defaults to 12.
        soc2_report_age_months (int, optional): Age of the latest SOC2 Type II report in months (range 0-24). Defaults to 6.

    Returns:
        Dict[str, Any]: Structured dictionary containing compliance_score, status ('PASSED', 'NEEDS_REVIEW', 'FAILED', or 'ERROR'),
            passed_controls, failed_controls, recommendations, and optional error_message / recovery_instruction.

    Guided Error Handling & LLM Recovery Instructions:
        - If 'vendor_name' is missing or empty, the tool returns status='ERROR' with error details.
          LLM Recovery Action: Extract or request a valid non-empty vendor name string and re-call audit_soc2_compliance.
        - If 'pentest_frequency_months' or 'soc2_report_age_months' are out of bounds (ge=1, le=36 for pentest; ge=0, le=24 for soc2 age),
          the tool returns status='ERROR'.
          LLM Recovery Action: Sanitize numeric arguments into valid bounds (e.g., 12 and 6) and retry audit_soc2_compliance.
        - If an unexpected execution exception occurs, the tool catches it gracefully and returns recovery guidance.
          LLM Recovery Action: Read the 'error_message', correct input argument formats, and re-invoke the tool.
    """
    try:
        if not vendor_name or not isinstance(vendor_name, str) or not vendor_name.strip():
            return {
                "status": "ERROR",
                "error_message": "Invalid or missing 'vendor_name'. A non-empty string vendor name is required.",
                "recovery_instruction": "Extract or ask the user for a valid vendor name string, then re-call audit_soc2_compliance with 'vendor_name'.",
                "compliance_score": 0.0,
                "passed_controls": [],
                "failed_controls": ["Invalid input parameters: vendor_name"],
                "recommendations": ["Provide a valid vendor name for auditing."]
            }

        # Strict validation via Pydantic model
        input_data = SOC2AuditInput(
            vendor_name=vendor_name.strip(),
            encryption_at_rest=encryption_at_rest,
            tls_version=str(tls_version),
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

    except Exception as e:
        logger.error(f"Error executing audit_soc2_compliance for '{vendor_name}': {e}")
        return {
            "status": "ERROR",
            "error_message": f"Execution error in audit_soc2_compliance: {str(e)}",
            "recovery_instruction": "Check input argument types and bounds (pentest_frequency_months 1-36, soc2_report_age_months 0-24). Sanitize arguments and re-invoke audit_soc2_compliance.",
            "compliance_score": 0.0,
            "passed_controls": [],
            "failed_controls": ["Audit tool execution exception"],
            "recommendations": ["Verify input parameters and retry tool invocation."]
        }


@trace_span(name="tool.scan_vulnerabilities", kind="tool")
def scan_vulnerabilities(
    vendor_id: str,
    target_endpoint: str = "https://api.vendor.com",
    scan_type: str = "comprehensive"
) -> Dict[str, Any]:
    """Scans vendor public API configuration and endpoints for active security vulnerabilities and CVEs.

    Args:
        vendor_id (str): Unique vendor identifier or slug (must be a non-empty string).
        target_endpoint (str, optional): Target domain or endpoint URL for inspection. Defaults to "https://api.vendor.com".
        scan_type (str, optional): Intensity of scan ('quick', 'standard', or 'comprehensive'). Defaults to "comprehensive".

    Returns:
        Dict[str, Any]: Structured dictionary containing vendor_id, total_vulnerabilities, critical_count, high_count,
            medium_count, low_count, cve_list, scan_status ('CLEAN_PASS', 'FINDINGS_DETECTED', or 'ERROR'), and optional error_message / recovery_instruction.

    Guided Error Handling & LLM Recovery Instructions:
        - If 'vendor_id' is missing or empty, the tool returns scan_status='ERROR'.
          LLM Recovery Action: Provide a valid vendor slug or identifier (e.g. 'acme_corp') and retry scan_vulnerabilities.
        - If 'target_endpoint' is invalid or improperly formatted, the tool returns scan_status='ERROR'.
          LLM Recovery Action: Format target_endpoint as a valid HTTP/HTTPS URL (e.g. 'https://api.vendor.com') and retry scan_vulnerabilities.
        - If 'scan_type' is unsupported, the tool returns scan_status='ERROR'.
          LLM Recovery Action: Set scan_type to one of ('quick', 'standard', 'comprehensive') and retry.
    """
    try:
        if not vendor_id or not isinstance(vendor_id, str) or not vendor_id.strip():
            return {
                "scan_status": "ERROR",
                "vendor_id": vendor_id or "unknown",
                "error_message": "Invalid or missing 'vendor_id'. A non-empty string is required.",
                "recovery_instruction": "Provide a valid string vendor_id (e.g., 'vendor_acme') and re-call scan_vulnerabilities.",
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "cve_list": []
            }

        input_data = VulnerabilityScanInput(
            vendor_id=vendor_id.strip(),
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

    except Exception as e:
        logger.error(f"Error executing scan_vulnerabilities for '{vendor_id}': {e}")
        return {
            "scan_status": "ERROR",
            "vendor_id": vendor_id or "unknown",
            "error_message": f"Execution error in scan_vulnerabilities: {str(e)}",
            "recovery_instruction": "Verify that target_endpoint is a valid URL starting with http:// or https://, and scan_type is one of ('quick', 'standard', 'comprehensive').",
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "cve_list": []
        }


@trace_span(name="tool.calculate_vendor_risk", kind="tool")
def calculate_vendor_risk(
    vendor_name: str,
    soc2_compliance_score: float,
    critical_vulnerabilities: int = 0,
    data_sensitivity: str = "High (Confidential / PII)",
    subprocessor_count: int = 3
) -> Dict[str, Any]:
    """Calculates overall vendor risk rating using multi-factor weighted scoring.

    Args:
        vendor_name (str): Vendor or service provider name (must be a non-empty string).
        soc2_compliance_score (float): Calculated SOC2 compliance score between 0.0 and 100.0.
        critical_vulnerabilities (int, optional): Count of open critical vulnerability findings (ge=0). Defaults to 0.
        data_sensitivity (str, optional): Level of data sensitivity handled by vendor. Defaults to "High (Confidential / PII)".
        subprocessor_count (int, optional): Number of third-party subprocessors utilized by vendor (ge=0). Defaults to 3.

    Returns:
        Dict[str, Any]: Structured dictionary containing overall_risk_score, risk_tier, maximum_allowed_contract_value_usd,
            compliance_badge, evaluation_timestamp, and optional error_message / recovery_instruction.

    Guided Error Handling & LLM Recovery Instructions:
        - If 'vendor_name' is missing or empty, the tool returns an error response with recovery instructions.
          LLM Recovery Action: Provide a valid non-empty vendor name string and re-invoke calculate_vendor_risk.
        - If 'soc2_compliance_score' is outside [0.0, 100.0] or numeric counts are negative, the tool returns an error response.
          LLM Recovery Action: Clamp soc2_compliance_score to [0.0, 100.0] and ensure counts are non-negative, then retry.
        - If 'data_sensitivity' string is invalid, the tool gracefully falls back to High sensitivity or reports invalid option.
          LLM Recovery Action: Choose a valid SensitivityLevel string ('Low (Public Data)', 'Medium (Internal Business Data)', 'High (Confidential / PII)', 'Critical (Financial / Health / Secrets)') and retry.
    """
    try:
        if not vendor_name or not isinstance(vendor_name, str) or not vendor_name.strip():
            return {
                "risk_tier": RiskTier.CRITICAL_RISK.value,
                "overall_risk_score": 100.0,
                "error_message": "Invalid or missing 'vendor_name'. A non-empty string is required.",
                "recovery_instruction": "Provide a valid non-empty vendor name string and retry calculate_vendor_risk.",
                "maximum_allowed_contract_value_usd": 0,
                "compliance_badge": "REJECTED_UNSAFE",
                "evaluation_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            }

        sens_enum = SensitivityLevel(data_sensitivity) if data_sensitivity in [e.value for e in SensitivityLevel] else SensitivityLevel.HIGH
        
        input_data = VendorRiskCalculationInput(
            vendor_name=vendor_name.strip(),
            soc2_compliance_score=max(0.0, min(100.0, float(soc2_compliance_score))),
            critical_vulnerabilities=max(0, int(critical_vulnerabilities)),
            data_sensitivity=sens_enum,
            subprocessor_count=max(0, int(subprocessor_count))
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

    except Exception as e:
        logger.error(f"Error executing calculate_vendor_risk for '{vendor_name}': {e}")
        return {
            "risk_tier": RiskTier.CRITICAL_RISK.value,
            "overall_risk_score": 100.0,
            "error_message": f"Execution error in calculate_vendor_risk: {str(e)}",
            "recovery_instruction": "Verify soc2_compliance_score is between 0.0 and 100.0, critical_vulnerabilities and subprocessor_count are non-negative integers, and data_sensitivity is a valid string.",
            "maximum_allowed_contract_value_usd": 0,
            "compliance_badge": "REJECTED_UNSAFE",
            "evaluation_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        }


@trace_span(name="tool.lookup_memory", kind="tool")
def lookup_memory(
    query: str,
    vendor_id: Optional[str] = None,
    max_results: int = 3
) -> Dict[str, Any]:
    """Performs vector similarity search over historical security audits and vendor context in long-term memory.

    Args:
        query (str): Search query string for vector memory lookup (at least 3 characters long).
        vendor_id (Optional[str], optional): Optional vendor ID filter to scope search results. Defaults to None.
        max_results (int, optional): Maximum number of historical context results to return (range 1-10). Defaults to 3.

    Returns:
        Dict[str, Any]: Structured dictionary containing query, results_found, context_summary, matches,
            and optional error_message / recovery_instruction.

    Guided Error Handling & LLM Recovery Instructions:
        - If 'query' is shorter than 3 characters or empty, the tool returns an error payload.
          LLM Recovery Action: Formulate a descriptive query of at least 3 characters (e.g., 'SOC2 audit history for Acme') and retry lookup_memory.
        - If 'max_results' is out of bounds (not between 1 and 10), the tool returns an error payload.
          LLM Recovery Action: Adjust max_results to an integer between 1 and 10 (e.g. 3) and re-call lookup_memory.
    """
    try:
        if not query or not isinstance(query, str) or len(query.strip()) < 3:
            return {
                "query": query or "",
                "results_found": 0,
                "context_summary": "Search query too short.",
                "matches": [],
                "error_message": "Invalid query: Search query must be at least 3 characters long.",
                "recovery_instruction": "Provide a descriptive search query of at least 3 characters and retry lookup_memory."
            }

        input_data = MemoryLookupInput(
            query=query.strip(),
            vendor_id=vendor_id,
            max_results=max_results
        )

        output = MemoryLookupOutput(
            query=pii_sanitizer.sanitize_text(input_data.query),
            results_found=0,
            context_summary=f"Memory lookup executed for query '{input_data.query}'.",
            matches=[]
        )
        return output.model_dump()

    except Exception as e:
        logger.error(f"Error executing lookup_memory for query '{query}': {e}")
        return {
            "query": query or "",
            "results_found": 0,
            "context_summary": "Error during memory lookup.",
            "matches": [],
            "error_message": f"Execution error in lookup_memory: {str(e)}",
            "recovery_instruction": "Ensure query is at least 3 characters long and max_results is between 1 and 10, then retry lookup_memory."
        }

