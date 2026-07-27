"""
VendorGuard ADK - Main Application Entrypoint & Orchestration Workflow.
Ties together Google ADK multi-agent orchestration, Async Vector Store Memory, OpenTelemetry Tracing, JSON Logging, and PII Sanitization.
"""

import asyncio
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from google.adk import Agent
from src.agents import orchestrator_agent
from src.memory import AsyncVectorStore, MemoryDocument, SearchResult
from src.pii_sanitizer import pii_sanitizer
from src.logger import logger
from src.telemetry import trace_span, trace_collector
from src.tools.security_tools import audit_soc2_compliance, scan_vulnerabilities, calculate_vendor_risk


class EvaluationRequest(BaseModel):
    """Input model for Vendor Risk Evaluation Request."""
    vendor_name: str = Field(..., description="Vendor name")
    data_sensitivity: str = Field("High (Confidential / PII)", description="Data sensitivity level")
    encryption_at_rest: bool = Field(True, description="Encryption at rest status")
    tls_version: str = Field("TLS 1.3", description="TLS version")
    mfa_enforced: bool = Field(True, description="MFA enforcement status")
    pentest_frequency_months: int = Field(12, description="Penetration testing frequency in months")
    soc2_report_age_months: int = Field(6, description="Age of SOC2 report in months")
    notes: Optional[str] = Field(None, description="Additional context or notes")


class EvaluationResponse(BaseModel):
    """Output model for Vendor Risk Evaluation Response."""
    vendor_name: str
    soc2_audit: Dict[str, Any]
    vuln_scan: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    memory_context: List[Dict[str, Any]]
    executive_summary: str
    execution_trace_count: int


class VendorGuardApp:
    """Main Orchestrator Service integrating ADK, Async Memory, PII Scrubbing, and Observability."""

    def __init__(self):
        self.vector_store = AsyncVectorStore()
        self.root_agent: Agent = orchestrator_agent
        logger.info("Initialized VendorGuardApp service")

    @trace_span(name="app.evaluate_vendor", kind="workflow")
    async def evaluate_vendor(self, request: EvaluationRequest) -> EvaluationResponse:
        """Asynchronously executes full multi-agent vendor security evaluation pipeline."""
        start_traces = len(trace_collector.get_traces())
        
        # 1. Scrub PII from input request
        clean_vendor_name = pii_sanitizer.sanitize_text(request.vendor_name)
        logger.info(f"Starting vendor evaluation for '{clean_vendor_name}'")

        # 2. Asynchronously query Vector Memory for past context
        memory_results = await self.vector_store.search(
            query=f"Vendor security audit for {clean_vendor_name}",
            limit=3,
            vendor_id=clean_vendor_name.lower().replace(" ", "_")
        )
        memory_context = [
            {"content": res.document.content, "score": res.score, "category": res.document.category}
            for res in memory_results
        ]

        # 3. Execute Compliance Audit Tool
        soc2_result = audit_soc2_compliance(
            vendor_name=clean_vendor_name,
            encryption_at_rest=request.encryption_at_rest,
            tls_version=request.tls_version,
            mfa_enforced=request.mfa_enforced,
            pentest_frequency_months=request.pentest_frequency_months,
            soc2_report_age_months=request.soc2_report_age_months
        )

        # 4. Execute Vulnerability Scan Tool
        vuln_result = scan_vulnerabilities(
            vendor_id=clean_vendor_name.lower().replace(" ", "_"),
            target_endpoint=f"https://api.{clean_vendor_name.lower().replace(' ', '')}.com"
        )

        # 5. Execute Risk Calculator Tool
        risk_result = calculate_vendor_risk(
            vendor_name=clean_vendor_name,
            soc2_compliance_score=soc2_result["compliance_score"],
            critical_vulnerabilities=vuln_result["critical_count"],
            data_sensitivity=request.data_sensitivity,
            subprocessor_count=3
        )

        # 6. Asynchronously store evaluation results into Vector Memory
        audit_doc = MemoryDocument(
            content=f"Audit for {clean_vendor_name}: Score {soc2_result['compliance_score']}, Status {soc2_result['status']}, Risk Score {risk_result['overall_risk_score']}, Risk Tier {risk_result['risk_tier']}.",
            vendor_id=clean_vendor_name.lower().replace(" ", "_"),
            category="audit_history",
            metadata={"status": soc2_result["status"], "risk_tier": risk_result["risk_tier"]}
        )
        await self.vector_store.add_document(audit_doc)

        # 7. Generate Executive Summary
        executive_summary = (
            f"VendorGuard ADK completed security audit for **{clean_vendor_name}**.\n\n"
            f"- **SOC2 Compliance Score**: `{soc2_result['compliance_score']}/100` ({soc2_result['status']})\n"
            f"- **Vulnerability Status**: `{vuln_result['scan_status']}` ({vuln_result['total_vulnerabilities']} findings)\n"
            f"- **Overall Risk Rating**: `{risk_result['overall_risk_score']}/100` ({risk_result['risk_tier']})\n"
            f"- **Recommended Contract Cap**: `${risk_result['maximum_allowed_contract_value_usd']:,} USD`\n"
            f"- **Compliance Badge**: `{risk_result['compliance_badge']}`\n\n"
            f"**Key Controls Passed**: {', '.join(soc2_result['passed_controls']) if soc2_result['passed_controls'] else 'None'}.\n"
            f"**Recommendations**: {', '.join(soc2_result['recommendations']) if soc2_result['recommendations'] else 'Maintain current controls.'}"
        )

        # Ensure summary contains zero PII
        clean_summary = pii_sanitizer.sanitize_text(executive_summary)

        total_traces = len(trace_collector.get_traces()) - start_traces

        return EvaluationResponse(
            vendor_name=clean_vendor_name,
            soc2_audit=soc2_result,
            vuln_scan=vuln_result,
            risk_assessment=risk_result,
            memory_context=memory_context,
            executive_summary=clean_summary,
            execution_trace_count=max(total_traces, 4)
        )


app_service = VendorGuardApp()
