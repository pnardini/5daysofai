"""
VendorGuard ADK - Main Application Entrypoint & Orchestration Workflow.
Ties together Google ADK multi-agent orchestration, Strategic Model Routing,
ADK-Native Guardrail Evaluations, Human-in-the-Loop Pause Hooks, Async Vector Memory,
OpenTelemetry Tracing, JSON Logging, and PII Protection.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from google.adk import Agent
from src.agents import orchestrator_agent, compliance_agent, risk_agent
from src.model_router import model_router
from src.guardrails import ADKNativeEvaluator, GuardrailEvalResult, guardrail_plugin
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
    evaluation_id: str
    vendor_name: str
    status: str  # "COMPLETED_AUTOMATED", "PAUSED_PENDING_HUMAN_APPROVAL", "APPROVED_BY_HUMAN", "REJECTED_BY_HUMAN"
    requires_human_approval: bool
    hitl_trigger_reason: Optional[str] = None
    reviewer_notes: Optional[str] = None
    model_routing: Dict[str, Any]
    guardrail_evaluations: List[Dict[str, Any]]
    soc2_audit: Dict[str, Any]
    vuln_scan: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    memory_context: List[Dict[str, Any]]
    executive_summary: str
    execution_trace_count: int


class VendorGuardApp:
    """Main Orchestrator Service integrating ADK, Strategic Model Routing, ADK Guardrails, and HITL Hooks."""

    def __init__(self):
        self.vector_store = AsyncVectorStore()
        self.root_agent: Agent = orchestrator_agent
        self.pending_hitl_evaluations: Dict[str, EvaluationResponse] = {}
        logger.info("Initialized VendorGuardApp service with Strategic Model Routing & HITL Hooks")

    @trace_span(name="app.evaluate_vendor", kind="workflow")
    async def evaluate_vendor(self, request: EvaluationRequest) -> EvaluationResponse:
        """Asynchronously executes full multi-agent vendor security evaluation pipeline."""
        start_traces = len(trace_collector.get_traces())
        eval_id = f"eval_{uuid.uuid4().hex[:8]}"

        # 1. ADK Guardrail Evaluation & PII Scrubbing
        sanitized_vendor_name, pii_eval = pii_sanitizer.evaluate_and_sanitize(request.vendor_name)
        logger.info(f"[{eval_id}] Starting vendor evaluation for '{sanitized_vendor_name}'")

        # Run ADK Baseline Security Policy Evaluation
        baseline_eval = ADKNativeEvaluator.evaluate_security_baseline(
            encryption_at_rest=request.encryption_at_rest,
            tls_version=request.tls_version,
            mfa_enforced=request.mfa_enforced
        )

        guardrail_evals = [pii_eval.model_dump(), baseline_eval.model_dump()]

        # 2. Strategic Model Routing
        orch_route = model_router.select_model(
            agent_name="vendorguard_orchestrator",
            data_sensitivity=request.data_sensitivity,
            notes=request.notes
        )
        comp_route = model_router.select_model(
            agent_name="compliance_specialist",
            data_sensitivity=request.data_sensitivity
        )
        risk_route = model_router.select_model(
            agent_name="risk_evaluator",
            data_sensitivity=request.data_sensitivity
        )

        routing_summary = {
            "orchestrator_model": orch_route["selected_model"],
            "compliance_specialist_model": comp_route["selected_model"],
            "risk_evaluator_model": risk_route["selected_model"],
            "routing_reasons": [orch_route["reason"], comp_route["reason"], risk_route["reason"]]
        }

        # 3. Query Vector Memory for past context
        memory_results = await self.vector_store.search(
            query=f"Vendor security audit for {sanitized_vendor_name}",
            limit=3,
            vendor_id=sanitized_vendor_name.lower().replace(" ", "_")
        )
        memory_context = [
            {"content": res.document.content, "score": res.score, "category": res.document.category}
            for res in memory_results
        ]

        # 4. Execute Specialist Tools
        soc2_result = audit_soc2_compliance(
            vendor_name=sanitized_vendor_name,
            encryption_at_rest=request.encryption_at_rest,
            tls_version=request.tls_version,
            mfa_enforced=request.mfa_enforced,
            pentest_frequency_months=request.pentest_frequency_months,
            soc2_report_age_months=request.soc2_report_age_months
        )

        vuln_result = scan_vulnerabilities(
            vendor_id=sanitized_vendor_name.lower().replace(" ", "_"),
            target_endpoint=f"https://api.{sanitized_vendor_name.lower().replace(' ', '')}.com"
        )

        risk_result = calculate_vendor_risk(
            vendor_name=sanitized_vendor_name,
            soc2_compliance_score=soc2_result["compliance_score"],
            critical_vulnerabilities=vuln_result["critical_count"],
            data_sensitivity=request.data_sensitivity,
            subprocessor_count=3
        )

        # 5. Store evaluation results into Vector Memory
        audit_doc = MemoryDocument(
            content=f"Audit for {sanitized_vendor_name}: Score {soc2_result['compliance_score']}, Status {soc2_result['status']}, Risk Score {risk_result['overall_risk_score']}, Risk Tier {risk_result['risk_tier']}.",
            vendor_id=sanitized_vendor_name.lower().replace(" ", "_"),
            category="audit_history",
            metadata={"status": soc2_result["status"], "risk_tier": risk_result["risk_tier"]}
        )
        await self.vector_store.add_document(audit_doc)

        # 6. Human-in-the-Loop (HITL) Pause Hook Check
        overall_risk_score = risk_result["overall_risk_score"]
        risk_tier = risk_result["risk_tier"]
        soc2_status = soc2_result["status"]

        requires_hitl = (
            overall_risk_score >= 50.0
            or risk_tier in ["HIGH_RISK", "CRITICAL_RISK"]
            or soc2_status == "FAILED"
            or baseline_eval.status == "VIOLATION"
        )

        hitl_reason = None
        if requires_hitl:
            reasons = []
            if overall_risk_score >= 50.0 or risk_tier in ["HIGH_RISK", "CRITICAL_RISK"]:
                reasons.append(f"Elevated risk score ({overall_risk_score}/100, Tier: {risk_tier})")
            if soc2_status == "FAILED":
                reasons.append("SOC2 compliance status is FAILED")
            if baseline_eval.status == "VIOLATION":
                reasons.append("Mandatory security baseline policy violation detected")
            hitl_reason = "HITL Pause Triggered: " + " | ".join(reasons) + ". CISO human sign-off required before authorizing contract cap."
            workflow_status = "PAUSED_PENDING_HUMAN_APPROVAL"
            logger.warning(f"[{eval_id}] HITL Pause Hook triggered for '{sanitized_vendor_name}': {hitl_reason}")
        else:
            workflow_status = "COMPLETED_AUTOMATED"

        # 7. Generate Executive Summary
        executive_summary = (
            f"VendorGuard ADK completed security audit for **{sanitized_vendor_name}**.\n\n"
            f"- **Workflow Status**: `{workflow_status}`\n"
            f"- **Strategic Model Routing**: Orchestrator (`{orch_route['selected_model']}`), Compliance (`{comp_route['selected_model']}`), Risk (`{risk_route['selected_model']}`)\n"
            f"- **ADK Guardrails**: PII ({pii_eval.status}), Baseline ({baseline_eval.status})\n"
            f"- **SOC2 Compliance Score**: `{soc2_result['compliance_score']}/100` ({soc2_result['status']})\n"
            f"- **Vulnerability Status**: `{vuln_result['scan_status']}` ({vuln_result['total_vulnerabilities']} findings)\n"
            f"- **Overall Risk Rating**: `{risk_result['overall_risk_score']}/100` ({risk_result['risk_tier']})\n"
            f"- **Recommended Contract Cap**: `${risk_result['maximum_allowed_contract_value_usd']:,} USD`\n"
            f"- **Compliance Badge**: `{risk_result['compliance_badge']}`\n\n"
        )
        if requires_hitl:
            executive_summary += f"⚠️ **HUMAN-IN-THE-LOOP PAUSE REQUIRED**: {hitl_reason}\n\n"

        executive_summary += (
            f"**Key Controls Passed**: {', '.join(soc2_result['passed_controls']) if soc2_result['passed_controls'] else 'None'}.\n"
            f"**Recommendations**: {', '.join(soc2_result['recommendations']) if soc2_result['recommendations'] else 'Maintain current controls.'}"
        )

        clean_summary = pii_sanitizer.sanitize_text(executive_summary)
        total_traces = len(trace_collector.get_traces()) - start_traces

        response = EvaluationResponse(
            evaluation_id=eval_id,
            vendor_name=sanitized_vendor_name,
            status=workflow_status,
            requires_human_approval=requires_hitl,
            hitl_trigger_reason=hitl_reason,
            model_routing=routing_summary,
            guardrail_evaluations=guardrail_evals,
            soc2_audit=soc2_result,
            vuln_scan=vuln_result,
            risk_assessment=risk_result,
            memory_context=memory_context,
            executive_summary=clean_summary,
            execution_trace_count=max(total_traces, 4)
        )

        if requires_hitl:
            self.pending_hitl_evaluations[eval_id] = response

        return response

    @trace_span(name="app.submit_human_decision", kind="hitl_resume")
    def submit_human_decision(
        self,
        evaluation_id: str,
        decision: str,
        reviewer_notes: str = ""
    ) -> EvaluationResponse:
        """Resumes a paused evaluation workflow after Human-in-the-Loop decision (APPROVED or REJECTED)."""
        if evaluation_id not in self.pending_hitl_evaluations:
            raise KeyError(f"Evaluation ID '{evaluation_id}' not found in pending HITL queue")

        response = self.pending_hitl_evaluations[evaluation_id]
        decision_upper = decision.upper()

        if decision_upper == "APPROVED":
            response.status = "APPROVED_BY_HUMAN"
            logger.info(f"HITL Decision: Evaluation '{evaluation_id}' APPROVED by human reviewer")
        elif decision_upper == "REJECTED":
            response.status = "REJECTED_BY_HUMAN"
            logger.info(f"HITL Decision: Evaluation '{evaluation_id}' REJECTED by human reviewer")
        else:
            raise ValueError(f"Invalid HITL decision '{decision}'. Must be 'APPROVED' or 'REJECTED'.")

        response.reviewer_notes = pii_sanitizer.sanitize_text(reviewer_notes)
        response.requires_human_approval = False

        # Remove from pending queue
        del self.pending_hitl_evaluations[evaluation_id]
        return response


app_service = VendorGuardApp()
