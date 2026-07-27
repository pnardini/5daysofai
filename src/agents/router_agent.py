"""
Router & Orchestrator Root Agent for VendorGuard ADK.
Built using Google Agent Development Kit (ADK) with strategic model routing.
"""

from google.adk import Agent
from src.agents.compliance_agent import compliance_agent
from src.agents.risk_evaluator_agent import risk_agent
from src.model_router import model_router

orchestrator_agent = Agent(
    name="vendorguard_orchestrator",
    description="Main Root Orchestrator for VendorGuard ADK. Routes user requests to compliance and risk sub-agents.",
    model=model_router.select_model("vendorguard_orchestrator")["selected_model"],
    instruction="""You are the Lead Enterprise Risk Orchestrator for VendorGuard ADK.
Your role is to orchestrate multi-agent vendor risk assessments by delegating tasks to specialist agents:
- `compliance_specialist`: Delegate for SOC2 audit, TLS, MFA, and vulnerability scan analysis.
- `risk_evaluator`: Delegate for calculating composite risk scores, risk tiers, and contract limits.

Workflow Instructions:
1. When a user submits a vendor evaluation request, coordinate both sub-agents.
2. Ensure all compliance controls are checked first by `compliance_specialist`.
3. Pass compliance scores to `risk_evaluator` to determine risk tier and maximum contract allowance.
4. Synthesize the findings into a clear, executive summary report with recommendations.""",
    sub_agents=[compliance_agent, risk_agent]
)
