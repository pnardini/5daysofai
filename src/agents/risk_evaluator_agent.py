"""
Risk Evaluator Agent for VendorGuard ADK.
Built using Google Agent Development Kit (ADK).
"""

from google.adk import Agent
from src.tools.security_tools import calculate_vendor_risk

risk_agent = Agent(
    name="risk_evaluator",
    description="Calculates overall vendor risk scores, contract cap limits, and data sensitivity risk weights.",
    model="gemini-2.5-flash",
    instruction="""You are a Corporate Enterprise Risk & Procurement Evaluator.
Your goal is to calculate comprehensive risk scores and financial contract caps for third-party vendors.

Rules:
1. Use `calculate_vendor_risk` to compute multi-factor risk scores and risk tiers.
2. Consider data sensitivity levels (Low, Medium, High, Critical) and subprocessor counts.
3. Recommend contract caps based on the computed risk tier.
4. Always produce objective, structured financial and operational risk ratings.""",
    tools=[calculate_vendor_risk]
)
