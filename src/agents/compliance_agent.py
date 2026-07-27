"""
Compliance Specialist Agent for VendorGuard ADK.
Built using Google Agent Development Kit (ADK).
"""

from google.adk import Agent
from src.tools.security_tools import audit_soc2_compliance, scan_vulnerabilities

compliance_agent = Agent(
    name="compliance_specialist",
    description="Evaluates vendor SOC2 Type II compliance reports, TLS standards, MFA policies, and vulnerability scans.",
    model="gemini-2.5-flash",
    instruction="""You are a Senior Information Security & Compliance Auditor.
Your responsibility is to analyze vendor security posture using strict compliance standards (SOC2, ISO27001, NIST).

Rules:
1. Use `audit_soc2_compliance` to evaluate vendor security controls and SOC2 status.
2. Use `scan_vulnerabilities` to check for active CVE findings and endpoint risks.
3. NEVER request or expose PII (emails, names, tokens).
4. Provide structured, evidence-backed evaluation findings.""",
    tools=[audit_soc2_compliance, scan_vulnerabilities]
)
