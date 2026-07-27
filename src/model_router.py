"""
Strategic Model Routing for VendorGuard ADK.
Dynamically routes requests between lightweight (Flash) and reasoning (Pro) models
based on agent role, request complexity, and data sensitivity.
"""

from enum import Enum
from typing import Dict, Any, Optional
from src.logger import logger
from src.telemetry import trace_span


class ModelTier(str, Enum):
    FLASH = "gemini-2.5-flash"
    PRO = "gemini-2.5-pro"


class ModelRouter:
    """Strategic model router to optimize latency, cost, and reasoning accuracy."""

    def __init__(self, default_model: str = ModelTier.FLASH.value):
        self.default_model = default_model

    @trace_span(name="model_router.select_model", kind="routing")
    def select_model(
        self,
        agent_name: str,
        data_sensitivity: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Selects appropriate Gemini model based on agent specialization and request risk factors.
        
        Routing Logic:
        - Orchestrator: Uses Flash for fast routing and dispatch.
        - Compliance Specialist: Uses Pro for deep audit, SOC2 rule parsing, and CVE analysis.
        - Risk Evaluator: Uses Pro for High/Critical data sensitivity, Flash for Low/Medium.
        """
        sens_upper = (data_sensitivity or "").upper()
        is_high_sensitivity = "HIGH" in sens_upper or "CRITICAL" in sens_upper
        has_complex_notes = notes is not None and len(notes) > 100

        if agent_name == "vendorguard_orchestrator":
            if is_high_sensitivity and has_complex_notes:
                model = ModelTier.PRO.value
                reason = "High sensitivity & complex prompt notes require Pro orchestrator reasoning"
            else:
                model = ModelTier.FLASH.value
                reason = "Fast routing & intent dispatch via Flash model"

        elif agent_name == "compliance_specialist":
            model = ModelTier.PRO.value
            reason = "Deep SOC2 audit parsing & security compliance validation requires Pro model"

        elif agent_name == "risk_evaluator":
            if is_high_sensitivity:
                model = ModelTier.PRO.value
                reason = "High/Critical data sensitivity requires Pro financial risk calculation"
            else:
                model = ModelTier.FLASH.value
                reason = "Standard risk scoring routed to Flash for low latency"

        else:
            model = self.default_model
            reason = f"Default fallback model selected for {agent_name}"

        logger.info(f"Model Router [{agent_name}]: selected '{model}' ({reason})")

        return {
            "agent_name": agent_name,
            "selected_model": model,
            "reason": reason,
            "data_sensitivity": data_sensitivity,
            "is_high_sensitivity": is_high_sensitivity
        }


model_router = ModelRouter()
