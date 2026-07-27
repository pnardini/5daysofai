"""
Unit tests for Strategic Model Router.
"""

from src.model_router import ModelRouter, ModelTier


def test_model_router_orchestrator_routing():
    router = ModelRouter()
    res_flash = router.select_model("vendorguard_orchestrator", data_sensitivity="Low")
    assert res_flash["selected_model"] == ModelTier.FLASH.value

    res_pro = router.select_model("vendorguard_orchestrator", data_sensitivity="High", notes="x" * 120)
    assert res_pro["selected_model"] == ModelTier.PRO.value


def test_model_router_compliance_routing():
    router = ModelRouter()
    res = router.select_model("compliance_specialist")
    assert res["selected_model"] == ModelTier.PRO.value


def test_model_router_risk_evaluator_routing():
    router = ModelRouter()
    res_low = router.select_model("risk_evaluator", data_sensitivity="Low")
    assert res_low["selected_model"] == ModelTier.FLASH.value

    res_high = router.select_model("risk_evaluator", data_sensitivity="Critical")
    assert res_high["selected_model"] == ModelTier.PRO.value
