"""
Strict Pydantic Input/Output Schemas for VendorGuard ADK Tools and UI.
Guarantees schema enforcement, input validation, and clear JSON schema exports.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, SecretStr, field_validator


class SensitivityLevel(str, Enum):
    LOW = "Low (Public Data)"
    MEDIUM = "Medium (Internal Business Data)"
    HIGH = "High (Confidential / PII)"
    CRITICAL = "Critical (Financial / Health / Secrets)"


class RiskTier(str, Enum):
    LOW_RISK = "LOW RISK (Approved)"
    MEDIUM_RISK = "MEDIUM RISK (Conditional Approval)"
    HIGH_RISK = "HIGH RISK (Security Review Required)"
    CRITICAL_RISK = "CRITICAL RISK (Rejected)"


# --- SOC2 Audit Tool Schemas ---
class SOC2AuditInput(BaseModel):
    """Input model for SOC2 Compliance Audit Tool."""
    vendor_name: str = Field(..., description="Name of the third-party vendor or service provider", min_length=2)
    encryption_at_rest: bool = Field(True, description="Whether AES-256 encryption at rest is enabled")
    tls_version: str = Field("TLS 1.3", description="Supported TLS version for data in transit (e.g., 'TLS 1.3', 'TLS 1.2')")
    mfa_enforced: bool = Field(True, description="Whether Multi-Factor Authentication is enforced for all staff")
    pentest_frequency_months: int = Field(12, description="Frequency of third-party penetration testing in months", ge=1, le=36)
    soc2_report_age_months: int = Field(6, description="Age of the latest SOC2 Type II report in months", ge=0, le=24)


class SOC2AuditOutput(BaseModel):
    """Output model for SOC2 Compliance Audit Tool."""
    vendor_name: str
    compliance_score: float = Field(..., description="Calculated compliance score between 0.0 and 100.0")
    status: str = Field(..., description="Compliance status: PASSED, NEEDS_REVIEW, or FAILED")
    passed_controls: List[str]
    failed_controls: List[str]
    recommendations: List[str]


# --- Vulnerability Scanner Tool Schemas ---
class VulnerabilityScanInput(BaseModel):
    """Input model for Vulnerability Scanner Tool."""
    vendor_id: str = Field(..., description="Unique vendor ID or slug")
    target_endpoint: str = Field("https://api.vendor.com", description="Target domain or endpoint for configuration inspection")
    scan_type: str = Field("comprehensive", description="Scan intensity: 'quick', 'standard', or 'comprehensive'")


class CVEItem(BaseModel):
    cve_id: str
    severity: str
    description: str


class VulnerabilityScanOutput(BaseModel):
    """Output model for Vulnerability Scanner Tool."""
    vendor_id: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    cve_list: List[CVEItem]
    scan_status: str


# --- Risk Calculator Tool Schemas ---
class VendorRiskCalculationInput(BaseModel):
    """Input model for Vendor Risk Rating Calculator."""
    vendor_name: str = Field(..., description="Vendor name")
    soc2_compliance_score: float = Field(..., description="SOC2 score from 0.0 to 100.0", ge=0.0, le=100.0)
    critical_vulnerabilities: int = Field(0, description="Count of open critical vulnerabilities", ge=0)
    data_sensitivity: SensitivityLevel = Field(SensitivityLevel.HIGH, description="Level of data sensitivity handled by vendor")
    subprocessor_count: int = Field(3, description="Number of third-party subprocessors used", ge=0)


class VendorRiskCalculationOutput(BaseModel):
    """Output model for Vendor Risk Rating Calculator."""
    vendor_name: str
    overall_risk_score: float = Field(..., description="Overall risk score from 0.0 (Safe) to 100.0 (Critical Risk)")
    risk_tier: RiskTier
    maximum_allowed_contract_value_usd: int
    compliance_badge: str
    evaluation_timestamp: str


# --- Memory Lookup Tool Schemas ---
class MemoryLookupInput(BaseModel):
    """Input model for Vector Memory Lookup Tool."""
    query: str = Field(..., description="Search query for vector memory lookup", min_length=3)
    vendor_id: Optional[str] = Field(None, description="Optional vendor ID filter")
    max_results: int = Field(3, description="Maximum number of historical context results to return", ge=1, le=10)


class MemoryLookupOutput(BaseModel):
    """Output model for Vector Memory Lookup Tool."""
    query: str
    results_found: int
    context_summary: str
    matches: List[str]
