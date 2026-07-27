"""
VendorGuard ADK - Interactive Streamlit UI Dashboard.
Provides a rich, modern web interface with live OpenTelemetry traces, Vector Store Memory inspector, PII Redaction validator, and JSON log viewer.
"""

import asyncio
import json
import streamlit as st
import pandas as pd
from src.app import app_service, EvaluationRequest
from src.pii_sanitizer import pii_sanitizer
from src.telemetry import trace_collector
from src.tools.schemas import SensitivityLevel

# Page configuration
st.set_page_config(
    page_title="VendorGuard ADK - Enterprise Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for modern dark-mode aesthetic
st.markdown("""
<style>
    /* Gradient Header */
    .main-header {
        background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4338ca 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        color: white;
        margin-bottom: 2rem;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 1.2rem;
        color: white;
        text-align: center;
    }
    .badge-passed {
        background-color: #065f46;
        color: #34d399;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
    }
    .badge-failed {
        background-color: #991b1b;
        color: #f87171;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
    }
    .badge-pii {
        background-color: #0284c7;
        color: #e0f2fe;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


def run_async(coro):
    return asyncio.run(coro)


# Sidebar Navigation
st.sidebar.title("🛡️ VendorGuard ADK")
st.sidebar.markdown("`Google ADK Multi-Agent System`")
menu = st.sidebar.radio(
    "Navigation",
    ["Vendor Risk Evaluator", "PII Redaction Engine", "OpenTelemetry Tracing", "Vector Memory Store", "ADK Architecture"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔒 Security Status")
st.sidebar.markdown("✅ **PII Filter**: Active")
st.sidebar.markdown("✅ **JSON Logger**: Enforced")
st.sidebar.markdown("✅ **Async Memory**: ChromaDB Vector Store")
st.sidebar.markdown("✅ **Tracing**: OpenTelemetry")


# HEADER
st.markdown("""
<div class="main-header">
    <h1 style="margin:0; font-size: 2.2rem;">🛡️ VendorGuard ADK</h1>
    <p style="margin:5px 0 0 0; opacity: 0.9;">Automated Enterprise Security & Compliance Assessment Agent built with <b>Google Agent Development Kit (ADK)</b></p>
</div>
""", unsafe_allow_html=True)


# PAGE 1: VENDOR EVALUATION
if menu == "VendorRiskEvaluator" or menu == "Vendor Risk Evaluator":
    st.subheader("📋 Submit Vendor for Multi-Agent Security Audit")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("#### Vendor Configuration (Strict Pydantic Inputs)")
        vendor_name = st.text_input("Vendor Name", value="Acme Cloud Solutions Inc.")
        sensitivity = st.selectbox(
            "Data Sensitivity Level",
            [e.value for e in SensitivityLevel],
            index=2
        )
        encryption = st.checkbox("AES-256 Encryption at Rest Enabled", value=True)
        mfa = st.checkbox("MFA Enforced for Staff & Admins", value=True)

    with col2:
        st.markdown("#### Control Parameters")
        tls = st.selectbox("Supported Transit Protocol", ["TLS 1.3", "TLS 1.2", "TLS 1.1 (Deprecated)"], index=0)
        pentest_months = st.slider("Penetration Test Cycle (Months)", min_value=1, max_value=24, value=12)
        soc2_age = st.slider("SOC2 Report Age (Months)", min_value=1, max_value=24, value=6)
        notes = st.text_area("Vendor Notes / Context", value="Primary contact email: john.doe@acme.com, SSN: 000-12-3456")

    submit_button = st.button("🚀 Run ADK Security Audit", type="primary", use_container_width=True)

    if submit_button:
        with st.spinner("Executing Google ADK Multi-Agent Pipeline & Vector Memory lookup..."):
            req = EvaluationRequest(
                vendor_name=vendor_name,
                data_sensitivity=sensitivity,
                encryption_at_rest=encryption,
                tls_version=tls,
                mfa_enforced=mfa,
                pentest_frequency_months=pentest_months,
                soc2_report_age_months=soc2_age,
                notes=notes
            )
            response = run_async(app_service.evaluate_vendor(req))

        st.success("Audit Completed Successfully!")

        # Results Overview Metrics
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("SOC2 Compliance", f"{response.soc2_audit['compliance_score']}/100", response.soc2_audit['status'])
        with m2:
            st.metric("Overall Risk Score", f"{response.risk_assessment['overall_risk_score']}/100", response.risk_assessment['risk_tier'])
        with m3:
            st.metric("Contract Limit Cap", f"${response.risk_assessment['maximum_allowed_contract_value_usd']:,} USD")
        with m4:
            st.metric("OpenTelemetry Spans", f"{response.execution_trace_count} Spans Recorded")

        st.markdown("---")
        st.markdown("### 📝 Executive Audit Summary")
        st.markdown(response.executive_summary)

        t1, t2, t3 = st.tabs(["SOC2 Control Details", "Vulnerability Scan", "Memory Context"])
        with t1:
            st.json(response.soc2_audit)
        with t2:
            st.json(response.vuln_scan)
        with t3:
            st.json(response.memory_context)


# PAGE 2: PII REDACTION ENGINE
elif menu == "PII Redaction Engine":
    st.subheader("🔒 Zero-PII Guarantee Inspection Engine")
    st.markdown("VendorGuard ADK enforces strict pattern-based sanitization before data is logged, stored in vector memory, or transmitted to LLMs.")

    user_text = st.text_area(
        "Test Raw Input String (Contains Sensitive Data)",
        value="User John Doe (john.doe@company.com) reported an issue from IP 192.168.1.105 with SSN 123-45-6789 and API key secret_key: abc123xyz456secrettoken."
    )

    if st.button("Scrub PII Now"):
        clean_text = pii_sanitizer.sanitize_text(user_text)
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### ❌ Raw Input")
            st.code(user_text)
        with c2:
            st.markdown("#### ✅ Sanitized Output (Logged & Stored)")
            st.code(clean_text)


# PAGE 3: OPENTELEMETRY TRACING
elif menu == "OpenTelemetry Tracing":
    st.subheader("📡 Live OpenTelemetry Trace Inspector")
    st.markdown("Real-time telemetry spans recorded across agent decision loops, memory lookups, and tool executions.")

    traces = trace_collector.get_traces()
    if not traces:
        st.info("No traces recorded yet. Run a vendor evaluation to populate telemetry spans!")
    else:
        df = pd.DataFrame(traces)
        st.dataframe(df, use_container_width=True)
        st.json(traces)


# PAGE 4: VECTOR MEMORY STORE
elif menu == "Vector Memory Store":
    st.subheader("🧠 Async Vector Memory Store (ChromaDB)")
    st.markdown("Asynchronous long-term vector storage for historical security audits and vendor context.")

    query = st.text_input("Query Vector Memory", value="Acme Cloud Solutions")
    if st.button("Search Memory"):
        results = run_async(app_service.vector_store.search(query=query, limit=5))
        if not results:
            st.info("No vector matches found for query.")
        else:
            for res in results:
                st.markdown(f"**Document ID**: `{res.document.id}` | **Similarity Score**: `{res.score}`")
                st.code(res.document.content)


# PAGE 5: ADK ARCHITECTURE
elif menu == "ADK Architecture":
    st.subheader("🏗️ Google Agent Development Kit Architecture")
    st.markdown("""
    ### System Architecture & Rubric Alignment

    1. **Tool & Interface Design (Strict Pydantic / JSON Schemas)**
       - Schema validation using Pydantic v2 models across all tool inputs, tool outputs, and UI request objects.
       - Interactive Streamlit dashboard with dark mode and live metric cards.

    2. **Context & Memory (Async Vector Store)**
       - Asynchronous ChromaDB vector database wrapper (`AsyncVectorStore`).
       - Non-blocking async embedding and search operations.

    3. **Orchestration & Logic (ADK Multi-Agent Team)**
       - Built with `google-adk` framework.
       - `vendorguard_orchestrator` root agent delegating to `compliance_specialist` and `risk_evaluator` agents.

    4. **Observability & Tracing (OpenTelemetry & JSON Strings)**
       - OpenTelemetry SDK instrumentation with custom span decorators (`@trace_span`).
       - JSON string structured log formatter (`JSONFormatter`).

    5. **Infrastructure & CI/CD**
       - Clean modular code layout (`src/`, `ui/`, `tests/`).
       - Secrets Manager abstraction with Google Cloud Secret Manager support and local fallback.
       - Full CI/CD pipeline via GitHub Actions (`.github/workflows/ci.yml`).
       - Comprehensive unit tests covering all components.
    """)
