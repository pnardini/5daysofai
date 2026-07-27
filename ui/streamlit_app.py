"""
VendorGuard ADK - Interactive Streamlit UI Dashboard.
Provides a rich, modern web interface with live Strategic Model Routing insights,
ADK Guardrail Evaluations, Human-in-the-Loop Pause/Approval Hooks, OpenTelemetry traces,
Vector Store Memory inspector, PII Redaction validator, and JSON log viewer.
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
    .badge-hitl {
        background-color: #b45309;
        color: #fef3c7;
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
    [
        "Vendor Risk Evaluator",
        "Human-in-the-Loop (HITL)",
        "PII Redaction & Guardrails",
        "OpenTelemetry Tracing",
        "Vector Memory Store",
        "ADK Architecture"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔒 Security & AI Routing Status")
st.sidebar.markdown("⚡ **Routing**: Dynamic (Flash + Pro)")
st.sidebar.markdown("🛡️ **Guardrails**: ADK Native Evaluator")
st.sidebar.markdown("⏸️ **HITL Hooks**: Active (Pause & Resume)")
st.sidebar.markdown("✅ **Async Memory**: ChromaDB Vector Store")
st.sidebar.markdown("✅ **Tracing**: OpenTelemetry")


# HEADER
st.markdown("""
<div class="main-header">
    <h1 style="margin:0; font-size: 2.2rem;">🛡️ VendorGuard ADK</h1>
    <p style="margin:5px 0 0 0; opacity: 0.9;">Automated Enterprise Security & Compliance Assessment Agent with <b>Strategic Model Routing, ADK Guardrails & HITL Hooks</b></p>
</div>
""", unsafe_allow_html=True)


# PAGE 1: VENDOR EVALUATION
if menu == "Vendor Risk Evaluator":
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
        with st.spinner("Executing Strategic Routing, ADK Guardrails & Multi-Agent Pipeline..."):
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

        st.success(f"Audit Pipeline Processed (Evaluation ID: {response.evaluation_id})")

        # HITL Alert Banner if Paused
        if response.requires_human_approval:
            st.warning(f"⏸️ **HUMAN-IN-THE-LOOP PAUSE HOOK TRIGGERED**\n\n{response.hitl_trigger_reason}")
            
            c_app, c_rej = st.columns(2)
            with c_app:
                if st.button("✅ Approve Vendor (CISO Sign-Off)", key=f"app_{response.evaluation_id}"):
                    res = app_service.submit_human_decision(response.evaluation_id, "APPROVED", "Approved after CISO manual review")
                    st.success(f"Vendor Approved! Status: {res.status}")
                    st.rerun()
            with c_rej:
                if st.button("❌ Reject Vendor", key=f"rej_{response.evaluation_id}"):
                    res = app_service.submit_human_decision(response.evaluation_id, "REJECTED", "Rejected due to security risk thresholds")
                    st.error(f"Vendor Rejected! Status: {res.status}")
                    st.rerun()

        # Results Overview Metrics
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("SOC2 Compliance", f"{response.soc2_audit['compliance_score']}/100", response.soc2_audit['status'])
        with m2:
            st.metric("Overall Risk Score", f"{response.risk_assessment['overall_risk_score']}/100", response.risk_assessment['risk_tier'])
        with m3:
            st.metric("Contract Limit Cap", f"${response.risk_assessment['maximum_allowed_contract_value_usd']:,} USD")
        with m4:
            st.metric("Workflow Status", response.status)

        st.markdown("---")

        # Display Strategic Model Routing & ADK Guardrail Insights
        r_col1, r_col2 = st.columns(2)
        with r_col1:
            st.markdown("#### ⚡ Strategic Model Routing")
            st.json(response.model_routing)
        with r_col2:
            st.markdown("#### 🛡️ ADK-Native Guardrail Evaluations")
            st.json(response.guardrail_evaluations)

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


# PAGE 2: HUMAN-IN-THE-LOOP QUEUE
elif menu == "Human-in-the-Loop (HITL)":
    st.subheader("⏸️ Human-in-the-Loop Pending Approvals Queue")
    st.markdown("When vendor evaluations exceed risk thresholds or violate baseline security policies, the workflow automatically pauses for mandatory CISO sign-off.")

    pending = app_service.pending_hitl_evaluations
    if not pending:
        st.info("No pending vendor approvals in queue. All automated audits are fully processed.")
    else:
        for eval_id, response in list(pending.items()):
            with st.expander(f"🔴 Pending Review: {response.vendor_name} (ID: {eval_id})", expanded=True):
                st.write(f"**Trigger Reason**: {response.hitl_trigger_reason}")
                st.write(f"**Overall Risk**: `{response.risk_assessment['overall_risk_score']}/100` ({response.risk_assessment['risk_tier']})")
                st.write(f"**Proposed Contract Cap**: `${response.risk_assessment['maximum_allowed_contract_value_usd']:,} USD`")

                notes_input = st.text_input("Reviewer Audit Notes / Comments", key=f"notes_{eval_id}", value="Reviewed risk profile and security controls.")
                
                b1, b2 = st.columns(2)
                with b1:
                    if st.button("✅ Approve & Authorize Contract", key=f"hitl_app_{eval_id}"):
                        res = app_service.submit_human_decision(eval_id, "APPROVED", notes_input)
                        st.success(f"Evaluation {eval_id} approved!")
                        st.rerun()
                with b2:
                    if st.button("❌ Reject Vendor Cap", key=f"hitl_rej_{eval_id}"):
                        res = app_service.submit_human_decision(eval_id, "REJECTED", notes_input)
                        st.error(f"Evaluation {eval_id} rejected!")
                        st.rerun()


# PAGE 3: PII REDACTION & GUARDRAILS
elif menu == "PII Redaction & Guardrails":
    st.subheader("🔒 ADK Guardrails & Zero-PII Inspection Engine")
    st.markdown("VendorGuard ADK combines pattern-based sanitization with ADK-native guardrail evaluations before data is logged or sent to LLMs.")

    user_text = st.text_area(
        "Test Raw Input String (Contains Sensitive Data)",
        value="User John Doe (john.doe@company.com) reported an issue from IP 192.168.1.105 with SSN 123-45-6789 and API key secret_key: abc123xyz456secrettoken."
    )

    if st.button("Run ADK Guardrail Evaluation & Scrub"):
        clean_text, eval_res = pii_sanitizer.evaluate_and_sanitize(user_text)
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### ❌ Raw Input")
            st.code(user_text)
        with c2:
            st.markdown("#### ✅ Sanitized Output (Logged & Stored)")
            st.code(clean_text)

        st.markdown("#### 🛡️ ADK Evaluation Result")
        st.json(eval_res.model_dump())


# PAGE 4: OPENTELEMETRY TRACING
elif menu == "OpenTelemetry Tracing":
    st.subheader("📡 Live OpenTelemetry Trace Inspector")
    st.markdown("Real-time telemetry spans recorded across strategic model routing, guardrail evaluations, and HITL pause hooks.")

    traces = trace_collector.get_traces()
    if not traces:
        st.info("No traces recorded yet. Run a vendor evaluation to populate telemetry spans!")
    else:
        df = pd.DataFrame(traces)
        st.dataframe(df, use_container_width=True)
        st.json(traces)


# PAGE 5: VECTOR MEMORY STORE
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


# PAGE 6: ADK ARCHITECTURE
elif menu == "ADK Architecture":
    st.subheader("🏗️ Google Agent Development Kit Architecture")
    st.markdown("""
    ### System Architecture & Rubric Alignment

    1. **Strategic Model Routing**
       - Dynamic model router (`src/model_router.py`) selecting between `gemini-2.5-flash` (low latency, orchestrator) and `gemini-2.5-pro` (deep reasoning for compliance & risk).

    2. **ADK-Native Guardrail Evaluations**
       - Multi-dimensional evaluations (`src/guardrails.py`) running ADK lifecycle plugin hooks (`BasePlugin`) and safety policy evaluators (`PII_PROTECTION_EVAL`, `SECURITY_BASELINE_EVAL`).

    3. **Human-in-the-Loop (HITL) Pause Hooks**
       - Critical interruption points (`PAUSED_PENDING_HUMAN_APPROVAL`) triggered when risk score >= 50, risk tier is High/Critical, or security controls fail.
       - Interactive CISO decision submission & resume hooks (`submit_human_decision`).

    4. **Context & Memory (Async Vector Store)**
       - Asynchronous ChromaDB vector database wrapper (`AsyncVectorStore`).

    5. **Observability & Tracing (OpenTelemetry & JSON Strings)**
       - OpenTelemetry SDK instrumentation with custom span decorators (`@trace_span`).
       - JSON string structured log formatter (`JSONFormatter`).
    """)
