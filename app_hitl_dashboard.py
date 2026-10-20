"""
Pre-Deployment Backend & RAG Testing Pipeline with Human-in-the-Loop (HITL) Gatekeeper.
Production-grade QA & Application Security dashboard compliant with ISO/IEC 25010 & OWASP ASVS.
Zero decorative emojis; formal corporate audit reporting.
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.test_runner import (
    REPORTS_DIR,
    generate_audit_markdown_report,
    load_latest_report,
    run_pytest_suite,
)
from core.pdf_report_generator import generate_pdf_audit_report
from core.ai_agent_evaluator import (
    AgentEvaluator,
    OllamaClient,
    get_available_ollama_models,
)
from core.local_specialist_reviewer import LocalSpecialistReviewer
from core.market_readiness_engine import MarketReadinessEngine, MarketReadinessReport
from core.security_scanner import SecurityScanner, SecurityScanSummary
from core.source_analyzer import analyze_and_test

# ---------------------------------------------------------------------------
# Streamlit Application Configuration
# ---------------------------------------------------------------------------

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

st.set_page_config(
    page_title="Production Readiness & Security Gatekeeper",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "market_report": None,
    "test_report": None,
    "eval_report": None,
    "specialist_review": None,
    "qa_notes": {},
    "overrides": {},
    "reviewer_name": "",
    "deployment_decision": None,
    "source_scan_result": None,
    "selected_model": "qa-auditor-specialist",
    "target_artifact": "Backend Services & RAG Pipeline",
}
for key, val in _DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = val


# ---------------------------------------------------------------------------
# Cryptographic & Formatting Utilities
# ---------------------------------------------------------------------------

def _sign_payload(data: dict) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _format_status(status: str) -> str:
    mapping = {
        "passed": "[PASSED]",
        "failed": "[FAILED]",
        "error": "[ERROR]",
        "skipped": "[SKIPPED]",
    }
    return mapping.get(status.lower(), f"[{status.upper()}]")


def _format_severity(severity: str) -> str:
    mapping = {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
    }
    return mapping.get(severity.lower(), f"[{severity.upper()}]")


# ---------------------------------------------------------------------------
# Sidebar Controls & Ingestion
# ---------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Market Readiness Gatekeeper")
    st.caption("ISO/IEC 25010 & OWASP Verification Governance")
    st.divider()

    st.subheader("Reviewer Identity")
    st.session_state.reviewer_name = st.text_input(
        "Lead QA Engineer / Reviewer Name",
        value=st.session_state.reviewer_name,
        placeholder="e.g., Alex Mercer (Lead AppSec / QA)",
    )

    st.divider()
    st.subheader("Local Open-Source AI Model Engine")

    available_models = get_available_ollama_models()
    if available_models:
        default_idx = 0
        if st.session_state.selected_model in available_models:
            default_idx = available_models.index(st.session_state.selected_model)
        st.session_state.selected_model = st.selectbox(
            "Active Local Ollama Model",
            available_models,
            index=default_idx,
            help="High-capacity open-source model running locally for deep vulnerability exploitability assessment.",
        )
    else:
        st.session_state.selected_model = st.text_input(
            "Local Model Identifier",
            value="llama3.2",
            help="Ollama not detected or no models pulled. Enter model name or use deterministic fallback.",
        )

    st.divider()
    st.subheader("Application Ingestion & Comprehensive Audit")

    uploaded_file = st.file_uploader(
        "Upload Application Archive (.zip) or Source (.py)",
        type=["zip", "py"],
        help="Upload any GitHub release/repo ZIP archive or Python module for automated multi-pillar evaluation.",
    )

    source_path_input = st.text_input(
        "Or Specify Local Path (.zip, directory, or .py)",
        placeholder="/path/to/repo.zip or /path/to/project/",
    )

    if st.button("Execute Full Market Readiness Audit", use_container_width=True, type="primary"):
        target_path = None

        if uploaded_file is not None:
            upload_dir = PROJECT_ROOT / "reports" / "uploads"
            upload_dir.mkdir(parents=True, exist_ok=True)
            target_path = upload_dir / uploaded_file.name
            target_path.write_bytes(uploaded_file.getvalue())
        elif source_path_input.strip():
            candidate = Path(source_path_input.strip())
            if candidate.exists():
                target_path = candidate

        if target_path and target_path.exists():
            with st.spinner(f"Executing 5-Pillar Market Readiness Audit on '{target_path.name}'..."):
                engine = MarketReadinessEngine(
                    llm_client=OllamaClient(model=st.session_state.selected_model)
                    if available_models else None
                )
                mkt_report = engine.evaluate(target_path, run_functional_tests=True)
                st.session_state.market_report = mkt_report.to_dict()
                st.session_state.test_report = mkt_report.test_summary
                st.session_state.eval_report = mkt_report.ai_evaluation
                st.session_state.target_artifact = str(target_path.name)
                st.session_state.overrides = {}
                st.session_state.qa_notes = {}
                st.session_state.deployment_decision = None
            st.rerun()
        else:
            st.error("Please provide a valid file upload or an existing filesystem path.")

    if st.button("Run Built-in Test Suite Only", use_container_width=True):
        with st.spinner("Executing built-in test suite..."):
            report = run_pytest_suite(
                paths=[str(PROJECT_ROOT / "tests" / "test_backend_suite.py")],
                extra_args=["-v", "--tb=short", "-q"],
            )
            st.session_state.test_report = report.to_dict()
            st.session_state.market_report = None
            st.session_state.eval_report = None
            st.session_state.overrides = {}
            st.session_state.qa_notes = {}
            st.session_state.deployment_decision = None
            st.session_state.target_artifact = "Built-in Backend & RAG Suite"
        st.rerun()

    if st.session_state.test_report and st.button("Execute AI Defect Analysis", use_container_width=True):
        with st.spinner("Evaluating defect root causes..."):
            evaluator = AgentEvaluator(model_name=st.session_state.selected_model)
            evaluation = evaluator.analyze_test_report(st.session_state.test_report)
            st.session_state.eval_report = evaluation.to_dict()
        st.rerun()

    if (st.session_state.market_report or st.session_state.test_report) and st.button(
        "Execute Specialist Deep-Dive Audit", use_container_width=True
    ):
        with st.spinner(f"Running specialized local audit with '{st.session_state.selected_model}'..."):
            reviewer = LocalSpecialistReviewer(model_name=st.session_state.selected_model)
            if st.session_state.market_report:
                spec_res = reviewer.review_market_readiness(st.session_state.market_report)
            else:
                spec_res = reviewer.review_market_readiness({
                    "target_path": st.session_state.target_artifact,
                    "market_readiness_score": st.session_state.test_report.get("pass_rate", 0.0),
                    "test_summary": st.session_state.test_report,
                    "security_summary": {},
                })
            st.session_state.specialist_review = spec_res.to_dict()
        st.rerun()

    st.divider()
    st.caption("Verification Engine v3.0 | ISO/IEC 25010 & OWASP Top 10")


# ---------------------------------------------------------------------------
# Main Content View
# ---------------------------------------------------------------------------

st.title("Enterprise Market Readiness & Verification Pipeline")
st.caption(
    "Automated Quality Assurance, OWASP Security Auditing, and Human-in-the-Loop Deployment Governance"
)

# ---------------------------------------------------------------------------
# Section 0: Market Readiness Scorecard & Determination
# ---------------------------------------------------------------------------

mkt_data = st.session_state.market_report
if mkt_data:
    st.header("1. Market Readiness Determination & Pillar Scorecard")

    gate = mkt_data.get("gate_decision", "MARKET_BLOCKED")
    score = mkt_data.get("market_readiness_score", 0.0)
    archetype = mkt_data.get("archetype", "Unknown")

    if gate == "MARKET_READY_APPROVED":
        st.success(
            f"GO-TO-MARKET DETERMINATION: APPROVED (Score: {score:.1f} / 100.0)\n\n"
            f"Target satisfies all security, reliability, architecture, and API criteria."
        )
    elif gate == "CONDITIONAL_APPROVAL":
        st.warning(
            f"GO-TO-MARKET DETERMINATION: CONDITIONAL APPROVAL (Score: {score:.1f} / 100.0)\n\n"
            f"Non-critical remediation or quality gate waivers required prior to release."
        )
    else:
        st.error(
            f"GO-TO-MARKET DETERMINATION: DEPLOYMENT BLOCKED (Score: {score:.1f} / 100.0)\n\n"
            f"Application fails critical production thresholds. Immediate remediation mandatory."
        )

    st.markdown(f"**Identified Archetype:** `{archetype}` | **Target Artifact:** `{mkt_data.get('target_path')}`")

    # Pillar Scores
    pillars = mkt_data.get("pillar_scores", {})
    p1, p2, p3, p4, p5 = st.columns(5)
    p1.metric("Security (30%)", f"{pillars.get('security_score', 0):.1f}%")
    p2.metric("Reliability (25%)", f"{pillars.get('reliability_score', 0):.1f}%")
    p3.metric("Code Health (20%)", f"{pillars.get('code_health_score', 0):.1f}%")
    p4.metric("API Contract (15%)", f"{pillars.get('api_readiness_score', 0):.1f}%")
    p5.metric("GenAI Safety (10%)", f"{pillars.get('genai_safety_score', 0):.1f}%")

    blocking = mkt_data.get("blocking_reasons", [])
    if blocking:
        st.subheader("Blocking Defect Criteria")
        for b in blocking:
            st.markdown(f"- **[BLOCKING ISSUE]** {b}")

    # Code Health metrics
    health = mkt_data.get("code_health", {})
    if health:
        with st.expander("Architectural Code Health Metrics"):
            h1, h2, h3, h4 = st.columns(4)
            h1.metric("Total Lines of Code", health.get("total_loc", 0))
            h2.metric("Avg Complexity (McCabe)", health.get("average_cyclomatic_complexity", 1.0))
            h3.metric("Complex Functions (>10)", health.get("complex_functions_count", 0))
            h4.metric("Health Grade", health.get("health_grade", "A"))

    st.divider()

# ---------------------------------------------------------------------------
# Section 1: Security & Vulnerability Scan (OWASP Top 10)
# ---------------------------------------------------------------------------

if mkt_data and mkt_data.get("security_summary"):
    sec = mkt_data["security_summary"]
    st.header("2. Application Security & Vulnerability Register (OWASP Top 10)")

    sc1, sc2, sc3, sc4, sc5 = st.columns(5)
    sc1.metric("Total Flaws Identified", sec.get("total_findings", 0))
    sc2.metric("Critical Severity", sec.get("critical_count", 0))
    sc3.metric("High Severity", sec.get("high_count", 0))
    sc4.metric("Exposed Secrets", sec.get("secrets_count", 0))
    sc5.metric("Security Score", f"{sec.get('security_score', 100):.1f}%")

    findings = sec.get("findings", [])
    if findings:
        for f in findings:
            sev_tag = _format_severity(f.get("severity", "medium"))
            title = f.get("title", "Security Flaw")
            cwe = f.get("cwe_id", "CWE-Unknown")
            loc = f"{Path(f.get('file_path', '')).name}:{f.get('line_number', 0)}"

            with st.expander(f"{sev_tag} {title} | {cwe} | Location: {loc}"):
                st.markdown(f"**Vulnerability Description:**\n{f.get('description')}")
                st.code(f.get("code_snippet", ""), language="text")
                st.markdown(f"**Remediation Guidance:**\n{f.get('remediation_guidance')}")
    else:
        st.success("Static security audit clean. Zero known OWASP Top 10 vulnerabilities or hardcoded credentials.")

    st.divider()

# ---------------------------------------------------------------------------
# Section 2: Functional Test Execution Metrics
# ---------------------------------------------------------------------------

report = st.session_state.test_report

if not report:
    st.info("System idle. Ingest a target application archive/file via the sidebar to initiate evaluation.")
    st.stop()

st.header("3. Functional Test Execution Metrics and Benchmarks")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Test Cases", report.get("total", 0))
col2.metric("Passed Assertions", report.get("passed", 0))
col3.metric("Functional Failures", report.get("failed", 0))
col4.metric("Execution Errors", report.get("errors", 0))
col5.metric("Pass Rate", f"{report.get('pass_rate', 0.0)}%")

st.caption(
    f"Execution Latency: {report.get('total_duration_ms', 0.0):.2f} ms | "
    f"Audit Identifier: {report.get('run_id', 'N/A')} | "
    f"Evaluation Target: {st.session_state.target_artifact}"
)

# ---------------------------------------------------------------------------
# Section 3: Test Results Matrix
# ---------------------------------------------------------------------------

st.header("4. Detailed Test Execution Register")

tab_all, tab_failed, tab_passed, tab_skipped = st.tabs(
    ["All Test Cases", "Failed Defect Tests", "Passed Tests", "Skipped Tests"]
)

results = report.get("results", [])


def _render_results_matrix(items: list[dict]) -> None:
    if not items:
        st.write("No test cases recorded under this classification filter.")
        return

    for item in items:
        status_tag = _format_status(item.get("status", ""))
        label = (
            f"{status_tag} {item.get('test_name')} | "
            f"Latency: {item.get('duration_ms', 0.0):.2f} ms | "
            f"Category: {item.get('category', 'unit').upper()}"
        )
        with st.expander(label):
            r1, r2, r3 = st.columns(3)
            r1.write(f"**Module:** `{item.get('module')}`")
            r2.write(f"**Status:** {item.get('status', '').upper()}")
            r3.write(f"**Duration:** {item.get('duration_ms', 0.0):.2f} ms")

            if item.get("confidence_score") is not None:
                st.write(f"**RAG Faithfulness Confidence:** {item['confidence_score']:.4f}")

            if item.get("traceback_str"):
                st.text("Traceback / Failure Log:")
                st.code(item["traceback_str"], language="text")


with tab_all:
    _render_results_matrix(results)

with tab_failed:
    _render_results_matrix([r for r in results if r.get("status") in ("failed", "error")])

with tab_passed:
    _render_results_matrix([r for r in results if r.get("status") == "passed"])

with tab_skipped:
    _render_results_matrix([r for r in results if r.get("status") == "skipped"])

# ---------------------------------------------------------------------------
# Section 4: AI Defect Root Cause Analysis
# ---------------------------------------------------------------------------

st.header("5. AI Defect Root Cause Analysis & Remediation")

eval_report = st.session_state.eval_report

if not eval_report:
    st.info("Click 'Execute AI Defect Analysis' in sidebar to trigger LLM root cause analysis.")
else:
    analyses = eval_report.get("failure_analyses", [])
    if not analyses:
        st.success("Verification successful. No test failures requiring remediation.")
    else:
        for fa in analyses:
            sev_tag = _format_severity(fa.get("severity", "medium"))
            test_name = fa.get("test_name", "Unknown")

            with st.expander(f"{sev_tag} Defect in `{test_name}`", expanded=True):
                st.markdown(f"**Root Cause Investigation:**\n{fa.get('root_cause')}")
                st.markdown(f"**Recommended Remediation Plan:**\n{fa.get('suggested_fix')}")
                st.divider()

                key_note = f"note_{test_name}"
                note_val = st.text_area(
                    "QA Reviewer Analysis and Mitigation Notes",
                    value=st.session_state.qa_notes.get(test_name, ""),
                    key=key_note,
                )
                st.session_state.qa_notes[test_name] = note_val

                key_override = f"override_{test_name}"
                override_val = st.checkbox(
                    "Quality Gate Override: Mark this defect as reviewed, acknowledged, and non-blocking for deployment",
                    value=st.session_state.overrides.get(test_name, False),
                    key=key_override,
                )
                st.session_state.overrides[test_name] = override_val

# ---------------------------------------------------------------------------
# Section 5: Local Fine-Tuned AI Specialist Deep-Dive Audit
# ---------------------------------------------------------------------------

spec_review = st.session_state.specialist_review
if spec_review:
    st.header("6. Local Fine-Tuned AI Specialist Deep-Dive Audit")

    spec_model = spec_review.get("model_identifier", "qa-auditor-specialist")
    spec_gate = spec_review.get("gate_recommendation", "VERIFIED")
    spec_conf = spec_review.get("confidence_score", 0.95)
    spec_digest = spec_review.get("cryptographic_digest", "N/A")

    if spec_gate == "APPROVED_FOR_MARKET":
        st.success(
            f"SPECIALIST GATE VERDICT: APPROVED FOR COMMERCIAL MARKET RELEASE\n\n"
            f"Autonomous Specialist: {spec_model} | Confidence: {spec_conf * 100:.1f}%\n"
            f"Cryptographic Review Digest: {spec_digest[:32]}..."
        )
    elif spec_gate == "CONDITIONAL_ACCEPTANCE":
        st.warning(
            f"SPECIALIST GATE VERDICT: CONDITIONAL ACCEPTANCE\n\n"
            f"Autonomous Specialist: {spec_model} | Confidence: {spec_conf * 100:.1f}%\n"
            f"Cryptographic Review Digest: {spec_digest[:32]}..."
        )
    else:
        st.error(
            f"SPECIALIST GATE VERDICT: IMMEDIATE RELEASE VETO\n\n"
            f"Autonomous Specialist: {spec_model} | Confidence: {spec_conf * 100:.1f}%\n"
            f"Cryptographic Review Digest: {spec_digest[:32]}..."
        )

    st.markdown(f"**Specialist Synthesis:** {spec_review.get('executive_summary', '')}")

    threat_findings = spec_review.get("threat_findings", [])
    if threat_findings:
        st.subheader("Confirmed Exploitability & Threat Modeling")
        for tf in threat_findings:
            with st.expander(f"[{tf.get('exploitability', 'THEORETICAL')}] {tf.get('finding_id')} - {tf.get('cwe_id')} (CVSS {tf.get('cvss_v3_score', 0.0):.1f})"):
                st.markdown(f"**Attack Vector:** {tf.get('attack_vector')}")
                st.markdown(f"**Auditor Rationale:** {tf.get('auditor_rationale')}")
                st.markdown("**Remediation Patch:**")
                st.code(tf.get("remediation_patch", ""), language="text")

    defect_diagnoses = spec_review.get("defect_diagnoses", [])
    if defect_diagnoses:
        st.subheader("Specialist Defect Diagnoses")
        for dd in defect_diagnoses:
            with st.expander(f"Defect in {dd.get('test_id')} - {dd.get('failure_type')}"):
                st.markdown(f"**Root Cause:** {dd.get('root_cause')}")
                st.markdown(f"**Suggested Fix:** {dd.get('suggested_fix')}")
                if dd.get("patch_diff"):
                    st.code(dd.get("patch_diff"), language="diff")

    st.divider()

# ---------------------------------------------------------------------------
# Section 6: Human-in-the-Loop Sign-Off & Report Export
# ---------------------------------------------------------------------------

st.header("7. Human-in-the-Loop Quality Gatekeeper Sign-Off" if spec_review else "6. Human-in-the-Loop Quality Gatekeeper Sign-Off")

if not st.session_state.reviewer_name.strip():
    st.warning("Action Required: Please enter your reviewer name or ID in the sidebar to enable deployment sign-off.")
    st.stop()

col_approve, col_block = st.columns(2)

with col_approve:
    approve = st.button(
        "Approve for Production Deployment",
        use_container_width=True,
        type="primary",
        disabled=st.session_state.deployment_decision is not None,
    )

with col_block:
    block = st.button(
        "Reject / Block Deployment",
        use_container_width=True,
        type="secondary",
        disabled=st.session_state.deployment_decision is not None,
    )

if approve or block:
    decision_status = approve

    decision_data = {
        "run_id": report.get("run_id", "N/A"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reviewer": st.session_state.reviewer_name.strip(),
        "approved": decision_status,
        "decision": "APPROVED FOR PRODUCTION" if decision_status else "DEPLOYMENT BLOCKED",
        "target_artifact": st.session_state.target_artifact,
        "archetype": mkt_data.get("archetype", "Generic Application") if mkt_data else "Generic Application",
        "market_readiness_score": mkt_data.get("market_readiness_score", report.get("pass_rate", 0.0)) if mkt_data else report.get("pass_rate", 0.0),
        "pillar_scores": mkt_data.get("pillar_scores") if mkt_data else None,
        "security_summary": mkt_data.get("security_summary") if mkt_data else None,
        "total": report.get("total", 0),
        "passed": report.get("passed", 0),
        "failed": report.get("failed", 0),
        "errors": report.get("errors", 0),
        "skipped": report.get("skipped", 0),
        "pass_rate": report.get("pass_rate", 0.0),
        "total_duration_ms": report.get("total_duration_ms", 0.0),
        "failure_analyses": eval_report.get("failure_analyses", []) if eval_report else [],
        "specialist_review": st.session_state.specialist_review,
        "overrides": {k: ("Approved via formal override" if v else "Defect active") for k, v in st.session_state.overrides.items()},
        "qa_notes": {k: v for k, v in st.session_state.qa_notes.items() if v},
        "results": report.get("results", []),
    }

    decision_data["signature"] = _sign_payload(decision_data)
    st.session_state.deployment_decision = decision_data

    # Persist audit reports
    json_path = REPORTS_DIR / "qa_deployment_report.json"
    json_path.write_text(json.dumps(decision_data, indent=2, default=str), encoding="utf-8")

    md_report_content = generate_audit_markdown_report(decision_data)
    md_path = REPORTS_DIR / "qa_deployment_report.md"
    md_path.write_text(md_report_content, encoding="utf-8")

    pdf_path = REPORTS_DIR / "qa_deployment_report.pdf"
    generate_pdf_audit_report(decision_data, pdf_path)

    st.rerun()

if st.session_state.deployment_decision:
    dec = st.session_state.deployment_decision
    if dec["approved"]:
        st.success(
            f"STATUS: APPROVED FOR PRODUCTION\n\n"
            f"Certified by: {dec['reviewer']} | Timestamp: {dec['timestamp']}"
        )
    else:
        st.error(
            f"STATUS: DEPLOYMENT BLOCKED\n\n"
            f"Blocked by: {dec['reviewer']} | Timestamp: {dec['timestamp']}"
        )

    st.caption(f"Cryptographic Verification Digest (SHA-256): {dec['signature']}")

    with st.expander("Inspect Generated Audit Report (Formal Markdown)", expanded=True):
        md_path = REPORTS_DIR / "qa_deployment_report.md"
        if md_path.exists():
            st.markdown(md_path.read_text(encoding="utf-8"))

    col_dl_json, col_dl_md, col_dl_pdf = st.columns(3)
    with col_dl_json:
        st.download_button(
            "Download Audit Report (JSON)",
            data=json.dumps(dec, indent=2, default=str),
            file_name="qa_deployment_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with col_dl_md:
        md_content = generate_audit_markdown_report(dec)
        st.download_button(
            "Download Audit Report (Markdown)",
            data=md_content,
            file_name="qa_deployment_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with col_dl_pdf:
        pdf_path = REPORTS_DIR / "qa_deployment_report.pdf"
        if not pdf_path.exists():
            generate_pdf_audit_report(dec, pdf_path)
        st.download_button(
            "Download Audit Report (PDF)",
            data=pdf_path.read_bytes(),
            file_name="qa_deployment_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    if st.button("Reset Quality Gate Decision", use_container_width=True):
        st.session_state.deployment_decision = None
        st.rerun()
