"""
SOC Sentinel — Streamlit UI

Multi-Agent SOC Triage with OWASP Nettacker Recon, powered by Mistral AI.

Usage:
    streamlit run app.py
"""

import json
import os
import time
from io import StringIO
from contextlib import redirect_stdout

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# Ensure demo mode for reliable UI
os.environ.setdefault("DEMO_MODE", "true")

from demo.demo_data import DEMO_ALERTS
from graph.graph import app
from graph.state import SOCState

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOC Sentinel AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ SOC Sentinel")
    st.caption("Multi-Agent SOC Triage")
    st.caption("Powered by Mistral AI + OWASP Nettacker")
    st.divider()

    if st.button("🚀 Import Demo Alerts & Run Pipeline", type="primary", use_container_width=True):
        st.session_state["run_pipeline"] = True

    st.divider()
    st.subheader("Agent Status")

    if "final_state" in st.session_state:
        agents = {
            "Commander": "🟢",
            "Triage Officer": "🟢",
            "Threat Hunter": "🟢",
            "Forensics Analyst": "🟢",
            "Recon Specialist": "🟢",
            "Oversight Officer": "🟢",
            "Briefing Writer": "🟢",
        }
    elif st.session_state.get("run_pipeline"):
        agents = {
            "Commander": "🟡",
            "Triage Officer": "🟡",
            "Threat Hunter": "🟡",
            "Forensics Analyst": "🟡",
            "Recon Specialist": "🟡",
            "Oversight Officer": "🟡",
            "Briefing Writer": "🟡",
        }
    else:
        agents = {
            "Commander": "⚪",
            "Triage Officer": "⚪",
            "Threat Hunter": "⚪",
            "Forensics Analyst": "⚪",
            "Recon Specialist": "⚪",
            "Oversight Officer": "⚪",
            "Briefing Writer": "⚪",
        }

    for name, status in agents.items():
        st.text(f"{status} {name}")

    st.divider()
    st.caption(f"Alerts loaded: {len(DEMO_ALERTS)}")
    if "elapsed" in st.session_state:
        st.caption(f"Pipeline time: {st.session_state['elapsed']:.1f}s")

# ---------------------------------------------------------------------------
# Run pipeline if triggered
# ---------------------------------------------------------------------------

if st.session_state.get("run_pipeline") and "final_state" not in st.session_state:
    initial_state: SOCState = {
        "alerts": DEMO_ALERTS,
        "triage_results": [],
        "enrichment_results": [],
        "forensics_results": [],
        "recon_results": [],
        "oversight_verdict": {},
        "confidence": 0.0,
        "briefing": "",
        "verification_alerts": [],
        "iteration_count": 0,
    }

    # Capture stdout for agent activity log
    log_buffer = StringIO()
    with st.spinner("🔄 Running 6-agent pipeline... This may take 30-60 seconds."):
        start_time = time.time()
        with redirect_stdout(log_buffer):
            final_state = app.invoke(initial_state)
        elapsed = time.time() - start_time

    st.session_state["final_state"] = final_state
    st.session_state["elapsed"] = elapsed
    st.session_state["agent_log"] = log_buffer.getvalue()
    st.session_state["run_pipeline"] = False
    st.rerun()

# ---------------------------------------------------------------------------
# Verification alert banner
# ---------------------------------------------------------------------------

if "final_state" in st.session_state:
    state = st.session_state["final_state"]
    verdict = state.get("oversight_verdict", {})
    conflicts = verdict.get("conflicts", [])

    # Show red banner for critical conflicts
    severity_conflicts = [
        c for c in conflicts
        if isinstance(c, dict) and c.get("conflict_type") in (
            "SEVERITY_CONFLICT", "RECON_SEVERITY_MISMATCH", "CORROBORATING_EVIDENCE"
        )
    ]

    if severity_conflicts:
        for sc in severity_conflicts:
            if sc.get("conflict_type") == "SEVERITY_CONFLICT":
                st.error(
                    f"🚨 **VERIFICATION ALERT**: Agent conflict on **{sc.get('alert_id')}**. "
                    f"{sc.get('description', '')}",
                    icon="🚨",
                )
            elif sc.get("conflict_type") == "RECON_SEVERITY_MISMATCH":
                st.warning(
                    f"⚠️ **RECON MISMATCH**: {sc.get('alert_id')} — "
                    f"{sc.get('description', '')}",
                    icon="⚠️",
                )
            elif sc.get("conflict_type") == "CORROBORATING_EVIDENCE":
                st.info(
                    f"🔗 **CORROBORATING EVIDENCE**: {sc.get('alert_id')} — "
                    f"{sc.get('description', '')}",
                    icon="🔗",
                )

# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

st.title("🛡️ SOC Sentinel AI Agent Cluster")
st.caption("Multi-Agent SOC Triage with OWASP Nettacker Recon — Powered by Mistral AI")

if "final_state" not in st.session_state:
    st.info("👈 Click **Import Demo Alerts & Run Pipeline** in the sidebar to get started.")
    st.stop()

state = st.session_state["final_state"]

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Alert Queue",
    "🤖 Agent Activity",
    "🔍 Recon Results",
    "📄 Final Report",
])

# --- Tab 1: Alert Queue ---
with tab1:
    st.subheader("Alert Queue")

    # Build table data
    triage_by_id = {r["alert_id"]: r for r in state.get("triage_results", [])}
    enrich_by_id = {r["alert_id"]: r for r in state.get("enrichment_results", [])}
    recon_by_id = {r["alert_id"]: r for r in state.get("recon_results", [])}

    table_data = []
    for alert in state["alerts"]:
        aid = alert["id"]
        t = triage_by_id.get(aid, {})
        e = enrich_by_id.get(aid, {})
        r = recon_by_id.get(aid, {})

        severity = t.get("severity", "N/A")
        threat_actor = e.get("threat_actor", "Unknown")
        recon_score = r.get("attack_surface_score", "N/A")

        # Determine final verdict per alert
        final_verdict = severity
        # Check if oversight overrode this alert
        for c in verdict.get("conflicts", []):
            if isinstance(c, dict) and c.get("alert_id") == aid:
                if c.get("conflict_type") in ("SEVERITY_CONFLICT", "RECON_SEVERITY_MISMATCH"):
                    final_verdict = "⬆️ CRITICAL (Override)"

        table_data.append({
            "Alert ID": aid,
            "Source IP": alert.get("source_ip", ""),
            "Type": alert.get("alert_type", ""),
            "Triage": severity,
            "Threat Intel": threat_actor[:20],
            "Recon Score": recon_score,
            "Final Verdict": final_verdict,
        })

    st.dataframe(
        table_data,
        use_container_width=True,
        hide_index=True,
    )

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    severities = [t.get("severity", "") for t in state.get("triage_results", [])]
    with col1:
        st.metric("Total Alerts", len(state["alerts"]))
    with col2:
        critical_count = severities.count("Critical") + severities.count("High")
        st.metric("Critical/High", critical_count)
    with col3:
        noise_count = severities.count("Noise") + severities.count("Low")
        st.metric("Noise/Low", noise_count)
    with col4:
        st.metric("Confidence", f"{state.get('confidence', 0):.0f}/100")


# --- Tab 2: Agent Activity ---
with tab2:
    st.subheader("Agent Activity Log")
    if "agent_log" in st.session_state:
        st.code(st.session_state["agent_log"], language="text")
    else:
        st.info("Run the pipeline to see agent activity.")


# --- Tab 3: Recon Results ---
with tab3:
    st.subheader("Reconnaissance Results (OWASP Nettacker)")

    recon_results = state.get("recon_results", [])

    # Deduplicate by target
    seen_targets = set()
    for r in recon_results:
        target = r.get("target", "")
        if target in seen_targets:
            continue
        seen_targets.add(target)

        score = r.get("attack_surface_score", 0)

        # Color based on score
        if score >= 70:
            icon = "🔴"
        elif score >= 40:
            icon = "🟡"
        else:
            icon = "🟢"

        with st.expander(f"{icon} {target} — Attack Surface: {score}/100", expanded=(score >= 70)):
            col1, col2 = st.columns([1, 1])

            with col1:
                st.markdown("**Open Ports**")
                ports = r.get("open_ports", [])
                if ports:
                    c2_ports = {4444, 8443, 1337, 9999}
                    db_ports = {3306, 5432, 27017, 6379}

                    for p in ports:
                        services = r.get("services", {})
                        svc = services.get(str(p), "unknown")
                        badge = ""
                        if p in c2_ports:
                            badge = " 🔴 **C2**"
                        elif p in db_ports:
                            badge = " 🟠 **DB**"
                        st.markdown(f"- `{p}` — {svc}{badge}")
                else:
                    st.text("No open ports detected")

            with col2:
                st.markdown("**Vulnerabilities**")
                vulns = r.get("vulnerabilities", [])
                if vulns:
                    for v in vulns:
                        sev = v.get("severity", "unknown")
                        if sev == "critical":
                            sev_icon = "🔴"
                        elif sev == "high":
                            sev_icon = "🟠"
                        elif sev == "medium":
                            sev_icon = "🟡"
                        else:
                            sev_icon = "⚪"
                        st.markdown(f"- {sev_icon} **{v.get('type', 'unknown')}** ({sev}): {v.get('detail', '')}")
                else:
                    st.text("No vulnerabilities detected")

            # Attack surface gauge
            st.progress(min(score / 100, 1.0), text=f"Attack Surface Score: {score}/100")

            # LLM interpretation
            notes = r.get("notes", "")
            if notes:
                st.info(f"**Analysis:** {notes}")


# --- Tab 4: Final Report ---
with tab4:
    st.subheader("Security Briefing")
    briefing = state.get("briefing", "No briefing generated.")
    st.code(briefing, language="text")

    with st.expander("Raw Oversight Verdict (JSON)"):
        st.json(state.get("oversight_verdict", {}))
