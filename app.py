"""
SOC Sentinel — Streamlit UI

Multi-Agent SOC Triage with OWASP Nettacker Recon, powered by Mistral AI.
Includes interactive SVG architecture diagram with animated agent data flow.

Usage:
    streamlit run app.py
"""

import os
import re
import time
from io import StringIO
from contextlib import redirect_stdout

import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

load_dotenv()

# Ensure demo mode for reliable UI
os.environ.setdefault("DEMO_MODE", "true")

from demo.demo_data import DEMO_ALERTS
from graph.graph import app
from graph.state import SOCState

# ---------------------------------------------------------------------------
# Agent log parser — extracts per-agent completion status from stdout capture
# ---------------------------------------------------------------------------

def parse_agent_log(log_text: str) -> dict:
    """Parse captured agent stdout to determine per-agent completion status."""
    patterns = {
        "commander":    (r"\[Commander\] Routing (\d+) alert",      "{0} alerts routed"),
        "triage":       (r"\[Triage Officer\] Done\. (\d+) alert",  "{0} classified"),
        "threat_hunter":(r"\[Threat Hunter\] Done\. (\d+) alert",   "{0} enriched"),
        "forensics":    (r"\[Forensics Analyst\] Done\. (\d+) report", "{0} reports"),
        "recon":        (r"\[Recon Specialist\] Done\. (\d+) recon",   "{0} scanned"),
        "oversight":    (r"\[Oversight Officer\] Verdict: (\S+)",   "Verdict: {0}"),
        "briefing":     (r"\[Briefing Writer\] Done",               "Report ready"),
    }
    statuses = {}
    for agent_id, (pattern, template) in patterns.items():
        match = re.search(pattern, log_text)
        if match:
            groups = match.groups() if match.groups() else ()
            detail = template.format(*groups) if groups else template
            statuses[agent_id] = {"status": "completed", "detail": detail}
        else:
            statuses[agent_id] = {"status": "idle", "detail": ""}
    return statuses


# ---------------------------------------------------------------------------
# SVG Architecture Diagram — renders the full agent graph with animations
# ---------------------------------------------------------------------------

def render_agent_graph(phase: str, agent_statuses: dict = None,
                       conflict_count: int = 0, confidence: float = 0.0) -> str:
    """Return HTML+SVG for the agent architecture diagram.

    phase: "idle" | "running" | "completed"
    """
    if agent_statuses is None:
        agent_statuses = {}

    # --- Colour palette per phase ---
    if phase == "idle":
        node_fill     = "#16182d"
        node_stroke   = "#3d4065"
        conn_stroke   = "#2d305a"
        label_color   = "#8888aa"
        subtitle_color = "#5d5f8a"
        dash          = "6,4"
        glow          = "none"
        bg_color      = "#0d0f1a"
    elif phase == "running":
        node_fill     = "#1e1a10"
        node_stroke   = "#f59e0b"
        conn_stroke   = "#f59e0b"
        label_color   = "#fbbf24"
        subtitle_color = "#d97706"
        dash          = "6,4"
        glow          = "url(#glowAmber)"
        bg_color      = "#0d0f1a"
    else:  # completed
        node_fill     = "#0f1f15"
        node_stroke   = "#22c55e"
        conn_stroke   = "#22c55e"
        label_color   = "#4ade80"
        subtitle_color = "#16a34a"
        dash          = "none"
        glow          = "url(#glowGreen)"
        bg_color      = "#0d0f1a"

    # --- Node metadata: (id, label, subtitle, icon_char, cx, cy) ---
    nodes = [
        ("commander",     "Commander",         "Entry Point",        "⌘",  350, 55),
        ("triage",        "Triage Officer",    "IP Reputation",      "🎯", 100, 195),
        ("threat_hunter", "Threat Hunter",     "IOC Enrichment",     "🔍", 280, 195),
        ("forensics",     "Forensics Analyst", "CVE Analysis",       "🧬", 460, 195),
        ("recon",         "Recon Specialist",  "Nettacker Scan",     "📡", 640, 195),
        ("oversight",     "Oversight Officer", "Cross-Verification", "⚖️",  350, 330),
        ("briefing",      "Briefing Writer",   "Final Report",       "📄", 350, 440),
    ]

    # --- Build connection paths (id, d-attribute) ---
    connections = [
        # Commander fan-out
        ("c-cmd-tri",  "M 350 80  Q 225 140 100 175"),
        ("c-cmd-thr",  "M 350 80  Q 315 140 280 175"),
        ("c-cmd-for",  "M 350 80  Q 405 140 460 175"),
        ("c-cmd-rec",  "M 350 80  Q 495 140 640 175"),
        # Convergence to oversight
        ("c-tri-ovs",  "M 100 220 Q 225 280 350 310"),
        ("c-thr-ovs",  "M 280 220 Q 315 280 350 310"),
        ("c-for-ovs",  "M 460 220 Q 405 280 350 310"),
        ("c-rec-ovs",  "M 640 220 Q 495 280 350 310"),
        # Oversight to briefing
        ("c-ovs-brf",  "M 350 355 L 350 420"),
    ]

    # Loop-back path (Oversight -> Commander, right side)
    loop_path = "M 430 330 Q 730 330 730 55 Q 730 20 430 55"

    # --- Build per-node color overrides for completed state ---
    def node_colors(nid):
        if phase == "completed":
            s = agent_statuses.get(nid, {})
            if s.get("status") == "completed":
                return "#0f1f15", "#22c55e", "url(#glowGreen)"
            return "#16182d", "#3d4065", "none"
        return node_fill, node_stroke, glow

    # --- Detail badge text for completed nodes ---
    def detail_text(nid):
        if phase != "completed":
            return ""
        return agent_statuses.get(nid, {}).get("detail", "")

    # --- Build SVG nodes ---
    node_w, node_h, rx = 146, 50, 12
    svg_nodes = ""
    for nid, label, subtitle, icon, cx, cy in nodes:
        nf, ns, ng = node_colors(nid)
        x = cx - node_w // 2
        y = cy - node_h // 2
        detail = detail_text(nid)

        # Conflict badge for oversight
        badge = ""
        if nid == "oversight" and phase == "completed" and conflict_count > 0:
            badge = f'''
            <circle cx="{cx + node_w//2 - 5}" cy="{cy - node_h//2 + 5}" r="13"
                    fill="#ef4444" stroke="{bg_color}" stroke-width="2.5">
                <animate attributeName="opacity" values="1;0.6;1" dur="2s" repeatCount="indefinite"/>
            </circle>
            <text x="{cx + node_w//2 - 5}" y="{cy - node_h//2 + 9}"
                  text-anchor="middle" fill="white" font-size="10" font-weight="bold">{conflict_count}</text>
            '''

        # Confidence badge for oversight
        conf_badge = ""
        if nid == "oversight" and phase == "completed" and confidence > 0:
            conf_color = "#22c55e" if confidence >= 70 else "#f59e0b" if confidence >= 40 else "#ef4444"
            conf_badge = f'''
            <rect x="{cx - 28}" y="{cy + node_h//2 + 28}" width="56" height="20" rx="10"
                  fill="{bg_color}" stroke="{conf_color}" stroke-width="1.5"/>
            <text x="{cx}" y="{cy + node_h//2 + 42}"
                  text-anchor="middle" fill="{conf_color}" font-size="11"
                  font-family="monospace" font-weight="bold">{confidence:.0f}/100</text>
            '''

        # Detail label below node
        detail_label = ""
        if detail:
            detail_label = f'''
            <text x="{cx}" y="{cy + node_h//2 + 16}"
                  text-anchor="middle" fill="{label_color}" font-size="9"
                  font-family="monospace" opacity="0.9">{detail}</text>
            '''

        anim_class = f'class="node-pulse"' if phase == "running" else ""

        # Checkmark for completed nodes
        checkmark = ""
        if phase == "completed" and agent_statuses.get(nid, {}).get("status") == "completed":
            checkmark = f'''
            <circle cx="{cx - node_w//2 + 8}" cy="{cy - node_h//2 + 8}" r="7"
                    fill="#22c55e" stroke="{bg_color}" stroke-width="1.5"/>
            <text x="{cx - node_w//2 + 8}" y="{cy - node_h//2 + 12}"
                  text-anchor="middle" fill="white" font-size="9" font-weight="bold">✓</text>
            '''

        svg_nodes += f'''
        <g {anim_class}>
            <rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="{rx}"
                  fill="{nf}" stroke="{ns}" stroke-width="2"
                  filter="{ng}"/>
            <text x="{cx}" y="{cy - 3}" text-anchor="middle"
                  fill="#e8e8f0" font-size="12.5" font-weight="bold"
                  font-family="'Segoe UI', system-ui, sans-serif">{label}</text>
            <text x="{cx}" y="{cy + 13}" text-anchor="middle"
                  fill="{subtitle_color}" font-size="9"
                  font-family="'Segoe UI', system-ui, sans-serif">{subtitle}</text>
            {badge}
            {checkmark}
            {detail_label}
            {conf_badge}
        </g>
        '''

    # --- Build SVG connections ---
    svg_conns = ""
    for cid, d in connections:
        svg_conns += f'''
        <path id="{cid}" d="{d}" fill="none"
              stroke="{conn_stroke}" stroke-width="1.8"
              stroke-dasharray="{dash}" marker-end="url(#arrow)"
              opacity="0.6"/>
        '''

    # --- Loop-back arrow ---
    loop_opacity = "0.3"
    loop_dash = "6,4"
    loop_color = "#818cf8"
    if phase == "completed":
        loop_opacity = "0.5"
    svg_conns += f'''
    <path id="c-loop" d="{loop_path}" fill="none"
          stroke="{loop_color}" stroke-width="1.5"
          stroke-dasharray="{loop_dash}" marker-end="url(#arrowLoop)"
          opacity="{loop_opacity}"/>
    <text font-size="8.5" fill="{loop_color}" font-family="monospace" opacity="0.6">
        <textPath href="#c-loop" startOffset="35%" text-anchor="middle">
            confidence &lt; 70 → re-investigate
        </textPath>
    </text>
    '''

    # --- Animated particles (running state) ---
    svg_particles = ""
    if phase == "running":
        particle_color = "#f59e0b"
        particle_glow = "#fbbf24"
        durations = ["1.5s", "1.8s", "2.0s", "1.6s", "1.7s", "1.9s", "2.1s", "1.4s", "1.3s"]
        for i, (cid, _) in enumerate(connections):
            dur = durations[i % len(durations)]
            # Primary particle
            svg_particles += f'''
            <circle r="3.5" fill="{particle_color}" opacity="0.95">
                <animateMotion dur="{dur}" repeatCount="indefinite">
                    <mpath href="#{cid}"/>
                </animateMotion>
            </circle>
            '''
            # Trailing glow particle
            svg_particles += f'''
            <circle r="6" fill="{particle_glow}" opacity="0.2">
                <animateMotion dur="{dur}" repeatCount="indefinite">
                    <mpath href="#{cid}"/>
                </animateMotion>
            </circle>
            '''
        # Loop-back particle (slower, purple)
        svg_particles += f'''
        <circle r="3" fill="{loop_color}" opacity="0.8">
            <animateMotion dur="3s" repeatCount="indefinite">
                <mpath href="#c-loop"/>
            </animateMotion>
        </circle>
        '''

    # --- Status text at the bottom ---
    status_text = ""
    if phase == "idle":
        status_text = f'''
        <text x="380" y="475" text-anchor="middle" fill="#4a4c7a" font-size="11"
              font-family="monospace">Ready — click Run Pipeline to begin</text>
        '''
    elif phase == "running":
        status_text = f'''
        <text x="380" y="475" text-anchor="middle" fill="#f59e0b" font-size="11"
              font-family="monospace" class="node-pulse">
            ● Processing alerts through 7-agent pipeline...
        </text>
        '''
    elif phase == "completed":
        v = agent_statuses.get("oversight", {}).get("detail", "")
        status_text = f'''
        <text x="380" y="475" text-anchor="middle" fill="#22c55e" font-size="11"
              font-family="monospace">✓ Pipeline complete — {v}</text>
        '''

    # --- Assemble full HTML ---
    html = f'''
    <html><body style="margin:0; padding:0; background:transparent; overflow:hidden;">
    <div style="display:flex; justify-content:center; padding: 8px 0;">
    <svg viewBox="0 0 760 490" width="100%" height="490"
         preserveAspectRatio="xMidYMid meet"
         xmlns="http://www.w3.org/2000/svg"
         style="max-width: 920px; font-family: 'Segoe UI', system-ui, sans-serif;">

        <!-- Background (transparent to match Streamlit theme) -->
        <rect width="760" height="490" rx="16" fill="transparent"/>

        <defs>
            <!-- Arrow markers -->
            <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5"
                    markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="{conn_stroke}" opacity="0.7"/>
            </marker>
            <marker id="arrowLoop" viewBox="0 0 10 10" refX="10" refY="5"
                    markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="{loop_color}" opacity="0.6"/>
            </marker>

            <!-- Glow filters -->
            <filter id="glowAmber" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="6" result="blur"/>
                <feFlood flood-color="#f59e0b" flood-opacity="0.35"/>
                <feComposite in2="blur" operator="in"/>
                <feMerge>
                    <feMergeNode/>
                    <feMergeNode in="SourceGraphic"/>
                </feMerge>
            </filter>
            <filter id="glowGreen" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="5" result="blur"/>
                <feFlood flood-color="#22c55e" flood-opacity="0.3"/>
                <feComposite in2="blur" operator="in"/>
                <feMerge>
                    <feMergeNode/>
                    <feMergeNode in="SourceGraphic"/>
                </feMerge>
            </filter>
            <filter id="glowCyan" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="4" result="blur"/>
                <feFlood flood-color="#06b6d4" flood-opacity="0.3"/>
                <feComposite in2="blur" operator="in"/>
                <feMerge>
                    <feMergeNode/>
                    <feMergeNode in="SourceGraphic"/>
                </feMerge>
            </filter>
        </defs>

        <style>
            @keyframes pulse {{
                0%, 100% {{ opacity: 0.8; }}
                50% {{ opacity: 1; }}
            }}
            @keyframes glow-pulse {{
                0%, 100% {{ filter: brightness(1); }}
                50% {{ filter: brightness(1.3); }}
            }}
            @keyframes dash-march {{
                0% {{ stroke-dashoffset: 20; }}
                100% {{ stroke-dashoffset: 0; }}
            }}
            .node-pulse {{
                animation: pulse 2s ease-in-out infinite;
            }}
            .conn-flow {{
                animation: dash-march 1s linear infinite;
            }}
        </style>

        <!-- Tier separator lines -->
        <line x1="40" y1="125" x2="720" y2="125" stroke="#1a1c35" stroke-width="1" opacity="0.5"/>
        <line x1="40" y1="270" x2="720" y2="270" stroke="#1a1c35" stroke-width="1" opacity="0.5"/>
        <line x1="40" y1="395" x2="720" y2="395" stroke="#1a1c35" stroke-width="1" opacity="0.5"/>

        <!-- Tier labels -->
        <text x="30" y="55" fill="#3d4065" font-size="8" font-family="monospace"
              transform="rotate(-90, 30, 55)" letter-spacing="2">ENTRY</text>
        <text x="30" y="210" fill="#3d4065" font-size="8" font-family="monospace"
              transform="rotate(-90, 30, 210)" letter-spacing="2">SPECIALISTS</text>
        <text x="30" y="345" fill="#3d4065" font-size="8" font-family="monospace"
              transform="rotate(-90, 30, 345)" letter-spacing="2">VERIFY</text>
        <text x="30" y="445" fill="#3d4065" font-size="8" font-family="monospace"
              transform="rotate(-90, 30, 445)" letter-spacing="2">REPORT</text>

        <!-- Connections (drawn first, behind nodes) -->
        {svg_conns}

        <!-- Animated particles -->
        {svg_particles}

        <!-- Nodes -->
        {svg_nodes}

        <!-- Status -->
        {status_text}

    </svg>
    </div>
    </body></html>
    '''
    return html


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
# Custom CSS for a polished SOC-themed UI
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    /* Header styling */
    .main-title {
        background: linear-gradient(135deg, #1a1f3a 0%, #0f1328 100%);
        border: 1px solid #2a2f55;
        border-radius: 12px;
        padding: 20px 28px;
        margin-bottom: 20px;
    }
    .main-title h1 {
        margin: 0 0 4px 0;
        font-size: 1.8rem;
        color: #ffffff !important;
    }
    .main-title p {
        margin: 0;
        color: #9ca3af;
        font-size: 0.9rem;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        border: 1px solid #252850;
        border-radius: 10px;
        padding: 12px 16px;
    }
    [data-testid="stMetric"] label {
        color: #8b8fa8 !important;
        font-size: 0.8rem !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #e0e4f0 !important;
        font-size: 1.6rem !important;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        color: #a78bfa !important;
    }

    /* Running status banner */
    .running-banner {
        background: linear-gradient(135deg, #1a1510 0%, #1e1608 100%);
        border: 1px solid #f59e0b40;
        border-radius: 10px;
        padding: 12px 20px;
        text-align: center;
        margin-bottom: 12px;
        animation: banner-pulse 2s ease-in-out infinite;
    }
    @keyframes banner-pulse {
        0%, 100% { border-color: #f59e0b40; }
        50% { border-color: #f59e0b80; }
    }
    .running-banner .status-text {
        color: #fbbf24;
        font-family: monospace;
        font-size: 0.95rem;
    }
    .running-banner .elapsed-text {
        color: #92702a;
        font-family: monospace;
        font-size: 0.8rem;
        margin-top: 4px;
    }
</style>
""", unsafe_allow_html=True)

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

    # Compact agent status
    if "final_state" in st.session_state:
        status_icon, status_label = "🟢", "Pipeline Complete"
    elif st.session_state.get("run_pipeline"):
        status_icon, status_label = "🟡", "Running..."
    else:
        status_icon, status_label = "⚪", "Idle"

    st.markdown(f"**Status:** {status_icon} {status_label}")
    st.caption(f"Alerts loaded: {len(DEMO_ALERTS)}")
    if "elapsed" in st.session_state:
        st.caption(f"Pipeline time: {st.session_state['elapsed']:.1f}s")
    if "final_state" in st.session_state:
        fs = st.session_state["final_state"]
        st.caption(f"Confidence: {fs.get('confidence', 0):.0f}/100")
        n_conflicts = len(fs.get("oversight_verdict", {}).get("conflicts", []))
        if n_conflicts > 0:
            st.caption(f"⚠️ Conflicts: {n_conflicts}")

    st.divider()
    st.caption("Mistral Small → speed agents")
    st.caption("Mistral Large → reasoning agents")
    st.caption(f"Demo alerts: {len(DEMO_ALERTS)}")

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

    # Show the animated running architecture diagram
    st.markdown(
        '<div class="main-title"><h1>🛡️ SOC Sentinel AI Agent Cluster</h1>'
        '<p>Multi-Agent SOC Triage with OWASP Nettacker Recon — Powered by Mistral AI</p></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="running-banner">'
        '<div class="status-text">● Processing {0} alerts through 7-agent pipeline...</div>'
        '<div class="elapsed-text">Commander → Triage + Threat Hunter + Forensics + Recon → Oversight → Briefing</div>'
        '</div>'.format(len(DEMO_ALERTS)),
        unsafe_allow_html=True,
    )

    # Display the animated running-state architecture diagram
    components.html(render_agent_graph("running"), height=520, scrolling=False)

    # Capture stdout for agent activity log
    log_buffer = StringIO()
    start_time = time.time()
    try:
        with redirect_stdout(log_buffer):
            final_state = app.invoke(initial_state)
        elapsed = time.time() - start_time

        st.session_state["final_state"] = final_state
        st.session_state["elapsed"] = elapsed
        st.session_state["agent_log"] = log_buffer.getvalue()
        st.session_state["run_pipeline"] = False
        st.rerun()
    except Exception as e:
        elapsed = time.time() - start_time
        st.session_state["agent_log"] = log_buffer.getvalue()
        st.session_state["run_pipeline"] = False
        st.error(f"Pipeline error after {elapsed:.1f}s: {e}")
        st.code(log_buffer.getvalue(), language="text")
    st.stop()

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

st.markdown(
    '<div class="main-title"><h1>🛡️ SOC Sentinel AI Agent Cluster</h1>'
    '<p>Multi-Agent SOC Triage with OWASP Nettacker Recon — Powered by Mistral AI</p></div>',
    unsafe_allow_html=True,
)

if "final_state" not in st.session_state:
    # Show architecture diagram in idle state
    components.html(render_agent_graph("idle"), height=520, scrolling=False)
    st.info("👈 Click **Import Demo Alerts & Run Pipeline** in the sidebar to get started.")
    st.stop()

state = st.session_state["final_state"]

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

# --- Summary metrics row at top ---
log = st.session_state.get("agent_log", "")
agent_statuses = parse_agent_log(log)
n_conflicts = len(state.get("oversight_verdict", {}).get("conflicts", []))
conf = state.get("confidence", 0.0)

triage_by_id = {r["alert_id"]: r for r in state.get("triage_results", [])}
enrich_by_id = {r["alert_id"]: r for r in state.get("enrichment_results", [])}
recon_by_id = {r["alert_id"]: r for r in state.get("recon_results", [])}
severities = [t.get("severity", "") for t in triage_by_id.values()]

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Alerts Processed", len(state["alerts"]))
with col2:
    critical_count = severities.count("Critical") + severities.count("High")
    st.metric("Critical / High", critical_count)
with col3:
    noise_count = severities.count("Noise") + severities.count("Low")
    st.metric("Noise / Low", noise_count)
with col4:
    st.metric("Confidence", f"{conf:.0f}/100")
with col5:
    st.metric("Conflicts", n_conflicts)

st.markdown("")  # spacing

tab_arch, tab1, tab2, tab3, tab4 = st.tabs([
    "🏗️ Architecture",
    "📋 Alert Queue",
    "🤖 Agent Activity",
    "🔍 Recon Results",
    "📄 Final Report",
])

# --- Tab: Architecture ---
with tab_arch:
    elapsed = st.session_state.get("elapsed", 0)
    st.caption(f"Pipeline completed in {elapsed:.1f}s — all 7 agents finished successfully")
    components.html(render_agent_graph("completed", agent_statuses, n_conflicts, conf), height=520, scrolling=False)

# --- Tab 1: Alert Queue ---
with tab1:
    st.subheader("Alert Queue")

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
    # Voice briefing section first
    voice_col, report_col = st.columns([1, 2])

    with voice_col:
        st.subheader("🔊 Voice Briefing")
        st.caption("Hands-free audio — ElevenLabs TTS")

        if "voice_audio" in st.session_state and st.session_state["voice_audio"]:
            st.audio(st.session_state["voice_audio"], format="audio/mp3")
            st.success("Audio ready — ~1 min executive summary")
        elif st.button("🎙️ Generate Voice Briefing", type="primary", use_container_width=True):
            with st.spinner("Generating voice briefing..."):
                try:
                    from apis.elevenlabs_tts import generate_briefing_audio, build_executive_summary
                    speech_text = build_executive_summary(state)
                    audio_bytes = generate_briefing_audio(speech_text)
                    if audio_bytes:
                        st.session_state["voice_audio"] = audio_bytes
                        st.rerun()
                    else:
                        st.warning("Check ELEVENLABS_KEY in .env")
                except Exception as e:
                    st.error(f"Voice generation failed: {e}")
        else:
            st.info("Generate an audio summary for hands-free SOC operations during incident response.")

    with report_col:
        st.subheader("Security Briefing")
        briefing = state.get("briefing", "No briefing generated.")
        st.code(briefing, language="text")

    with st.expander("🔎 Raw Oversight Verdict (JSON)"):
        st.json(state.get("oversight_verdict", {}))
