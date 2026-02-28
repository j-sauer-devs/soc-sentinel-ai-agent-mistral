"""
SOC Sentinel — LangGraph StateGraph

Topology:
  commander ──fan-out──> triage ──────────────┐
                  └────> threat_hunter ────────┤
                  └────> forensics ────────────┼──> oversight ──> briefing
                  └────> recon_specialist ─────┘
                              ^
                              │  (confidence < 70 AND iteration < 3)
                              └──────────────────────────────────────┘

The commander fans out to triage, threat_hunter, forensics, and recon_specialist
in parallel via Send. LangGraph waits for all four branches before moving to oversight.
Oversight conditionally loops back to commander for re-investigation.
"""

from langgraph.graph import END, StateGraph
from langgraph.types import Send

from graph.nodes import (
    briefing_node,
    commander_node,
    forensics_node,
    oversight_node,
    recon_specialist_node,
    threat_hunter_node,
    triage_node,
)
from graph.state import SOCState


# ---------------------------------------------------------------------------
# Conditional edge: oversight -> loop or finish
# ---------------------------------------------------------------------------

def should_reinvestigate(state: SOCState):
    confidence = state.get("confidence", 100.0)
    iteration = state.get("iteration_count", 0)

    if confidence < 70 and iteration < 3:
        print(
            f"[Graph] Confidence {confidence:.1f} < 70 on iteration {iteration} — "
            "looping back to Commander for re-investigation."
        )
        return "commander"
    return "briefing"


# ---------------------------------------------------------------------------
# Commander fan-out: dispatch all four specialists in parallel via Send
# ---------------------------------------------------------------------------

def commander_fanout(state: SOCState):
    """Return Send objects to dispatch triage, threat_hunter, forensics, recon_specialist in parallel."""
    return [
        Send("triage", state),
        Send("threat_hunter", state),
        Send("forensics", state),
        Send("recon_specialist", state),
    ]


# ---------------------------------------------------------------------------
# Build graph
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    graph = StateGraph(SOCState)

    # Register nodes
    graph.add_node("commander", commander_node)
    graph.add_node("triage", triage_node)
    graph.add_node("threat_hunter", threat_hunter_node)
    graph.add_node("forensics", forensics_node)
    graph.add_node("recon_specialist", recon_specialist_node)
    graph.add_node("oversight", oversight_node)
    graph.add_node("briefing", briefing_node)

    # Entry point
    graph.set_entry_point("commander")

    # Commander fans out to all four specialists in parallel
    graph.add_conditional_edges(
        "commander",
        commander_fanout,
        ["triage", "threat_hunter", "forensics", "recon_specialist"],
    )

    # All four specialists converge at oversight
    graph.add_edge("triage", "oversight")
    graph.add_edge("threat_hunter", "oversight")
    graph.add_edge("forensics", "oversight")
    graph.add_edge("recon_specialist", "oversight")

    # Oversight: loop back or finish
    graph.add_conditional_edges(
        "oversight",
        should_reinvestigate,
        {"commander": "commander", "briefing": "briefing"},
    )

    # Briefing is the terminal node
    graph.add_edge("briefing", END)

    return graph


# Compile and export — import this in run.py and anywhere else
app = build_graph().compile()
