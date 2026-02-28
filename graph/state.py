"""
LangGraph state schema for SOC Sentinel.

All agent nodes read from and write to this shared TypedDict.
Annotated[list, operator.add] fields are append-only — each node's
partial return is merged rather than replaced.
"""

import operator
from typing import Annotated, TypedDict


class SOCState(TypedDict):
    # Input
    alerts: list[dict]                                          # raw alert batch

    # Specialist outputs (append-only so parallel branches merge cleanly)
    triage_results: Annotated[list[dict], operator.add]         # Triage Officer
    enrichment_results: Annotated[list[dict], operator.add]     # Threat Hunter
    forensics_results: Annotated[list[dict], operator.add]      # Forensics Analyst
    recon_results: Annotated[list[dict], operator.add]          # Recon Specialist (Nettacker)

    # Oversight & reporting
    oversight_verdict: dict                                     # Oversight Officer output
    confidence: float                                           # 0-100 score
    briefing: str                                               # final report text

    # Re-investigation loop
    verification_alerts: Annotated[list[dict], operator.add]    # conflicts flagged
    iteration_count: int                                        # loop counter
