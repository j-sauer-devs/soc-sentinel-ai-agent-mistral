"""
SOC Sentinel — End-to-end pipeline test.

Runs the full LangGraph pipeline with demo data and DEMO_MODE=True
for Nettacker, then asserts key behaviours:
  1. Oversight Officer catches the APT29 misclassification
  2. Recon Specialist returns results for all alert IPs
  3. Confidence score is reasonable
  4. Final briefing contains a Recon section

Usage:
    DEMO_MODE=true python3 -m pytest tests/test_full_pipeline.py -v
    # or simply:
    python3 tests/test_full_pipeline.py
"""

import os
import sys
import time

# Ensure DEMO_MODE is on for tests
os.environ["DEMO_MODE"] = "true"

from dotenv import load_dotenv
load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo.demo_data import DEMO_ALERTS
from graph.graph import app
from graph.state import SOCState


def run_pipeline():
    """Run the full pipeline and return final state + timing."""
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

    start = time.time()
    final_state = app.invoke(initial_state)
    elapsed = time.time() - start

    return final_state, elapsed


def test_pipeline():
    """Run all assertions on the pipeline output."""
    print("Running full pipeline test...")
    final_state, elapsed = run_pipeline()
    print(f"Pipeline completed in {elapsed:.1f}s")

    # 1. Check we got results from all agents
    assert len(final_state["triage_results"]) > 0, "No triage results"
    assert len(final_state["enrichment_results"]) > 0, "No enrichment results"
    assert len(final_state["forensics_results"]) > 0, "No forensics results"
    assert len(final_state["recon_results"]) > 0, "No recon results"
    print("  [PASS] All agents produced results")

    # 2. Check Recon Specialist returned results for all alert IPs
    recon_targets = {r["target"] for r in final_state["recon_results"]}
    alert_ips = {a["source_ip"] for a in DEMO_ALERTS}
    assert recon_targets == alert_ips, (
        f"Recon missed IPs: {alert_ips - recon_targets}"
    )
    print(f"  [PASS] Recon covered all {len(alert_ips)} unique IPs")

    # 3. Check Oversight Officer produced a verdict
    verdict = final_state["oversight_verdict"]
    assert verdict.get("verdict") in ("THREAT", "SUSPICIOUS", "CLEAN"), (
        f"Invalid verdict: {verdict.get('verdict')}"
    )
    print(f"  [PASS] Oversight verdict: {verdict['verdict']}")

    # 4. Check confidence score is reasonable
    confidence = final_state["confidence"]
    assert 0 <= confidence <= 100, f"Confidence out of range: {confidence}"
    assert confidence != 0, "Confidence is exactly 0 — likely an error"
    print(f"  [PASS] Confidence score: {confidence:.1f}/100")

    # 5. Check that the APT29 alert (ALERT-001) was flagged
    conflicts = verdict.get("conflicts", [])
    alert_001_conflicts = [
        c for c in conflicts
        if isinstance(c, dict) and c.get("alert_id") == "ALERT-001"
    ]
    assert len(alert_001_conflicts) > 0, (
        "Oversight did not catch ALERT-001 (APT29 misclassification)"
    )
    conflict_types = [c.get("conflict_type") for c in alert_001_conflicts]
    print(f"  [PASS] ALERT-001 conflicts caught: {conflict_types}")

    # 6. Check briefing contains recon section
    briefing = final_state["briefing"]
    assert "Nettacker" in briefing or "Reconnaissance" in briefing, (
        "Briefing missing Nettacker/Reconnaissance section"
    )
    print("  [PASS] Briefing includes recon findings")

    # 7. Check severity override
    sev_override = verdict.get("severity_override")
    if sev_override:
        print(f"  [PASS] Severity override: {sev_override}")
    else:
        print("  [WARN] No severity override (may be OK depending on LLM output)")

    # 8. Timing check
    if elapsed < 120:
        print(f"  [PASS] Pipeline completed in {elapsed:.1f}s (target: < 120s)")
    else:
        print(f"  [WARN] Pipeline took {elapsed:.1f}s (target: < 120s)")

    print(f"\n{'=' * 50}")
    print(f"  ALL TESTS PASSED")
    print(f"  Pipeline time: {elapsed:.1f}s")
    print(f"  Alerts: {len(DEMO_ALERTS)}, Recon targets: {len(recon_targets)}")
    print(f"  Verdict: {verdict['verdict']}, Confidence: {confidence:.1f}")
    print(f"  Conflicts: {len(conflicts)}")
    print(f"{'=' * 50}")

    return final_state


if __name__ == "__main__":
    test_pipeline()
