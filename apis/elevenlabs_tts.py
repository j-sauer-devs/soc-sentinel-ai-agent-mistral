"""
ElevenLabs Text-to-Speech API wrapper.

Converts the SOC Sentinel security briefing into a spoken audio briefing
for hands-free SOC operations during incident response.

Docs: https://elevenlabs.io/docs/api-reference
"""

import io
import os

# Default voice — "Rachel" (professional, clear, authoritative)
DEFAULT_VOICE_ID = "21m00Tcm4TlvDq8ikWAM"


def generate_briefing_audio(text: str, voice_id: str = None) -> bytes | None:
    """Generate TTS audio from a security briefing string.

    Returns MP3 bytes on success, None on failure.
    """
    api_key = os.getenv("ELEVENLABS_KEY", "")
    if not api_key:
        print("[ElevenLabs] ELEVENLABS_KEY not set — skipping voice briefing.")
        return None

    try:
        from elevenlabs import ElevenLabs

        client = ElevenLabs(api_key=api_key)

        # Use text_to_speech to generate audio
        audio_iterator = client.text_to_speech.convert(
            voice_id=voice_id or DEFAULT_VOICE_ID,
            text=text,
            model_id="eleven_turbo_v2_5",
            output_format="mp3_22050_32",
            voice_settings={
                "stability": 0.7,
                "similarity_boost": 0.8,
                "style": 0.2,
            },
        )

        # Collect all chunks into bytes
        audio_bytes = b""
        for chunk in audio_iterator:
            audio_bytes += chunk

        print(f"[ElevenLabs] Generated {len(audio_bytes)} bytes of audio.")
        return audio_bytes

    except ImportError:
        print("[ElevenLabs] elevenlabs package not installed. Run: pip install elevenlabs")
        return None
    except Exception as e:
        print(f"[ElevenLabs] TTS error: {e}")
        return None


def build_executive_summary(state: dict) -> str:
    """Build a concise ~150-word executive summary from pipeline state.

    Designed for ~1 minute of spoken audio at natural speech pace.
    Takes the structured state dict (not raw briefing text) so we can
    cherry-pick only the most critical findings.
    """
    verdict = state.get("oversight_verdict", {})
    confidence = state.get("confidence", 0.0)
    alerts = state.get("alerts", [])
    triage = state.get("triage_results", [])
    recon = state.get("recon_results", [])
    conflicts = verdict.get("conflicts", [])

    # --- Severity counts ---
    severities = [r.get("severity", "") for r in triage]
    sev_parts = []
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severities.count(sev)
        if count > 0:
            sev_parts.append(f"{count} {sev.lower()}")

    # --- Top conflicts (max 3, deduped by alert_id, prioritised) ---
    priority_order = ["SEVERITY_CONFLICT", "RECON_SEVERITY_MISMATCH",
                      "HALLUCINATED_CVE_IDS", "CORROBORATING_EVIDENCE"]
    sorted_conflicts = sorted(
        [c for c in conflicts if isinstance(c, dict)],
        key=lambda c: (
            priority_order.index(c.get("conflict_type", ""))
            if c.get("conflict_type", "") in priority_order else 99
        ),
    )
    # Deduplicate by alert_id — keep the highest priority conflict per alert
    seen_alerts = set()
    top_conflicts = []
    for c in sorted_conflicts:
        aid = c.get("alert_id", "")
        if aid not in seen_alerts:
            seen_alerts.add(aid)
            top_conflicts.append(c)
        if len(top_conflicts) >= 3:
            break

    # --- High-risk recon targets (score > 70) ---
    high_risk = [r for r in recon if r.get("attack_surface_score", 0) > 70]

    # --- APT indicators ---
    apt_indicators = verdict.get("apt_indicators", [])

    # --- Build the spoken script ---
    lines = ["SOC Sentinel security briefing."]

    lines.append(
        f"{len(alerts)} alerts processed. "
        f"Overall verdict: {verdict.get('verdict', 'unknown')}. "
        f"Confidence: {confidence:.0f} out of 100."
    )

    if sev_parts:
        lines.append(f"Severity breakdown: {', '.join(sev_parts)}.")

    if top_conflicts:
        lines.append(
            f"The Oversight Officer flagged {len(conflicts)} "
            f"verification conflict{'s' if len(conflicts) != 1 else ''}."
        )
        for c in top_conflicts:
            alert_id = c.get("alert_id", "unknown")
            ctype = c.get("conflict_type", "").replace("_", " ").lower()
            # Build a short description — take first sentence only
            desc = c.get("description", "")
            short_desc = desc.split(".")[0] if desc else ctype
            lines.append(f"Alert {alert_id}: {short_desc}.")

    if apt_indicators:
        # Expand APT for speech
        apt_text = ", ".join(str(a) for a in apt_indicators[:2])
        apt_text = apt_text.replace("APT", "A P T")
        apt_text = apt_text.replace("C2", "command and control")
        lines.append(f"Warning: {apt_text}.")

    if high_risk:
        lines.append(
            f"Reconnaissance identified {len(high_risk)} high-risk "
            f"target{'s' if len(high_risk) != 1 else ''} "
            f"with attack surface scores above 70."
        )

    # Assessment — use the verdict's reasoning summary (already concise)
    reasoning = verdict.get("reasoning_summary", "")
    if reasoning and reasoning != "N/A":
        # Expand abbreviations for speech
        reasoning = reasoning.replace("APT", "A P T")
        reasoning = reasoning.replace("C2", "command and control")
        reasoning = reasoning.replace("CVE-", "C V E ")
        lines.append(f"Assessment: {reasoning}")

    lines.append("End of briefing.")

    return "\n\n".join(lines)
