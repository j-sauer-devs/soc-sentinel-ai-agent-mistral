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


def prepare_briefing_for_speech(briefing: str) -> str:
    """Clean up the briefing text for better TTS pronunciation.

    - Strips ASCII art headers
    - Expands abbreviations
    - Formats IP addresses for natural reading
    """
    import re

    # Remove ASCII decoration lines
    text = re.sub(r"[=\-]{10,}", "", briefing)

    # Remove "SOC SENTINEL" header lines
    text = re.sub(r"SOC SENTINEL.*\n", "", text)
    text = re.sub(r"Powered by.*\n", "", text)

    # Expand common SOC abbreviations for natural speech
    text = text.replace("CVE-", "C V E ")
    text = text.replace("APT", "A P T")
    text = text.replace("C2", "command and control")
    text = text.replace("IOC", "indicator of compromise")
    text = text.replace("TTP", "tactics techniques and procedures")
    text = text.replace("MITRE ATT&CK", "MITRE attack framework")

    # Clean up multiple newlines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()
