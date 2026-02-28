"""
Shared utilities for the SOC Sentinel agent graph.

Import this module wherever you need to parse LLM responses:
    from graph.utils import extract_reasoning
"""

import re


def extract_reasoning(content: str) -> tuple[str, str]:
    """
    Handles reasoning tag formats that some models produce:
    - Standard:  <think>...</think>
    - Observed:  ...reasoning...</think>  (no opening tag)

    Falls back to returning the full content as the answer if no
    reasoning tags are found (Mistral does not produce <think> tags).

    Returns:
        (reasoning, final_answer)
        reasoning    — the model's internal chain-of-thought (empty string if none)
        final_answer — the response text shown to the user
    """
    # Try standard format first
    think_match = re.search(r'<think>(.*?)</think>', content, re.DOTALL)
    if think_match:
        reasoning = think_match.group(1).strip()
        answer = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
        return reasoning, answer

    # Fallback: split on closing tag only (observed in some models' streaming)
    if '</think>' in content:
        parts = content.split('</think>', 1)
        reasoning = parts[0].strip()
        answer = parts[1].strip()
        return reasoning, answer

    # No reasoning tags at all — Mistral typically returns clean JSON
    return "", content.strip()
