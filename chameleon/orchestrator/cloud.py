"""Provider-agnostic cloud chat interface: chat(provider, system, user, model).

Only Anthropic is wired up (deliberately not AWS Bedrock -- organizer
answer 3: AWS people are judges). Swapping providers is meant to be a
config change (config/routing.yaml's cloud_fallback.provider), not a code
change -- add a new function here and register it in PROVIDERS.
"""
from __future__ import annotations

import os


def _chat_anthropic(system: str, user: str, model: str) -> dict:
    import anthropic

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    resp = client.messages.create(
        model=model, max_tokens=1024, system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(block.text for block in resp.content if block.type == "text")
    return {"text": text, "in_tokens": resp.usage.input_tokens, "out_tokens": resp.usage.output_tokens}


PROVIDERS = {"anthropic": _chat_anthropic}


def chat(provider: str, system: str, user: str, model: str) -> dict:
    """Returns {"text": str, "in_tokens": int, "out_tokens": int}."""
    if provider not in PROVIDERS:
        raise ValueError(f"unknown cloud provider: {provider!r}")
    return PROVIDERS[provider](system, user, model)
