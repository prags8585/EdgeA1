"""OpenAI-compatible client for Nano-hosted (or cloud) LLMs, with a call log.

Every model call -- Nano or cloud -- goes through timed_call(), which times
it, logs it to llm_calls, and returns just the response text. Nano calls are
free; cloud calls (used only by the orchestrator, later) get a real cost
computed from config.CLOUD_PRICE_*.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from . import config, db


def _extract_text(response: dict) -> str:
    return response["choices"][0]["message"]["content"] or ""


def timed_call(
    *,
    role: str,
    model: str,
    messages: list[dict[str, str]],
    conn=None,
    session_id: str | None = None,
    run_id: str | None = None,
    provider: str = "nano",
    base_url: str | None = None,
    api_key: str | None = None,
    placement_reason: str | None = None,
    response_format: dict | None = None,
    timeout: float = 120.0,
    uds: str | None = None,
    **extra: Any,
) -> str:
    """uds: talk to a vLLM backend's Unix socket directly instead of the ZRT
    proxy. Needed for LoRA adapters -- the proxy routes only by the service's
    own label and returns 'unknown model name' for adapters served inside it."""
    if uds:
        base_url = "http://localhost/v1"
    url = (base_url or config.ZRT_PROXY_URL).rstrip("/") + "/chat/completions"
    config.assert_local(url, allow_cloud=(provider == "cloud"))

    payload: dict[str, Any] = {"model": model, "messages": messages, **extra}
    if response_format is not None:
        payload["response_format"] = response_format

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    start = time.perf_counter()
    ok, error, text, usage = True, None, "", {}
    try:
        transport = httpx.HTTPTransport(uds=uds) if uds else None
        with httpx.Client(transport=transport, timeout=timeout) as client:
            resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        text = _extract_text(data)
        usage = data.get("usage") or {}
        return text
    except Exception as exc:  # noqa: BLE001 - logged below, then re-raised
        ok, error = False, str(exc)
        raise
    finally:
        latency_ms = (time.perf_counter() - start) * 1000
        in_tokens = usage.get("prompt_tokens", 0)
        out_tokens = usage.get("completion_tokens", 0)
        est_cost_usd = 0.0
        if provider == "cloud":
            est_cost_usd = (
                (in_tokens / 1000) * config.CLOUD_PRICE_IN_PER_1K
                + (out_tokens / 1000) * config.CLOUD_PRICE_OUT_PER_1K
            )

        owns_conn = conn is None
        conn = conn or db.get_connection()
        try:
            db.init_db(conn)
            db.log_llm_call(
                conn,
                provider=provider,
                model=model,
                role=role,
                latency_ms=latency_ms,
                in_tokens=in_tokens,
                out_tokens=out_tokens,
                est_cost_usd=est_cost_usd,
                ok=ok,
                error=error,
                session_id=session_id,
                run_id=run_id,
                placement_reason=placement_reason,
            )
        finally:
            if owns_conn:
                conn.close()

        # Comparison mode: replay the same prompt on the same model on AWS, in the
        # background. Only the Qwen writer has a Bedrock twin (the Gemma verifier
        # doesn't), and a measurement must never break the product path.
        if ok and provider == "nano" and model == config.WRITER_MODEL_NAME and not uds:
            try:
                from . import cloud_mirror

                end_wall = time.time()
                cloud_mirror.mirror(
                    role=role, messages=messages, nano_latency_ms=latency_ms,
                    nano_in_tokens=in_tokens, nano_out_tokens=out_tokens,
                    started=end_wall - latency_ms / 1000, finished=end_wall,
                    max_tokens=extra.get("max_tokens"), temperature=extra.get("temperature"),
                )
            except Exception:  # noqa: BLE001 - see comment above; logged, never raised
                logging.getLogger(__name__).exception("AWS comparison mirror failed")
