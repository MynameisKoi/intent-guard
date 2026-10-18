"""LangChain chat models routed through Helicone when HELICONE_API_KEY is set."""

from __future__ import annotations

import logging
from typing import Any, Literal

from config import get_settings
from engine.llm.helicone import build_helicone_headers, helicone_enabled

logger = logging.getLogger(__name__)

Purpose = Literal["static", "dynamic"]


def build_langchain_chat_model(
    *,
    purpose: Purpose,
    static_context_hash: str | None = None,
    scan_id: str | None = None,
    target_ref: str | None = None,
    no_cache: bool = False,
):
    """
    Returns a LangChain BaseChatModel for the active LLM_PROVIDER.

    Helicone:
    - OpenAI: base_url https://oai.helicone.ai/v1 + Helicone-Auth
    - Anthropic: anthropic_api_url https://anthropic.helicone.ai + Helicone-Auth

    Caching: enabled for `purpose="static"` (repeatable codebase analysis);
    disabled for `purpose="dynamic"` so log batches are always evaluated fresh.
    """
    s = get_settings()
    provider = (s.llm_provider or "openai").lower().strip()
    enable_cache = (purpose == "static" and s.helicone_cache_enabled) and not no_cache
    headers = build_helicone_headers(
        enable_response_cache=enable_cache,
        static_context_hash=static_context_hash if purpose == "static" else None,
        request_purpose=purpose,
        scan_id=scan_id,
        target_ref=target_ref,
    )
    if no_cache:
        # Helicone explicitly respects this header for cache bypass.
        headers["Helicone-Cache-Enabled"] = "false"

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        if not s.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        model = s.llm_model or "gpt-4o-mini"
        kwargs: dict[str, Any] = {
            "model": model,
            "api_key": s.openai_api_key,
            "temperature": 0.0,
            "top_p": 0.1,
        }
        if helicone_enabled():
            kwargs["base_url"] = s.openai_helicone_base_url
            kwargs["default_headers"] = headers
        return ChatOpenAI(**kwargs)

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        if not s.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        model = s.llm_model or "claude-sonnet-4-20250514"
        kwargs = {
            "model": model,
            "api_key": s.anthropic_api_key,
            "temperature": 0.0,
            # A full report (findings + annotated_code + workflow) overruns 4096 and
            # arrives truncated, costing whichever field the contract lists last.
            "max_tokens": 8192,
        }
        if helicone_enabled():
            kwargs["anthropic_api_url"] = s.anthropic_helicone_base_url
            kwargs["default_headers"] = headers
        return ChatAnthropic(**kwargs)

    if provider == "openrouter":
        from langchain_openai import ChatOpenAI

        from engine.llm.openrouter_client import openrouter_connection, openrouter_model

        conn = openrouter_connection(headers)
        return ChatOpenAI(
            model=openrouter_model(),
            api_key=conn["api_key"],
            base_url=conn["base_url"],
            default_headers=conn["default_headers"],
            temperature=0.0,
            # OpenRouter applies a small per-model default otherwise, truncating the report.
            max_tokens=int(s.llm_max_tokens),
        )

    raise RuntimeError(f"Unsupported LLM_PROVIDER for LangGraph runtime: {provider}")
