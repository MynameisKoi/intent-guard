"""LangSmith / LangChain tracing (set standard LANGCHAIN_* env vars)."""

from __future__ import annotations

import logging
import os

from config import settings

logger = logging.getLogger(__name__)
_configured = False


def configure_runtime_observability() -> None:
    """
    Enable LangSmith tracing for LangChain + LangGraph runs.

    Set in .env:
      LANGCHAIN_TRACING_V2=true
      LANGCHAIN_API_KEY=...
      LANGCHAIN_PROJECT=intent-guard   (optional; defaults from config)
    """
    global _configured
    if _configured:
        return
    _configured = True

    if settings.langchain_api_key:
        os.environ.setdefault("LANGCHAIN_API_KEY", settings.langchain_api_key)
    if settings.langchain_tracing_v2:
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
    if settings.langchain_project:
        os.environ.setdefault("LANGCHAIN_PROJECT", settings.langchain_project)

    if settings.langchain_tracing_v2 and settings.langchain_api_key:
        logger.info("LangSmith tracing enabled (project=%s)", settings.langchain_project)
    elif settings.langchain_tracing_v2 and not settings.langchain_api_key:
        logger.warning("LANGCHAIN_TRACING_V2 is true but LANGCHAIN_API_KEY is missing — traces will not upload.")
