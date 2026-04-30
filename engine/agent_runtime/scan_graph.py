"""
LangGraph scan pipeline: static semantic pass (cache-friendly) then optional dynamic log merge.

Traced via LangSmith when LANGCHAIN_TRACING_V2 + LANGCHAIN_API_KEY are set.
LLM traffic can be proxied through Helicone (see engine.llm.helicone).
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from config import get_settings
from engine.agent_runtime.langchain_llm import build_langchain_chat_model

logger = logging.getLogger(__name__)


class ScanGraphState(TypedDict, total=False):
    system_prompt: str
    static_user_text: str
    dynamic_logs: str | None
    scan_id: str | None
    target_ref: str | None
    static_context_hash: str
    static_raw: str
    final_raw: str
    force_rescan: bool


def _static_hash(static_user_text: str) -> str:
    return hashlib.sha256(static_user_text.encode("utf-8", errors="replace")).hexdigest()


def _node_static(state: ScanGraphState) -> dict[str, Any]:
    h = state.get("static_context_hash") or _static_hash(state["static_user_text"])
    llm = build_langchain_chat_model(
        purpose="static",
        static_context_hash=h,
        scan_id=state.get("scan_id"),
        target_ref=state.get("target_ref"),
        no_cache=bool(state.get("force_rescan")),
    )
    out = llm.invoke(
        [
            SystemMessage(content=state["system_prompt"]),
            HumanMessage(content=state["static_user_text"]),
        ],
        config={
            "run_name": "intentguard_static_semantic",
            "tags": ["intentguard", "semantic", "static"],
            "metadata": {
                "scan_id": state.get("scan_id"),
                "target_ref": state.get("target_ref"),
                "static_context_hash": h,
            },
        },
    )
    content = getattr(out, "content", None) or ""
    if isinstance(content, list):
        content = "".join(str(c) for c in content)
    return {"static_raw": str(content).strip(), "static_context_hash": h}


def _node_dynamic(state: ScanGraphState) -> dict[str, Any]:
    logs = (state.get("dynamic_logs") or "").strip()
    if not logs:
        return {"final_raw": state.get("static_raw", "")}

    llm = build_langchain_chat_model(
        purpose="dynamic",
        static_context_hash=None,
        scan_id=state.get("scan_id"),
        target_ref=state.get("target_ref"),
        no_cache=bool(state.get("force_rescan")),
    )
    merge_prompt = (
        "You previously produced this JSON static security analysis.\n"
        "Now evaluate the RUNTIME LOGS and merge any new risks.\n"
        "Return a single JSON object using the SAME schema as before "
        "(intent_summary, risk_score, risk_label, permissions_inferred, network_targets, "
        "shell_execution, findings, category_scores, annotated_code).\n\n"
        f"STATIC_JSON:\n{state.get('static_raw', '')}\n\n"
        f"RUNTIME_LOGS:\n{logs}\n"
    )
    out = llm.invoke(
        [
            SystemMessage(content=state["system_prompt"]),
            HumanMessage(content=merge_prompt),
        ],
        config={
            "run_name": "intentguard_dynamic_semantic",
            "tags": ["intentguard", "semantic", "dynamic"],
            "metadata": {
                "scan_id": state.get("scan_id"),
                "target_ref": state.get("target_ref"),
            },
        },
    )
    content = getattr(out, "content", None) or ""
    if isinstance(content, list):
        content = "".join(str(c) for c in content)
    return {"final_raw": str(content).strip()}


def build_scan_graph():
    g = StateGraph(ScanGraphState)
    g.add_node("static", _node_static)
    g.add_node("dynamic", _node_dynamic)
    g.add_edge(START, "static")
    g.add_edge("static", "dynamic")
    g.add_edge("dynamic", END)
    return g.compile()


_compiled = None


def get_scan_graph():
    global _compiled
    if _compiled is None:
        _compiled = build_scan_graph()
    return _compiled


def run_semantic_scan_graph(
    *,
    system_prompt: str,
    static_user_text: str,
    dynamic_logs: str | None,
    scan_id: str | None,
    target_ref: str | None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    force_rescan: bool = False,
) -> str | None:
    """
    Returns raw model text (JSON). None if LangGraph runtime is disabled or graph fails.
    """
    s = get_settings()
    if not s.use_langgraph_runtime:
        if on_event:
            on_event(
                {
                    "type": "llm_step",
                    "step": "langgraph",
                    "phase": "skipped",
                    "reason": "USE_LANGGRAPH_RUNTIME is false",
                    "scan_id": scan_id,
                }
            )
        return None
    try:
        state: ScanGraphState = {
            "system_prompt": system_prompt,
            "static_user_text": static_user_text,
            "dynamic_logs": dynamic_logs,
            "scan_id": scan_id,
            "target_ref": target_ref,
            "force_rescan": force_rescan,
        }
        if on_event:
            on_event(
                {
                    "type": "llm_step",
                    "step": "langgraph_static",
                    "phase": "start",
                    "scan_id": scan_id,
                    "target_ref": target_ref,
                    "note": "Static semantic pass (Helicone cache-friendly when enabled)",
                }
            )
        state.update(_node_static(state))
        if on_event:
            on_event(
                {
                    "type": "llm_step",
                    "step": "langgraph_static",
                    "phase": "complete",
                    "scan_id": scan_id,
                    "static_context_hash": state.get("static_context_hash"),
                }
            )
        if on_event:
            on_event(
                {
                    "type": "llm_step",
                    "step": "langgraph_dynamic",
                    "phase": "start",
                    "scan_id": scan_id,
                    "has_runtime_logs": bool((dynamic_logs or "").strip()),
                }
            )
        state.update(_node_dynamic(state))
        if on_event:
            on_event(
                {
                    "type": "llm_step",
                    "step": "langgraph_dynamic",
                    "phase": "complete",
                    "scan_id": scan_id,
                }
            )
        raw = (state.get("final_raw") or state.get("static_raw") or "").strip()
        return raw or None
    except Exception as e:
        logger.warning("LangGraph semantic pipeline failed: %s", e)
        return None
