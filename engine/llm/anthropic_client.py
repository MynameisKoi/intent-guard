import json

import anthropic

from config import settings
from engine.llm.base import LLMClient
from engine.llm.helicone import build_helicone_headers, helicone_enabled


class AnthropicLLM(LLMClient):
    def __init__(self) -> None:
        key = settings.anthropic_api_key
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._model = settings.llm_model or "claude-sonnet-4-20250514"
        kwargs: dict = {"api_key": key}
        if helicone_enabled():
            kwargs["base_url"] = settings.anthropic_helicone_base_url
            kwargs["default_headers"] = build_helicone_headers(
                enable_response_cache=settings.helicone_cache_enabled,
                request_purpose="direct_sdk",
            )
        self._client = anthropic.Anthropic(**kwargs)

    def complete(self, *, system: str, user: str, no_cache: bool = False) -> str:
        extra_headers = {"Helicone-Cache-Enabled": "false"} if no_cache else None
        report_tool = {
            "name": "intent_report",
            "description": "Structured semantic security analysis JSON.",
            "input_schema": {
                "type": "object",
                "required": [
                    "intent_summary",
                    "risk_score",
                    "risk_label",
                    "permissions_inferred",
                    "network_targets",
                    "shell_execution",
                    "owasp_llm_top10",
                    "findings",
                    "category_scores",
                    "annotated_code",
                ],
                "properties": {
                    "intent_summary": {"type": "string"},
                    "risk_score": {"type": "number"},
                    "risk_label": {"type": "string"},
                    "permissions_inferred": {"type": "array", "items": {"type": "string"}},
                    "network_targets": {"type": "array", "items": {"type": "string"}},
                    "shell_execution": {"type": "boolean"},
                    "owasp_llm_top10": {
                        "type": "object",
                        "required": [f"LLM{i:02d}" for i in range(1, 11)],
                        "properties": {f"LLM{i:02d}": {"type": "boolean"} for i in range(1, 11)},
                    },
                    "findings": {"type": "array", "items": {"type": "object"}},
                    "category_scores": {"type": "array", "items": {"type": "object"}},
                    "annotated_code": {"type": "array", "items": {"type": "object"}},
                },
                "additionalProperties": True,
            },
        }
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            temperature=0.0,
            system=system,
            messages=[{"role": "user", "content": user}],
            tools=[report_tool],
            tool_choice={"type": "tool", "name": "intent_report"},
            extra_headers=extra_headers,
        )
        for b in msg.content:
            if b.type == "tool_use" and getattr(b, "input", None):
                return json.dumps(b.input, ensure_ascii=False)
        parts: list[str] = []
        for b in msg.content:
            if b.type == "text":
                parts.append(b.text)
        return "\n".join(parts).strip()
