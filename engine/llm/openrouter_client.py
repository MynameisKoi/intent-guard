"""OpenRouter — an OpenAI-compatible gateway, so the OpenAI SDK talks to it directly."""

from __future__ import annotations

from openai import OpenAI

from config import get_settings
from engine.llm.base import LLMClient
from engine.llm.helicone import build_helicone_headers, helicone_enabled


def openrouter_model() -> str:
    s = get_settings()
    return s.llm_model or s.openrouter_default_model


def openrouter_connection(helicone_headers: dict[str, str] | None = None) -> dict:
    """
    Base URL, key and headers shared by the direct SDK client and the LangChain model.

    `HTTP-Referer` / `X-Title` are OpenRouter's app-attribution headers. When Helicone
    is configured it fronts OpenRouter through its dedicated gateway, so the caller's
    Helicone headers (cache policy, scan properties) ride along.
    """
    s = get_settings()
    if not s.openrouter_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    headers = {"HTTP-Referer": s.openrouter_site_url, "X-Title": s.openrouter_app_name}
    base_url = s.openrouter_base_url
    if helicone_enabled():
        base_url = s.openrouter_helicone_base_url
        headers.update(helicone_headers or {})
    return {"api_key": s.openrouter_api_key, "base_url": base_url, "default_headers": headers}


class OpenRouterLLM(LLMClient):
    def __init__(self) -> None:
        s = get_settings()
        conn = openrouter_connection(
            build_helicone_headers(
                enable_response_cache=s.helicone_cache_enabled,
                request_purpose="direct_sdk",
            )
        )
        self._model = openrouter_model()
        self._max_tokens = int(s.llm_max_tokens)
        self._client = OpenAI(**conn)

    def complete(self, *, system: str, user: str, no_cache: bool = False) -> str:
        extra_headers = {"Helicone-Cache-Enabled": "false"} if no_cache else None
        r = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.0,
            max_tokens=self._max_tokens,
            extra_headers=extra_headers,
        )
        if not r.choices:
            raise RuntimeError(f"OpenRouter returned no choices for model {self._model}")
        return (r.choices[0].message.content or "").strip()
