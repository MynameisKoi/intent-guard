from openai import OpenAI

from config import settings
from engine.llm.base import LLMClient
from engine.llm.helicone import build_helicone_headers, helicone_enabled


class OpenAILLM(LLMClient):
    def __init__(self) -> None:
        key = settings.openai_api_key
        if not key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._model = settings.llm_model or "gpt-4o"
        kwargs: dict = {"api_key": key}
        if helicone_enabled():
            kwargs["base_url"] = settings.openai_helicone_base_url
            kwargs["default_headers"] = build_helicone_headers(
                enable_response_cache=settings.helicone_cache_enabled,
                request_purpose="direct_sdk",
            )
        self._client = OpenAI(**kwargs)

    def complete(self, *, system: str, user: str, no_cache: bool = False) -> str:
        extra_headers = {"Helicone-Cache-Enabled": "false"} if no_cache else None
        r = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.0,
            top_p=0.1,
            extra_headers=extra_headers,
        )
        return (r.choices[0].message.content or "").strip()
