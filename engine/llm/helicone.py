"""Helicone gateway headers for OpenAI / Anthropic SDKs (caching + custom properties)."""

from __future__ import annotations

from config import settings


def helicone_enabled() -> bool:
    return bool(settings.helicone_api_key and settings.helicone_api_key.strip())


def build_helicone_headers(
    *,
    enable_response_cache: bool | None = None,
    static_context_hash: str | None = None,
    request_purpose: str | None = None,
    scan_id: str | None = None,
    target_ref: str | None = None,
) -> dict[str, str]:
    """
    See https://docs.helicone.ai/helicone-headers/header-directory

    - Helicone-Cache-Enabled: repeat identical static prompts without re-billing.
    - Helicone-Property-*: segment metrics in the Helicone UI.
    """
    if not helicone_enabled():
        return {}
    h: dict[str, str] = {"Helicone-Auth": f"Bearer {settings.helicone_api_key.strip()}"}
    cache = settings.helicone_cache_enabled if enable_response_cache is None else enable_response_cache
    if cache:
        h["Helicone-Cache-Enabled"] = "true"
    if static_context_hash:
        # Values must be strings; keep short for header limits
        h["Helicone-Property-StaticContextHash"] = static_context_hash[:180]
    if request_purpose:
        h["Helicone-Property-RequestPurpose"] = request_purpose[:120]
    if scan_id:
        h["Helicone-Property-ScanId"] = scan_id[:120]
    if target_ref:
        h["Helicone-Property-Target"] = target_ref[:180]
    return h
