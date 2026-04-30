"""Deep-link payloads for LangSmith and Helicone (shared by API + live scan SSE)."""

from __future__ import annotations

import json
from urllib.parse import quote_plus

from config import settings


def build_telemetry_payload(*, scan_id: str, target: str, created_at_iso: str | None = None) -> dict:
    project = settings.langchain_project
    ls_base = settings.langsmith_base_url.rstrip("/")
    hc_base = settings.helicone_app_url.rstrip("/")

    ls_query = quote_plus(json.dumps({"metadata.scan_id": scan_id}))
    ls_project = quote_plus(project)
    langsmith_url = f"{ls_base}/projects/p/{ls_project}?peek={ls_query}"

    hc_scan = quote_plus(scan_id)
    hc_target = quote_plus(target[:180]) if target else ""
    helicone_url = f"{hc_base}/requests?property=ScanId&value={hc_scan}"
    if hc_target:
        helicone_url += f"&target={hc_target}"

    return {
        "scan_id": scan_id,
        "created_at": created_at_iso,
        "langsmith": {
            "enabled": bool(settings.langchain_tracing_v2 and settings.langchain_api_key),
            "project": project,
            "deep_link": langsmith_url,
            "filters": {"metadata.scan_id": scan_id},
        },
        "helicone": {
            "enabled": bool(settings.helicone_api_key),
            "deep_link": helicone_url,
            "filters": {
                "Helicone-Property-ScanId": scan_id,
                "Helicone-Property-Target": target[:180] if target else "",
            },
        },
    }
