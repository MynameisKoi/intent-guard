"""Smoke test for POST /api/scans/stream (SSE)."""

import io
from pathlib import Path

from api.app import create_app


def test_scan_stream_returns_sse_and_scan_started():
    """Local paths are CLI-only, so the streaming endpoint is exercised via upload."""
    root = Path(__file__).resolve().parents[1]
    skill = (root / "demo" / "sample_skill.md").read_bytes()
    app = create_app()
    client = app.test_client()
    resp = client.post(
        "/api/scans/stream",
        data={"files": (io.BytesIO(skill), "sample_skill.md")},
        content_type="multipart/form-data",
        headers={"Accept": "text/event-stream"},
    )
    assert resp.status_code == 200
    assert "event-stream" in (resp.headers.get("Content-Type") or "").lower()
    body = resp.get_data(as_text=True)
    assert "data:" in body
    assert "scan_started" in body
