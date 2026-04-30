"""Smoke test for POST /api/scans/stream (SSE)."""

from pathlib import Path

from api.app import create_app


def test_scan_stream_returns_sse_and_scan_started():
    root = Path(__file__).resolve().parents[1]
    target = str(root / "demo" / "sample_skill.md")
    app = create_app()
    client = app.test_client()
    resp = client.post(
        "/api/scans/stream",
        json={"target": target},
        headers={"Accept": "text/event-stream"},
    )
    assert resp.status_code == 200
    assert "event-stream" in (resp.headers.get("Content-Type") or "").lower()
    body = resp.get_data(as_text=True)
    assert "data:" in body
    assert "scan_started" in body
