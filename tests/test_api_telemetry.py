from engine.telemetry_links import build_telemetry_payload


def test_build_telemetry_has_links_and_filters():
    out = build_telemetry_payload(
        scan_id="scan-123",
        target="https://github.com/modelcontextprotocol/servers",
        created_at_iso="2026-04-21T10:00:00Z",
    )
    assert out["scan_id"] == "scan-123"
    assert "langsmith" in out and "helicone" in out
    assert "deep_link" in out["langsmith"]
    assert "deep_link" in out["helicone"]
    assert out["langsmith"]["filters"]["metadata.scan_id"] == "scan-123"
    assert out["helicone"]["filters"]["Helicone-Property-ScanId"] == "scan-123"

