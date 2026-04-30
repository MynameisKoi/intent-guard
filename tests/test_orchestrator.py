from pathlib import Path

from engine.agents.ast_tracer import trace_dataflow
from engine.agents.ingestion import Workspace, ingest
from engine.agents.semantic import evaluate_intent
from engine.orchestrator import run_scan


def test_trace_dataflow_emits_warning_for_unsupported_extension(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    pyf = root / "ok.py"
    pyf.write_text("x = 1\n", encoding="utf-8")
    yml = root / "config.yaml"
    yml.write_text("a: 1\n", encoding="utf-8")
    ws = Workspace(root=root, target=str(root), files=[pyf, yml], agent_manifests=[], cleanup=False)
    events: list[dict] = []
    trace_dataflow(ws, on_event=events.append, scan_id="test-scan-id")
    warns = [e for e in events if e.get("type") == "trace_warning"]
    assert warns, "expected trace_warning for .yaml"
    assert any("config.yaml" in (w.get("message") or "") for w in warns)
    assert warns[0].get("scan_id") == "test-scan-id"


def test_ingest_local_sample_file():
    root = Path(__file__).resolve().parents[1]
    p = root / "demo" / "sample_skill.md"
    ws = ingest(str(p))
    assert ws.root.exists()
    assert ws.files, "Expected at least one file"


def test_ingest_agent_markdown_manifest_sample_skill():
    root = Path(__file__).resolve().parents[1]
    md = root / "demo" / "sample_skill.md"
    ws = ingest(str(md))
    assert ws.agent_manifests, "expected YAML frontmatter manifest"
    assert ws.agent_manifests[0].name == "doc_reader"
    topo, bundle, hints = trace_dataflow(ws)
    kinds = {n.kind for n in topo.nodes}
    assert "agent" in kinds
    assert "doc_reader" in bundle
    assert any(h.get("agent") == "doc_reader" for h in hints)


def test_agent_markdown_declared_tools_create_requests_tool_edges(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    skill = repo / "pentest.md"
    skill.write_text(
        "---\nname: pentest-bot\ntools:\n  - nmap\n  - sqlmap\n  - bash\nmodel: gpt-4\n---\n\nBe safe.\n",
        encoding="utf-8",
    )
    ws = ingest(str(repo))
    topo, _, _ = trace_dataflow(ws)
    assert any(e.kind == "REQUESTS_TOOL" for e in topo.edges)
    tool_nodes = [n for n in topo.nodes if n.kind == "tool"]
    assert len(tool_nodes) >= 3


def test_plain_markdown_builds_intent_graph_without_frontmatter(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    doc = repo / "mission.md"
    doc.write_text(
        "# Talon Operator\n\n"
        "## Objectives\n"
        "- Enumerate exposed services with nmap\n"
        "- Use bash to collect evidence\n"
        "- Request filesystem:read and environment:read permissions\n",
        encoding="utf-8",
    )
    ws = ingest(str(repo))
    topo, bundle, hints = trace_dataflow(ws)
    kinds = {n.kind for n in topo.nodes}
    assert "agent" in kinds
    assert "prompt" in kinds
    assert "task" in kinds
    assert "tool" in kinds
    assert "permission" in kinds
    assert any(e.kind == "DESCRIBES_TASK" for e in topo.edges)
    assert any(e.kind == "DECLARES_TOOL" for e in topo.edges)
    assert "Talon Operator" in bundle
    assert any(h.get("tasks") for h in hints if h.get("file") == "mission.md")


def test_trace_dataflow_builds_topology():
    root = Path(__file__).resolve().parents[1]
    p = root / "demo" / "samples" / "log_collector.py"
    ws = ingest(str(p))
    topo, bundle, hints = trace_dataflow(ws)
    assert topo.nodes
    assert bundle


def test_heuristic_semantic():
    text = "import requests\nrequests.post('https://x.example.com')\nsubprocess.run('x', shell=True)"
    r = evaluate_intent(text, [])
    assert r.risk_score >= 4
    assert r.findings


def test_run_scan_demo_sample(tmp_path):
    root = Path(__file__).resolve().parents[1]
    target = str(root / "demo" / "sample_skill.md")
    rec = run_scan(target)
    assert rec.status == "completed"
    assert rec.scan_id
    assert rec.report is not None
    assert rec.topology is not None
