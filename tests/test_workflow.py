"""The workflow graph must describe behaviour, never name code symbols."""

import re

import pytest

from engine.agents.workflow import derive_workflow, humanize_label, parse_workflow
from schemas.graph_nodes import GraphNode, TopologyPayload
from schemas.report_schema import NutritionLabel

_SYMBOL_RE = re.compile(r"\(\)|\.py\b|\b[a-z]+_[a-z_]+\b|\b[a-z]+\.[a-z]+\(")


def _report(**kwargs) -> NutritionLabel:
    base = {"intent_summary": "s", "risk_score": 5.0, "risk_label": "Medium"}
    return NutritionLabel(**{**base, **kwargs})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("run_sandbox_smoke", "Run sandbox smoke"),
        ("engine/agents/ast_tracer.py", "Ast tracer"),
        ("evaluate_intent()", "Evaluate intent"),
        ("Send data to an external endpoint", "Send data to an external endpoint"),
    ],
)
def test_humanize_label_strips_symbol_shapes(raw, expected):
    assert humanize_label(raw) == expected


def test_parse_workflow_reads_model_output():
    workflow = parse_workflow(
        {
            "summary": "Collects files and sends them to a remote service.",
            "steps": [
                {"id": "s1", "label": "Receive a repository to review", "role": "input", "sensitive": True},
                {"id": "s2", "label": "Read the files in the repository", "role": "process"},
                {"id": "s3", "label": "Send the code to an external AI service", "role": "output"},
            ],
            "transitions": [
                {"source": "s1", "target": "s2", "label": "repository"},
                {"source": "s2", "target": "s3", "label": "file contents"},
            ],
        }
    )

    assert workflow is not None
    assert workflow.source == "llm"
    assert [s.role for s in workflow.steps] == ["input", "process", "output"]
    assert workflow.steps[0].sensitive
    assert len(workflow.transitions) == 2


def test_parse_workflow_rejects_unusable_payloads():
    assert parse_workflow(None) is None
    assert parse_workflow({"steps": []}) is None
    assert parse_workflow({"summary": "no steps"}) is None


def test_parse_workflow_drops_dangling_transitions_and_bad_roles():
    workflow = parse_workflow(
        {
            "steps": [
                {"id": "s1", "label": "Accept a request", "role": "banana"},
                {"id": "s2", "label": "Answer the request"},
            ],
            "transitions": [
                {"source": "s1", "target": "s2"},
                {"source": "s2", "target": "ghost"},
                {"source": "s1", "target": "s1"},
            ],
        }
    )

    assert workflow.steps[0].role == "process", "unknown roles fall back rather than raising"
    assert [(t.source, t.target) for t in workflow.transitions] == [("s1", "s2")]


def test_parse_workflow_chains_steps_when_transitions_are_missing():
    workflow = parse_workflow(
        {"steps": [{"id": "a", "label": "First stage"}, {"id": "b", "label": "Second stage"}]}
    )
    assert [(t.source, t.target) for t in workflow.transitions] == [("a", "b")]


def test_derived_workflow_reads_as_a_story():
    topology = TopologyPayload(
        nodes=[
            GraphNode(id="n1", label="Environment", kind="source", meta={"source_key": "environment"}),
            GraphNode(id="n2", label="stdin", kind="source", meta={"source_key": "stdin"}),
            GraphNode(id="n3", label="subprocess/shell", kind="external", meta={"family": "shell"}),
            GraphNode(id="n4", label="HTTP", kind="external", meta={"family": "network"}),
            GraphNode(id="n5", label="bash", kind="tool"),
            GraphNode(id="n6", label="Log Collector", kind="agent"),
        ],
        edges=[],
    )
    workflow = derive_workflow(topology, _report(shell_execution=True))

    labels = [s.label for s in workflow.steps]
    assert "Read configuration and secrets from the environment" in labels
    assert "Accept input typed by the user" in labels
    assert "Run shell commands on the host" in labels
    assert "Send data to an external network endpoint" in labels
    assert workflow.source == "derived"

    inputs = [s.id for s in workflow.steps if s.role == "input"]
    assert all(t.target == "core" for t in workflow.transitions if t.source in inputs)
    assert any("bash" in (s.detail or "") for s in workflow.steps)


def test_derived_workflow_is_never_empty():
    workflow = derive_workflow(TopologyPayload(nodes=[], edges=[]), _report())
    assert len(workflow.steps) >= 2
    assert workflow.transitions


@pytest.mark.parametrize(
    "topology",
    [
        TopologyPayload(
            nodes=[
                GraphNode(id="f1", label="engine/agents/ast_tracer.py", kind="file", path="engine/agents/ast_tracer.py"),
                GraphNode(id="fn1", label="run_sandbox_smoke", kind="function", path="engine/agents/sandbox.py"),
                GraphNode(id="a1", label="ingest_repository", kind="agent"),
            ],
            edges=[],
        ),
    ],
)
def test_derived_labels_never_leak_symbol_names(topology):
    workflow = derive_workflow(topology, _report())
    for step in workflow.steps:
        assert not _SYMBOL_RE.search(step.label), f"symbol name leaked into label: {step.label}"


def test_workflow_survives_report_serialization():
    report = _report(workflow=parse_workflow({"steps": [{"id": "s1", "label": "Do the thing"}]}))
    restored = NutritionLabel.model_validate(report.model_dump())
    assert restored.workflow.steps[0].label == "Do the thing"
