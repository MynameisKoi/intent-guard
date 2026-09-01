"""
Behaviour-level workflow graph: what the scanned repository is trying to do.

The AST topology answers "which symbol reaches which sink", which is the right
view for an auditor tracing a taint path and the wrong view for someone asking
"what is this agent for". This module produces the second view: a handful of
plain-language stages, deliberately naming activities instead of functions.

Preferred source is the semantic model, which has read the whole bundle. When
that is unavailable the graph is derived from the topology so the view is never
empty.
"""

from __future__ import annotations

import re
from typing import Any

from engine.agents.scope import PRODUCTION, classify_rel
from schemas.graph_nodes import TopologyPayload, WorkflowGraph, WorkflowStep, WorkflowTransition
from schemas.report_schema import NutritionLabel

_ROLES = {"input", "process", "decision", "external", "output", "storage"}
_MAX_STEPS = 10

# A label made only of identifier characters is a symbol name, not a description.
_BARE_IDENTIFIER_RE = re.compile(r"^[\w./\\-]+$")
_EXTENSION_RE = re.compile(r"\.(py|js|jsx|ts|tsx|md|json|ya?ml)$", re.I)

# Sources and sinks the tracer emits, phrased as behaviour.
_SOURCE_STEPS: dict[str, tuple[str, str]] = {
    "environment": ("Read configuration and secrets from the environment", "input"),
    "network_in": ("Fetch data from a remote service", "input"),
    "stdin": ("Accept input typed by the user", "input"),
    "argv": ("Accept command-line arguments", "input"),
    "mcp_prompt": ("Receive a prompt from the calling agent or tool", "input"),
}
_SINK_STEPS: dict[str, tuple[str, str]] = {
    "shell": ("Run shell commands on the host", "external"),
    "code_exec": ("Execute code assembled at runtime", "external"),
    "network": ("Send data to an external network endpoint", "output"),
}


def humanize_label(text: str) -> str:
    """Turn a symbol-ish label into prose; leave real prose untouched."""
    label = " ".join(str(text or "").split()).replace("()", "")
    if not label:
        return ""
    if _BARE_IDENTIFIER_RE.fullmatch(label):
        stem = re.split(r"[/\\]", label)[-1]
        stem = _EXTENSION_RE.sub("", stem)
        stem = stem.replace("_", " ").replace("-", " ").replace(".", " ")
        stem = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", stem).strip()
        if stem:
            label = stem[0].upper() + stem[1:]
    return label[:90]


def parse_workflow(payload: Any) -> WorkflowGraph | None:
    """Build a WorkflowGraph from the model's JSON, tolerating loose shapes."""
    if not isinstance(payload, dict):
        return None
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        return None

    steps: list[WorkflowStep] = []
    used_ids: set[str] = set()
    for index, item in enumerate(raw_steps[:_MAX_STEPS]):
        if not isinstance(item, dict):
            continue
        label = humanize_label(item.get("label") or item.get("name") or "")
        if not label:
            continue
        step_id = str(item.get("id") or f"s{index + 1}").strip() or f"s{index + 1}"
        if step_id in used_ids:
            continue
        used_ids.add(step_id)
        role = str(item.get("role") or "process").strip().lower()
        steps.append(
            WorkflowStep(
                id=step_id,
                label=label,
                role=role if role in _ROLES else "process",
                detail=str(item.get("detail") or "")[:240],
                sensitive=bool(item.get("sensitive")),
            )
        )
    if not steps:
        return None

    transitions: list[WorkflowTransition] = []
    seen: set[tuple[str, str]] = set()
    for item in payload.get("transitions") or []:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or item.get("from") or "").strip()
        target = str(item.get("target") or item.get("to") or "").strip()
        if source not in used_ids or target not in used_ids or source == target:
            continue
        if (source, target) in seen:
            continue
        seen.add((source, target))
        transitions.append(
            WorkflowTransition(source=source, target=target, label=str(item.get("label") or "")[:60])
        )

    if not transitions:
        transitions = _chain(steps)
    return WorkflowGraph(
        summary=str(payload.get("summary") or "")[:400],
        steps=steps,
        transitions=transitions,
        source="llm",
    )


def _chain(steps: list[WorkflowStep]) -> list[WorkflowTransition]:
    return [
        WorkflowTransition(source=a.id, target=b.id) for a, b in zip(steps, steps[1:])
    ]


def derive_workflow(topology: TopologyPayload, report: NutritionLabel) -> WorkflowGraph:
    """Fallback view assembled from traced entry points, capabilities, and sinks."""
    inputs: list[WorkflowStep] = []
    externals: list[WorkflowStep] = []
    capabilities: list[str] = []
    agent_names: list[str] = []

    for node in topology.nodes:
        if node.kind == "source":
            key = str(node.meta.get("source_key") or "")
            label, role = _SOURCE_STEPS.get(key, (humanize_label(node.label), "input"))
            if label and label not in [s.label for s in inputs]:
                inputs.append(
                    WorkflowStep(id=f"in{len(inputs) + 1}", label=label, role=role, sensitive=True)
                )
        elif node.kind == "external":
            family = str(node.meta.get("family") or "")
            if family not in _SINK_STEPS:
                continue
            label, role = _SINK_STEPS[family]
            if label not in [s.label for s in externals]:
                externals.append(
                    WorkflowStep(id=f"out{len(externals) + 1}", label=label, role=role, sensitive=True)
                )
        elif node.kind == "tool":
            if node.label and node.label not in capabilities:
                capabilities.append(str(node.label))
        elif node.kind == "agent":
            # Honeypot samples ship with loud names; naming the workflow after one
            # would describe the fixture instead of the project.
            if node.label and classify_rel(node.path or "") == PRODUCTION:
                agent_names.append(str(node.label))

    if report.shell_execution and not any(s.role == "external" for s in externals):
        externals.append(
            WorkflowStep(id=f"out{len(externals) + 1}", label=_SINK_STEPS["shell"][0], role="external", sensitive=True)
        )
    if report.network_targets and not any(s.role == "output" for s in externals):
        externals.append(
            WorkflowStep(id=f"out{len(externals) + 1}", label=_SINK_STEPS["network"][0], role="output", sensitive=True)
        )

    if not inputs:
        inputs.append(WorkflowStep(id="in1", label="Receive a task from the user", role="input"))

    core_detail = (
        f"Declared capabilities: {', '.join(capabilities[:6])}." if capabilities else ""
    )
    core = WorkflowStep(
        id="core",
        label=(
            f"Act on the request as {humanize_label(agent_names[0])}"
            if agent_names
            else "Process the request with the project's own logic"
        ),
        role="process",
        detail=core_detail,
    )

    steps = [*inputs, core, *externals]
    transitions = [WorkflowTransition(source=s.id, target=core.id, label="input") for s in inputs]
    transitions += [WorkflowTransition(source=core.id, target=s.id, label="action") for s in externals]

    return WorkflowGraph(
        summary=_derived_summary(inputs, capabilities, externals),
        steps=steps[:_MAX_STEPS],
        transitions=transitions,
        source="derived",
    )


def _derived_summary(
    inputs: list[WorkflowStep], capabilities: list[str], externals: list[WorkflowStep]
) -> str:
    parts = [f"Takes {len(inputs)} kind(s) of input"]
    if capabilities:
        parts.append(f"declares {len(capabilities)} tool(s)")
    if externals:
        parts.append(f"reaches {len(externals)} external capability/capabilities")
    return (
        "Derived from traced structure because the semantic model did not return a workflow. "
        + ", ".join(parts)
        + "."
    )
