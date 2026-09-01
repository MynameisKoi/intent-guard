"""Serializable graph primitives for Neo4j and API responses."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    kind: Literal["file", "function", "external", "data", "source", "agent", "tool", "prompt", "permission", "task", "other"] = "other"
    path: str | None = None
    is_source: bool = Field(
        default=False,
        description="True when this node is an untrusted-data entry (handler, tool param, etc.).",
    )
    meta: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: str = "flows_to"
    variable_name: str | None = Field(
        default=None,
        description="Variable or parameter name carrying tainted data along this edge (if known).",
    )
    meta: dict[str, Any] = Field(default_factory=dict)


class TopologyPayload(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


WorkflowRole = Literal["input", "process", "decision", "external", "output", "storage"]


class WorkflowStep(BaseModel):
    """One stage of what the target actually does, described in plain language."""

    id: str
    label: str
    role: WorkflowRole = "process"
    detail: str = ""
    sensitive: bool = Field(
        default=False,
        description="True when this stage touches untrusted input, credentials, or the outside world.",
    )


class WorkflowTransition(BaseModel):
    source: str
    target: str
    label: str = Field(default="", description="What moves between the two stages, e.g. 'user request'.")


class WorkflowGraph(BaseModel):
    """
    A behaviour-level companion to TopologyPayload.

    The topology answers "which symbol calls which"; this answers "what is this
    repository trying to do", so it names activities rather than functions.
    """

    summary: str = ""
    steps: list[WorkflowStep] = Field(default_factory=list)
    transitions: list[WorkflowTransition] = Field(default_factory=list)
    source: str = Field(default="derived", description="'llm' or 'derived'.")
