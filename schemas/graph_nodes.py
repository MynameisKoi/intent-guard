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
