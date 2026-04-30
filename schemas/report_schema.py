"""Nutrition label and persisted scan document shapes."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from schemas.graph_nodes import TopologyPayload


class RiskCategoryScore(BaseModel):
    category: str
    level: str = "medium"  # low | medium | high — kept loose for LLM JSON variance


class Finding(BaseModel):
    id: str
    title: str
    description: str
    owasp_id: str | None = None
    affected_path: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class NutritionLabel(BaseModel):
    """Human-readable + machine summary returned to the UI."""

    intent_summary: str
    risk_score: float = Field(ge=0.0, le=10.0)
    risk_label: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    permissions_inferred: list[str] = Field(default_factory=list)
    network_targets: list[str] = Field(default_factory=list)
    shell_execution: bool = False
    findings: list[Finding] = Field(default_factory=list)
    category_scores: list[RiskCategoryScore] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class ScanRecord(BaseModel):
    scan_id: str
    target: str
    created_at: datetime
    status: Literal["completed", "failed"] = "completed"
    error: str | None = None
    report: NutritionLabel | None = None
    topology: TopologyPayload | None = None
    sources: list[dict[str, str]] = Field(default_factory=list)
