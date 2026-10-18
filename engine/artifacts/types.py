"""Result shapes shared by every artifact inspector."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

from schemas.report_schema import Finding

Severity = Literal["info", "low", "medium", "high", "critical"]

# Deterministic issues set a floor under the LLM's score: a model file with a
# code-execution payload is Critical whatever the narrative says.
SEVERITY_SCORE: dict[str, float] = {"info": 0.0, "low": 3.0, "medium": 5.0, "high": 7.0, "critical": 9.0}
_SEVERITY_CONFIDENCE: dict[str, float] = {"info": 0.5, "low": 0.6, "medium": 0.7, "high": 0.85, "critical": 0.95}


@dataclass
class ArtifactIssue:
    code: str
    title: str
    description: str
    severity: Severity = "medium"
    owasp_id: str | None = "LLM03"
    location: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "owasp_id": self.owasp_id,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass
class ArtifactReport:
    """One inspected artifact (a file, a remote weight, or a model repository)."""

    name: str
    kind: str
    summary: dict[str, Any] = field(default_factory=dict)
    issues: list[ArtifactIssue] = field(default_factory=list)
    tool_outputs: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def add(self, issue: ArtifactIssue) -> None:
        self.issues.append(issue)

    @property
    def max_severity(self) -> str:
        order = list(SEVERITY_SCORE)
        worst = "info"
        for i in self.issues:
            if order.index(i.severity) > order.index(worst):
                worst = i.severity
        return worst

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "summary": self.summary,
            "issues": [i.as_dict() for i in self.issues],
            "max_severity": self.max_severity,
            "tool_outputs": self.tool_outputs,
            "error": self.error,
        }


def issue_to_finding(report: ArtifactReport, issue: ArtifactIssue) -> Finding:
    digest = hashlib.sha256(f"{report.name}:{issue.code}:{issue.location}".encode()).hexdigest()[:8]
    where = issue.location or report.name
    return Finding(
        id=f"art_{issue.code}_{digest}",
        title=f"[{issue.severity.upper()}] {issue.title}",
        description=issue.description,
        owasp_id=issue.owasp_id,
        affected_path=f"{report.name} -> {where}" if where != report.name else report.name,
        confidence=_SEVERITY_CONFIDENCE.get(issue.severity, 0.7),
    )
