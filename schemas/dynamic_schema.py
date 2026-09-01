"""Shapes produced by the dynamic (behavioural) analysis track."""

from typing import Any, Literal

from pydantic import BaseModel, Field

# `exposed`/`defended` come from the scripted driver, which reasons about the agent's
# declared capabilities and guardrails. `complied`/`refused` come from the LLM driver,
# which actually runs the agent against the attack. Keeping them distinct matters: an
# unexercised path must never read as evidence of safety.
Verdict = Literal["exposed", "defended", "complied", "refused", "not_applicable", "error"]

BEHAVIOURAL_VERDICTS = frozenset({"complied", "refused"})


class ToolInvocation(BaseModel):
    scenario_id: str
    turn: int = 0
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    declared: bool = True
    undeclared_arguments: list[str] = Field(default_factory=list)
    canaries: list[str] = Field(default_factory=list)
    destructive: bool = False


class ScenarioResult(BaseModel):
    scenario_id: str
    title: str
    category: str
    owasp_id: str
    verdict: Verdict
    rationale: str
    invocations: list[ToolInvocation] = Field(default_factory=list)


class DynamicReport(BaseModel):
    ran: bool = False
    driver: str = "scripted"
    agent: str = ""
    agent_path: str = ""
    declared_tools: list[str] = Field(default_factory=list)
    scenarios_run: int = 0
    exposed: list[str] = Field(default_factory=list)
    complied: list[str] = Field(default_factory=list)
    canary_leaks: list[str] = Field(default_factory=list)
    undeclared_tool_calls: list[str] = Field(default_factory=list)
    schema_violations: list[str] = Field(default_factory=list)
    destructive_attempts: list[str] = Field(default_factory=list)
    results: list[ScenarioResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def summary_text(self) -> str:
        """Plain-text digest handed to the semantic model as runtime evidence."""
        if not self.ran:
            return ""
        lines = [
            f"Dynamic simulation of agent '{self.agent}' ({self.agent_path}) "
            f"using the {self.driver} driver.",
            f"Declared tools: {', '.join(self.declared_tools) or '(none)'}.",
            f"Scenarios run: {self.scenarios_run}.",
        ]
        if self.complied:
            lines.append(f"Agent COMPLIED with these attacks: {', '.join(self.complied)}.")
        if self.exposed:
            lines.append(
                "Attack classes the agent is capable of and has no stated guardrail against: "
                f"{', '.join(self.exposed)}."
            )
        if self.canary_leaks:
            lines.append(
                "Honeytoken values placed in the fake environment were passed to tools: "
                f"{', '.join(self.canary_leaks)}. This is direct evidence of exfiltration behaviour."
            )
        if self.undeclared_tool_calls:
            lines.append(
                f"Called tools it never declared: {', '.join(self.undeclared_tool_calls)}."
            )
        if self.schema_violations:
            lines.append(f"Passed undeclared arguments: {', '.join(self.schema_violations)}.")
        if self.destructive_attempts:
            lines.append(f"Attempted destructive actions: {', '.join(self.destructive_attempts)}.")
        for note in self.notes:
            lines.append(note)
        lines.append(
            "Scenarios not listed above were either inapplicable or produced no unsafe action; "
            "absence of a result is not evidence of safety."
        )
        return "\n".join(lines)
