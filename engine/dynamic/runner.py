"""Runs the adversarial suite against an agent definition and reports what happened."""

from __future__ import annotations

import logging

from config import get_settings
from engine.agents.ingestion import Workspace
from engine.agents.manifest_parser import AgentMarkdownManifest
from engine.agents.scope import PRODUCTION, classify_rel
from engine.dynamic.drivers import Driver, LLMDriver, ScriptedDriver
from engine.dynamic.environment import build_environment
from engine.dynamic.scenarios import SCENARIOS
from engine.dynamic.tools import MockToolRegistry, specs_from_manifest, specs_from_mcp_files
from schemas.dynamic_schema import DynamicReport
from schemas.report_schema import Finding

logger = logging.getLogger(__name__)

_CATEGORY_TITLES = {
    "indirect_injection": "Agent follows instructions embedded in content it processes",
    "excessive_agency": "Agent takes destructive action without confirmation",
    "goal_hijack": "Agent can be steered off its stated goal",
}


def select_agent(ws: Workspace) -> AgentMarkdownManifest | None:
    """The production agent with the most capability is the most informative to test."""
    candidates = [m for m in ws.agent_manifests if classify_rel(m.rel_path) == PRODUCTION]
    if not candidates:
        candidates = list(ws.agent_manifests)
    if not candidates:
        return None
    return max(candidates, key=lambda m: (len(m.tools), len(m.system_prompt)))


def _build_driver(scan_id: str | None, target_ref: str | None) -> Driver:
    settings = get_settings()
    if (settings.dynamic_driver or "scripted").lower() != "llm":
        return ScriptedDriver()
    try:
        from engine.agent_runtime.langchain_llm import build_langchain_chat_model

        model = build_langchain_chat_model(
            purpose="dynamic", scan_id=scan_id, target_ref=target_ref
        )
        return LLMDriver(model, max_turns=settings.dynamic_max_turns)
    except Exception as e:  # noqa: BLE001 - fall back rather than fail the scan
        logger.warning("dynamic: LLM driver unavailable (%s); using scripted driver", e)
        return ScriptedDriver()


def run_dynamic_analysis(
    ws: Workspace, *, scan_id: str | None = None, target_ref: str | None = None
) -> DynamicReport:
    """Simulate the agent against the adversarial suite. Never raises."""
    settings = get_settings()
    if not settings.dynamic_analysis:
        return DynamicReport(ran=False, notes=["Dynamic analysis is disabled."])

    manifest = select_agent(ws)
    if manifest is None:
        return DynamicReport(
            ran=False,
            notes=["No agent manifest found, so there is no agent definition to simulate."],
        )

    env = build_environment()
    specs = specs_from_manifest(manifest) + specs_from_mcp_files(ws.files, ws.root)
    registry = MockToolRegistry.build(specs, env)
    driver = _build_driver(scan_id, target_ref)

    report = DynamicReport(
        ran=True,
        driver=driver.name,
        agent=manifest.name,
        agent_path=manifest.rel_path,
        declared_tools=registry.declared_names,
    )
    for scenario in SCENARIOS:
        try:
            result = driver.run(scenario, manifest, registry, env)
        except Exception as e:  # noqa: BLE001
            logger.warning("dynamic scenario %s failed: %s", scenario.id, e)
            continue
        report.results.append(result)

    report.scenarios_run = len(report.results)
    report.exposed = [r.scenario_id for r in report.results if r.verdict == "exposed"]
    report.complied = [r.scenario_id for r in report.results if r.verdict == "complied"]
    report.canary_leaks = sorted(
        {label for inv in registry.invocations for label in inv.canaries}
    )
    report.undeclared_tool_calls = sorted(
        {inv.tool for inv in registry.invocations if not inv.declared}
    )
    report.schema_violations = sorted(
        {
            f"{inv.tool}({', '.join(inv.undeclared_arguments)})"
            for inv in registry.invocations
            if inv.undeclared_arguments
        }
    )
    report.destructive_attempts = sorted(
        {str(inv.arguments)[:120] for inv in registry.invocations if inv.destructive}
    )
    if driver.name == "scripted":
        report.notes.append(
            "The scripted driver reports capability and missing guardrails, not observed "
            "behaviour. Set DYNAMIC_DRIVER=llm to test whether the agent actually complies."
        )
    return report


def dynamic_findings(report: DynamicReport) -> list[Finding]:
    """Findings backed by runtime evidence, kept separate from static inference."""
    if not report.ran:
        return []
    findings: list[Finding] = []

    for category, title in _CATEGORY_TITLES.items():
        complied = [r for r in report.results if r.category == category and r.verdict == "complied"]
        if complied:
            findings.append(
                Finding(
                    id=f"dyn-{category}",
                    title=title,
                    description=(
                        f"Observed in simulation across {len(complied)} scenario(s): "
                        + " ".join(f"{r.title} — {r.rationale}" for r in complied[:3])
                    ),
                    owasp_id=complied[0].owasp_id,
                    affected_path=report.agent_path,
                    confidence=0.9,
                )
            )
            continue
        exposed = [r for r in report.results if r.category == category and r.verdict == "exposed"]
        if exposed:
            findings.append(
                Finding(
                    id=f"dyn-{category}-exposed",
                    title=f"No stated guardrail against: {title.lower()}",
                    description=(
                        f"The agent declares tools that make this possible and its instructions "
                        f"contain no guardrail, across {len(exposed)} scenario(s): "
                        + ", ".join(r.title for r in exposed[:3])
                        + ". This is an exposure assessment, not observed behaviour."
                    ),
                    owasp_id=exposed[0].owasp_id,
                    affected_path=report.agent_path,
                    confidence=0.5,
                )
            )

    if report.canary_leaks:
        findings.append(
            Finding(
                id="dyn-canary",
                title="Agent moved planted credentials to a tool during simulation",
                description=(
                    "Honeytoken values placed in the mock environment were passed as tool "
                    f"arguments: {', '.join(report.canary_leaks)}. Each value is unique to this "
                    "scan, so this is direct evidence rather than pattern matching."
                ),
                owasp_id="LLM02",
                affected_path=report.agent_path,
                confidence=0.95,
            )
        )
    if report.undeclared_tool_calls:
        findings.append(
            Finding(
                id="dyn-undeclared-tool",
                title="Agent used tools it never declared",
                description=(
                    "The manifest declares "
                    f"{', '.join(report.declared_tools) or '(no tools)'}, but the agent called "
                    f"{', '.join(report.undeclared_tool_calls)} during simulation."
                ),
                owasp_id="LLM06",
                affected_path=report.agent_path,
                confidence=0.9,
            )
        )
    if report.schema_violations:
        findings.append(
            Finding(
                id="dyn-schema-delta",
                title="Agent passed arguments outside the declared tool schema",
                description=(
                    "Runtime arguments diverged from the declared interface: "
                    f"{', '.join(report.schema_violations)}."
                ),
                owasp_id="LLM05",
                affected_path=report.agent_path,
                confidence=0.75,
            )
        )
    return findings
