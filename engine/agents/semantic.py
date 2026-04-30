"""evaluate_intent() — LLM-backed semantic analysis with heuristic fallback."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from engine.agent_runtime.scan_graph import run_semantic_scan_graph
from engine.llm.factory import get_llm_client
from schemas.report_schema import Finding, NutritionLabel, RiskCategoryScore

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[2]
_PROMPTS_DIR = (_ROOT / "prompts").resolve()
_INTENT_PROMPT_PATH = (_PROMPTS_DIR / "intent_analysis.md").resolve()
_TOP10_VULN_PATH = (_PROMPTS_DIR / "TOP10_VULN.md").resolve()
_OWASP_IDS = [f"LLM{i:02d}" for i in range(1, 11)]


def _normalize_semantic_owasp_id(raw: Any) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip().upper()
    m_llm = re.search(r"\bLLM\s*0?([1-9]|10)\b", text)
    if m_llm:
        return f"LLM{int(m_llm.group(1)):02d}"
    m_a = re.search(r"\bA\s*0?([1-9]|10)\b", text)
    if m_a:
        return f"LLM{int(m_a.group(1)):02d}"
    return None


def _load_owasp_reference_text() -> str:
    """
    Read local taxonomy definitions and return plain text for prompt injection.
    The model cannot read local files directly, so we inject this text explicitly.
    """
    try:
        text = _TOP10_VULN_PATH.read_text(encoding="utf-8").strip()
        if text:
            return text[:120_000]
    except Exception as e:
        logger.warning("Failed to read taxonomy reference at %s: %s", _TOP10_VULN_PATH, e)
    return ""


def _strict_json_contract() -> str:
    flags = "\n".join([f'  "{oid}": false' + ("," if oid != "LLM10" else "") for oid in _OWASP_IDS])
    return (
        "Return ONLY strict JSON (no prose, no markdown fences) matching this contract:\n"
        "{\n"
        '  "intent_summary": "string",\n'
        '  "risk_score": 0.0,\n'
        '  "risk_label": "Low|Medium|High|Critical",\n'
        '  "permissions_inferred": ["string"],\n'
        '  "network_targets": ["string"],\n'
        '  "shell_execution": false,\n'
        '  "owasp_llm_top10": {\n'
        f"{flags}\n"
        "  },\n"
        '  "findings": [\n'
        '    {"id":"string","title":"string","description":"string","owasp_id":"LLM01|...|LLM10|null","affected_path":"string|null","confidence":0.0}\n'
        "  ],\n"
        '  "category_scores": [{"category":"string","level":"low|medium|high"}],\n'
        '  "annotated_code": [{"line":0,"code":"string","annotation":"string","severity":"low|medium|high","file":"string"}]\n'
        "}\n\n"
        "IMPORTANT:\n"
        "- Evaluate every OWASP LLM Top 10 category on every run.\n"
        "- `owasp_llm_top10` must include all keys LLM01..LLM10 and every value must be boolean true/false.\n"
        "- Do not omit any key, even when false.\n"
    )


def _load_system_prompt() -> str:
    base_prompt_text = _INTENT_PROMPT_PATH.read_text(encoding="utf-8")
    owasp_reference_text = _load_owasp_reference_text()
    contract = _strict_json_contract()
    if owasp_reference_text:
        return (
            f"{base_prompt_text}\n\n"
            "### Strict Classification Definitions ###\n"
            f"{owasp_reference_text}\n\n"
            "### Strict Output Contract ###\n"
            f"{contract}"
        )
    return (
        f"{base_prompt_text}\n\n"
        "### Strict Output Contract ###\n"
        f"{contract}"
    )


def evaluate_intent(
    code_bundle: str,
    path_hints: list[dict[str, Any]],
    dynamic_logs: str | None = None,
    scan_id: str | None = None,
    target_ref: str | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    force_rescan: bool = False,
) -> NutritionLabel:
    """
    Prefers LangGraph + LangSmith (when enabled) for traced multi-step analysis;
    falls back to a single LLMClient call, then heuristics.

    When HELICONE_API_KEY is set, LangGraph static node uses response caching keyed by
    static payload hash; dynamic log merge runs with caching disabled.
    """
    agent_rows = [h for h in path_hints if isinstance(h, dict) and h.get("agent")]
    user_payload: dict[str, Any] = {
        "code_and_manifest_excerpts": code_bundle[:100_000],
        "dataflow_hints": path_hints[:250],
    }
    if agent_rows:
        user_payload["prompt_only_agents"] = agent_rows[:50]
    user = json.dumps(user_payload, indent=2)
    system = _load_system_prompt()

    if on_event:
        on_event(
            {"type": "llm_step", "step": "langgraph", "phase": "attempt", "scan_id": scan_id, "force_rescan": force_rescan}
        )
    raw = run_semantic_scan_graph(
        system_prompt=system,
        static_user_text=user,
        dynamic_logs=dynamic_logs,
        scan_id=scan_id,
        target_ref=target_ref,
        on_event=on_event,
        force_rescan=force_rescan,
    )
    if raw:
        try:
            return _nutrition_from_dict(_parse_json_block(raw), code_bundle, path_hints)
        except Exception as e:
            logger.warning("LangGraph semantic JSON parse failed: %s", e)
            if on_event:
                on_event(
                    {
                        "type": "llm_step",
                        "step": "langgraph",
                        "phase": "parse_failed",
                        "scan_id": scan_id,
                        "note": "Skipping direct LLM retry to avoid duplicate requests; falling back to heuristics.",
                    }
                )
            return _heuristic_nutrition(code_bundle, path_hints)

    client = get_llm_client()
    if client:
        try:
            if on_event:
                on_event(
                    {
                        "type": "llm_step",
                        "step": "single_shot_llm",
                        "phase": "start",
                        "scan_id": scan_id,
                        "note": "Direct LLMClient call (still traced by LangSmith when enabled)",
                    }
                )
            raw2 = client.complete(system=system, user=user, no_cache=force_rescan)
            if on_event:
                on_event({"type": "llm_step", "step": "single_shot_llm", "phase": "complete", "scan_id": scan_id})
            parsed = _parse_json_block(raw2)
            return _nutrition_from_dict(parsed, code_bundle, path_hints)
        except Exception as e:
            logger.warning("LLM semantic analysis failed: %s", e)

    if on_event:
        on_event({"type": "llm_step", "step": "heuristic", "phase": "complete", "scan_id": scan_id})
    return _heuristic_nutrition(code_bundle, path_hints)


def _parse_json_block(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def _extract_candidate_functions(code: str, token: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(r"(?ms)^def\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*:\s*(.+?)(?=^def\s+|\Z)", code):
        fn = m.group(1)
        body = m.group(2)
        if token in body:
            out.append(fn)
    return out


def _candidate_from_path_hints(path_hints: list[dict[str, Any]], to_value: str) -> str | None:
    for h in path_hints:
        if str(h.get("to", "")).lower() != to_value.lower():
            continue
        src = str(h.get("from_function") or "").strip()
        if src:
            return f"{src} -> {to_value}"
    return None


def _infer_affected_path(owasp_id: str | None, code: str, path_hints: list[dict[str, Any]]) -> str | None:
    if owasp_id == "LLM01":
        from_hints = _candidate_from_path_hints(path_hints, "subprocess")
        if from_hints:
            return f"{from_hints}.run()"
        fns = _extract_candidate_functions(code, "subprocess.run")
        if fns:
            return f"{fns[0]}() -> subprocess.run()"
        if "os.system" in code:
            fns = _extract_candidate_functions(code, "os.system")
            if fns:
                return f"{fns[0]}() -> os.system()"
            return "input_to_agent -> os.system()"
    if owasp_id == "LLM02":
        fns = _extract_candidate_functions(code, "open(")
        if fns:
            return f"{fns[0]}() -> open() -> network request"
        if "AWS_ACCESS_KEY_ID" in code or "DATABASE_URL" in code:
            return "env_secret -> prompt_context/output"
    if owasp_id == "LLM06":
        fns = _extract_candidate_functions(code, "requests.post")
        if fns:
            return f"{fns[0]}() -> requests.post()"
    return None


def _infer_file_from_bundle(code_snippet: str, code_bundle: str) -> str:
    snippet = " ".join(str(code_snippet or "").strip().split()).lower()
    if not snippet or snippet == "—":
        return "unknown"
    current_file = "unknown"
    for raw_line in code_bundle.splitlines():
        line = raw_line.strip()
        m = re.match(r"^===\s+(.+?)\s+===$", line)
        if m:
            current_file = m.group(1).strip() or "unknown"
            continue
        if snippet in " ".join(line.split()).lower():
            return current_file
    return "unknown"


def _annotated_rows_from_llm(raw: Any, code_bundle: str) -> list[dict[str, Any]]:
    """Normalize LLM `annotated_code` array for report.meta."""
    if not raw or not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in raw:
        if not isinstance(row, dict):
            continue
        try:
            line = int(row.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        code = str(row.get("code") or "").strip()[:300]
        ann = str(row.get("annotation") or row.get("note") or "").strip()[:500]
        if not code and not ann:
            continue
        if not code:
            code = (ann[:120] + ("…" if len(ann) > 120 else "")) or "—"
        sev = str(row.get("severity") or "medium").lower()
        if sev not in ("low", "medium", "high"):
            sev = "medium"
        file_name = str(row.get("file") or "").strip()[:220] or "unknown"
        if file_name == "unknown":
            file_name = _infer_file_from_bundle(code, code_bundle)[:220]
        dedupe_key = (
            file_name,
            " ".join((ann or "Semantic risk").lower().split())[:200],
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        item: dict[str, Any] = {
            "line": max(0, line),
            "code": code,
            "annotation": ann or "Semantic risk",
            "severity": sev,
            "file": file_name,
        }
        out.append(item)
        if len(out) >= 120:
            break
    return out


def _nutrition_from_dict(d: dict[str, Any], code_bundle: str, path_hints: list[dict[str, Any]]) -> NutritionLabel:
    findings = []
    for i, f in enumerate(d.get("findings") or []):
        owasp_id = _normalize_semantic_owasp_id(f.get("owasp_id"))
        affected_path = str(f.get("affected_path")).strip() if f.get("affected_path") else None
        if not affected_path:
            affected_path = _infer_affected_path(owasp_id, code_bundle, path_hints)
        findings.append(
            Finding(
                id=str(f.get("id") or f"finding_{i}"),
                title=str(f.get("title") or "Finding"),
                description=str(f.get("description") or ""),
                owasp_id=owasp_id,
                affected_path=affected_path,
                confidence=float(f.get("confidence") or 0.7),
            )
        )
    cats = []
    for c in d.get("category_scores") or []:
        try:
            level = str(c.get("level", "medium")).lower()
            if level not in ("low", "medium", "high"):
                level = "medium"
            cats.append(RiskCategoryScore(category=str(c.get("category", "unknown")), level=level))
        except Exception:
            continue

    risk_label = d.get("risk_label") or "Medium"
    if risk_label not in ("Low", "Medium", "High", "Critical"):
        risk_label = "Medium"

    ann = _annotated_rows_from_llm(d.get("annotated_code"), code_bundle)
    meta: dict[str, Any] = {"source": "llm"}
    if ann:
        meta["annotated_code"] = ann

    return NutritionLabel(
        intent_summary=str(d.get("intent_summary") or "No summary returned."),
        risk_score=float(d.get("risk_score") or 5.0),
        risk_label=risk_label,
        permissions_inferred=list(d.get("permissions_inferred") or []),
        network_targets=list(d.get("network_targets") or []),
        shell_execution=bool(d.get("shell_execution")),
        findings=findings,
        category_scores=cats,
        meta=meta,
    )


def _heuristic_nutrition(code: str, path_hints: list[dict[str, Any]]) -> NutritionLabel:
    def infer_intent_summary() -> str:
        agent_names = []
        tools: list[str] = []
        tasks: list[str] = []
        for h in path_hints:
            if not isinstance(h, dict):
                continue
            agent = str(h.get("agent") or "").strip()
            if agent:
                agent_names.append(agent)
            for t in h.get("tools") or []:
                tt = str(t).strip()
                if tt:
                    tools.append(tt)
            for t in h.get("tasks") or []:
                tt = str(t).strip()
                if tt:
                    tasks.append(tt)

        has_network = bool(re.search(r"requests\.(post|get)|urllib|httpx\.", code))
        has_shell = bool(re.search(r"subprocess|os\.system|shell\s*=\s*True", code))
        has_fs = bool(re.search(r"open\(|read_text|read_bytes|pathlib\.Path", code))

        parts: list[str] = []
        if agent_names:
            parts.append(f"This repository defines agent behavior for {agent_names[0]}")
        else:
            parts.append("This repository appears to automate workflow steps")
        if tasks:
            parts.append(f"with tasks like {tasks[0][:120]}")
        if tools:
            uniq_tools: list[str] = []
            for t in tools:
                if t not in uniq_tools:
                    uniq_tools.append(t)
                if len(uniq_tools) >= 4:
                    break
            parts.append(f"and tool usage via {', '.join(uniq_tools)}")

        capabilities: list[str] = []
        if has_network:
            capabilities.append("network access")
        if has_fs:
            capabilities.append("filesystem reads")
        if has_shell:
            capabilities.append("command execution")
        if capabilities:
            parts.append(f". Static analysis shows {', '.join(capabilities)}")

        return " ".join(parts).strip() + "."

    score = 3.0
    findings: list[Finding] = []
    nets = []
    shell = False

    if re.search(r"requests\.(post|get)|urllib|httpx\.", code):
        score += 2.0
        nets.append("HTTP client usage detected")
    if re.search(r"subprocess|os\.system|shell\s*=\s*True", code):
        score += 2.5
        shell = True
        findings.append(
            Finding(
                id="h1",
                title="Shell / subprocess surface",
                description="Subprocess or os.system patterns increase prompt-injection impact.",
                owasp_id="LLM01",
                affected_path=_infer_affected_path("LLM01", code, path_hints),
                confidence=0.6,
            )
        )
    if re.search(r"open\(|read_text|read_bytes", code):
        findings.append(
            Finding(
                id="h2",
                title="Filesystem read",
                description="Local file reads can feed sensitive data into model context.",
                owasp_id="LLM02",
                affected_path=_infer_affected_path("LLM02", code, path_hints),
                confidence=0.55,
            )
        )
        score += 1.0
    if ".ssh" in code or "/etc/" in code:
        score += 2.0
        findings.append(
            Finding(
                id="h3",
                title="Sensitive path reference",
                description="Code or docs reference high-value paths.",
                owasp_id="LLM02",
                affected_path=_infer_affected_path("LLM02", code, path_hints),
                confidence=0.65,
            )
        )

    score = min(10.0, score)
    label: Any = "Low"
    if score >= 8:
        label = "Critical"
    elif score >= 6:
        label = "High"
    elif score >= 4:
        label = "Medium"

    return NutritionLabel(
        intent_summary=infer_intent_summary(),
        risk_score=round(score, 1),
        risk_label=label,
        permissions_inferred=["filesystem", "environment"] if "open(" in code else [],
        network_targets=nets,
        shell_execution=shell,
        findings=findings,
        category_scores=[
            RiskCategoryScore(category="exfiltration", level="medium" if score >= 5 else "low"),
            RiskCategoryScore(category="injection", level="high" if shell else "medium"),
        ],
        meta={"source": "heuristic", "hints": len(path_hints)},
    )

