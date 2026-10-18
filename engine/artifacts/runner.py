"""
Unified runner for artifact analysis and reverse engineering.

Scans GGUF, safetensors, pickle checkpoints, and binaries (PE/.NET, ELF, Mach-O,
ASAR, WASM, etc.) in a workspace. Produces:
1. Structured `ArtifactReport` objects and converted `Finding`s.
2. Formatted evidence for the LLM `code_bundle`, allowing OpenRouter models
   (e.g. DeepSeek, Claude) to reason over decompiled structure, headers, and strings.
3. Graph nodes and edges so model weights and reverse-engineered binary components
   are visible in Neo4j and the React frontend graph topology.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from config import get_settings
from engine.artifacts.binary_triage import strings_excerpt, triage_binary
from engine.artifacts.byte_source import LocalSource
from engine.artifacts.detect import detect_kind, is_binary_kind, is_candidate, is_model_kind
from engine.artifacts.gguf import inspect_gguf
from engine.artifacts.pickle_scan import inspect_pickle
from engine.artifacts.rea_bridge import rea_available, reverse_engineer
from engine.artifacts.safetensors import inspect_safetensors
from engine.artifacts.types import ArtifactIssue, ArtifactReport, SEVERITY_SCORE, issue_to_finding
from schemas.graph_nodes import GraphEdge, GraphNode, TopologyPayload

logger = logging.getLogger(__name__)


def inspect_local_file(path: Path, *, kind: str | None = None) -> ArtifactReport:
    """Inspect a single local model or binary artifact."""
    s = get_settings()
    k = kind or detect_kind(path) or "unknown"
    if k == "gguf":
        src = LocalSource(path)
        try:
            return inspect_gguf(
                src,
                name=path.name,
                sample_tensors=int(s.weight_sample_tensors),
                sample_bytes=int(s.weight_sample_bytes),
            )
        finally:
            src.close()
    if k == "safetensors":
        src = LocalSource(path)
        try:
            return inspect_safetensors(src, name=path.name)
        finally:
            src.close()
    if k in ("pickle", "torch_zip"):
        return inspect_pickle(path, name=path.name)

    # Executable / binary formats: run always-on triage, then REA if available
    report = triage_binary(path, kind=k, name=path.name)
    if rea_available():
        rea_res = reverse_engineer(path, k)
        report.tool_outputs["rea"] = rea_res
        if rea_res.get("available") and rea_res.get("commands"):
            report.summary["rea_commands_executed"] = len(rea_res["commands"])
    return report


def scan_workspace_artifacts(
    root: Path,
    candidate_paths: list[Path] | None = None,
    precomputed_reports: list[ArtifactReport] | None = None,
) -> list[ArtifactReport]:
    """Scan all candidate model and binary artifacts in the workspace."""
    s = get_settings()
    reports: list[ArtifactReport] = list(precomputed_reports or [])
    seen_names = {r.name for r in reports}

    paths = candidate_paths or []
    if not paths and root.exists():
        if root.is_file():
            paths = [root]
        else:
            for p in root.rglob("*"):
                if p.is_file() and is_candidate(p):
                    paths.append(p)

    max_artifacts = int(s.rea_max_artifacts)
    max_bytes = int(s.rea_max_artifact_bytes)
    scanned_count = 0

    for path in sorted(paths, key=lambda p: p.stat().st_size if p.exists() else 0):
        if scanned_count >= max_artifacts:
            break
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        if rel in seen_names or path.name in seen_names:
            continue
        try:
            sz = path.stat().st_size
            if max_bytes > 0 and sz > max_bytes:
                continue
            kind = detect_kind(path)
            if not kind:
                continue
            rep = inspect_local_file(path, kind=kind)
            rep.name = rel
            reports.append(rep)
            seen_names.add(rel)
            scanned_count += 1
        except Exception as e:
            logger.warning("Artifact inspection failed for %s: %s", path, e)
    return reports


def format_artifacts_for_prompt(reports: list[ArtifactReport], root: Path | None = None) -> str:
    """Format artifact findings, GGUF/model metadata, and REA reverse engineering output for the LLM."""
    if not reports:
        return ""
    sections: list[str] = ["=== ARTIFACT & REVERSE-ENGINEERING EVIDENCE ==="]
    for rep in reports:
        sections.append(f"\n[Artifact: {rep.name} (Kind: {rep.kind}, Severity: {rep.max_severity.upper()})]")
        if rep.error:
            sections.append(f"  Error: {rep.error}")
        if rep.summary:
            clean_summary = {k: v for k, v in rep.summary.items() if k not in ("truncated_read", "downloaded_text_files")}
            sections.append(f"  Summary Facts: {clean_summary}")
        if rep.issues:
            sections.append("  Detected Anomaly / Security Issues:")
            for issue in rep.issues:
                sections.append(f"    - [{issue.severity.upper()}] {issue.code}: {issue.title}")
                sections.append(f"      {issue.description}")

        # If REA reverse-engineered Evidence exists, include it for deep reasoning
        rea_data = rep.tool_outputs.get("rea")
        if isinstance(rea_data, dict) and rea_data.get("evidence_text"):
            sections.append("\n  [REA Reverse Engineering Evidence]")
            sections.append(rea_data["evidence_text"][:12_000])

        # Excerpt notable strings for binary triage if applicable
        if root and is_binary_kind(rep.kind):
            target_path = (root / rep.name).resolve()
            if target_path.exists():
                try:
                    str_samples = strings_excerpt(target_path, max_items=25)
                    if str_samples:
                        sections.append(f"  Sample Program Strings: {str_samples}")
                except Exception:
                    pass

    return "\n".join(sections)


def artifact_findings(reports: list[ArtifactReport]) -> list[Any]:
    findings = []
    for rep in reports:
        for issue in rep.issues:
            findings.append(issue_to_finding(rep, issue))
    return findings


def artifact_severity_floor(reports: list[ArtifactReport]) -> float:
    worst = 0.0
    for rep in reports:
        for issue in rep.issues:
            score = SEVERITY_SCORE.get(issue.severity, 0.0)
            if score > worst:
                worst = score
    return worst


def build_artifact_topology(reports: list[ArtifactReport]) -> TopologyPayload:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen: set[str] = set()

    for rep in reports:
        node_id = f"art::{rep.name}"
        if node_id not in seen:
            seen.add(node_id)
            k = "tool" if is_binary_kind(rep.kind) else ("data" if is_model_kind(rep.kind) else "external")
            nodes.append(
                GraphNode(
                    id=node_id,
                    label=rep.name,
                    kind=k,
                    path=rep.name,
                    meta={"artifact_kind": rep.kind, "severity": rep.max_severity, **rep.summary},
                )
            )

        for issue in rep.issues:
            iss_id = f"iss::{rep.name}::{issue.code}"
            if iss_id not in seen:
                seen.add(iss_id)
                nodes.append(
                    GraphNode(
                        id=iss_id,
                        label=f"{issue.code} ({issue.severity.upper()})",
                        kind="task" if issue.severity in ("critical", "high") else "other",
                        meta={"issue": issue.as_dict()},
                    )
                )
                edges.append(
                    GraphEdge(
                        id=f"e::{node_id}::{iss_id}",
                        source=node_id,
                        target=iss_id,
                        kind="has_anomaly",
                    )
                )
    return TopologyPayload(nodes=nodes, edges=edges)
