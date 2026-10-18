"""Pipeline coordinator — wires ingestion → AST → Neo4j → semantic → OWASP → sandbox → storage."""

from __future__ import annotations

import logging
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Callable
from typing import Any

from engine.agents.annotated_code import merge_annotations, pattern_annotate
from engine.agents.ast_tracer import trace_dataflow
from engine.agents.ingestion import Workspace, cleanup_workspace, ingest
from engine.agents.owasp import map_to_taxonomy
from engine.agents.sandbox import run_sandbox_smoke
from engine.agents.sanitize import redact_secrets, secret_finding
from engine.agents.semantic import evaluate_intent
from engine.agents.workflow import derive_workflow
from engine.dynamic.runner import dynamic_findings, run_dynamic_analysis
from engine.database.mongo_client import get_mongo_store
from engine.database.neo4j_client import get_neo4j
from engine.telemetry_links import build_telemetry_payload
from engine.artifacts.huggingface import is_hf_target
from engine.artifacts.runner import (
    artifact_findings,
    artifact_severity_floor,
    build_artifact_topology,
    format_artifacts_for_prompt,
    scan_workspace_artifacts,
)
from schemas.graph_nodes import TopologyPayload
from schemas.report_schema import NutritionLabel, ScanRecord

logger = logging.getLogger(__name__)


def run_scan(
    target: str,
    dynamic_logs: str | None = None,
    *,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    force_rescan: bool = False,
) -> ScanRecord:
    def emit(ev: dict[str, Any]) -> None:
        if on_event:
            try:
                on_event(ev)
            except Exception:
                logger.debug("scan on_event handler failed", exc_info=True)

    scan_id = str(uuid.uuid4())
    ws: Workspace | None = None
    created_iso = datetime.now(timezone.utc).isoformat()
    try:
        emit(
            {
                "type": "scan_started",
                "scan_id": scan_id,
                "target": target,
                "force_rescan": force_rescan,
                "telemetry": build_telemetry_payload(scan_id=scan_id, target=target, created_at_iso=created_iso),
            }
        )
        if force_rescan:
            _prepare_force_rescan(target, emit)
        ws = ingest(target)
        emit({"type": "phase", "phase": "ingestion", "status": "complete", "scan_id": scan_id})

        topology, code_bundle, path_hints = trace_dataflow(ws, on_event=emit, scan_id=scan_id)

        # Artifact inspection & REA reverse engineering (GGUF, safetensors, pickle, binaries)
        emit({"type": "phase", "phase": "artifact_analysis", "status": "started", "scan_id": scan_id})
        art_reports = scan_workspace_artifacts(
            ws.root,
            candidate_paths=ws.artifact_files,
            precomputed_reports=ws.artifact_reports,
        )
        art_evidence = format_artifacts_for_prompt(art_reports, root=ws.root)
        if art_evidence:
            code_bundle = f"{code_bundle}\n\n{art_evidence}" if code_bundle else art_evidence
        art_topo = build_artifact_topology(art_reports)
        topology.nodes.extend(art_topo.nodes)
        topology.edges.extend(art_topo.edges)
        emit(
            {
                "type": "phase",
                "phase": "artifact_analysis",
                "status": "complete",
                "scan_id": scan_id,
                "artifacts_scanned": len(art_reports),
            }
        )

        # Redact before anything leaves the process: the bundle goes to the LLM
        # provider, the observability proxy, and the report database.
        code_bundle, redactions = redact_secrets(code_bundle)
        emit(
            {
                "type": "phase",
                "phase": "static_analysis",
                "status": "complete",
                "scan_id": scan_id,
                "hint_count": len(path_hints),
                "redacted_secrets": sum(redactions.values()),
            }
        )

        neo = get_neo4j()
        if neo.available:
            neo.write_topology(scan_id, topology)
            emit({"type": "phase", "phase": "graph_storage", "status": "complete", "scan_id": scan_id})
        else:
            emit({"type": "phase", "phase": "graph_storage", "status": "skipped", "scan_id": scan_id})

        # Runs before the semantic step so observed behaviour becomes evidence the
        # model reasons over, rather than a footnote appended to its verdict.
        emit({"type": "phase", "phase": "dynamic_analysis", "status": "started", "scan_id": scan_id})
        dynamic = run_dynamic_analysis(ws, scan_id=scan_id, target_ref=target)
        dynamic_logs = "\n\n".join(part for part in (dynamic.summary_text(), dynamic_logs) if part) or None
        emit(
            {
                "type": "phase",
                "phase": "dynamic_analysis",
                "status": "complete" if dynamic.ran else "skipped",
                "scan_id": scan_id,
                "scenarios_run": dynamic.scenarios_run,
            }
        )

        emit(
            {
                "type": "semantic_started",
                "scan_id": scan_id,
                "message": "LLM semantic analysis (LangSmith traces + Helicone headers when configured)",
                "telemetry": build_telemetry_payload(scan_id=scan_id, target=target, created_at_iso=created_iso),
            }
        )
        report = evaluate_intent(
            code_bundle,
            path_hints,
            dynamic_logs=dynamic_logs,
            scan_id=scan_id,
            target_ref=target,
            on_event=emit,
            force_rescan=force_rescan,
        )
        emit({"type": "phase", "phase": "semantic_analysis", "status": "complete", "scan_id": scan_id})

        credentials = secret_finding(redactions)
        if credentials:
            report.findings.append(credentials)
        report.findings.extend(dynamic_findings(dynamic))

        # Merge deterministic artifact findings and apply severity floors
        art_items = artifact_findings(art_reports)
        if art_items:
            report.findings.extend(art_items)
        art_floor = artifact_severity_floor(art_reports)
        if art_floor > report.risk_score:
            report.risk_score = round(max(report.risk_score, art_floor), 1)
            report.risk_label = (
                "Critical" if report.risk_score >= 8.0 else ("High" if report.risk_score >= 6.0 else "Medium")
            )

        report.meta["artifacts"] = [r.as_dict() for r in art_reports]
        report.meta["dynamic"] = dynamic.model_dump()
        report.meta["redactions"] = redactions
        if not (report.workflow and report.workflow.steps):
            report.workflow = derive_workflow(topology, report)

        report = map_to_taxonomy(report)
        emit({"type": "phase", "phase": "taxonomy", "status": "complete", "scan_id": scan_id})

        llm_ann = list(report.meta.get("annotated_code") or [])
        report.meta["annotated_code"] = merge_annotations(llm_ann, pattern_annotate(code_bundle))
        report.meta["sandbox"] = run_sandbox_smoke(str(ws.root))
        report.meta["target"] = target
        if ws.scan_scope:
            report.meta["scan_scope"] = ws.scan_scope
        if dynamic_logs:
            report.meta["dynamic_logs_included"] = True
        emit({"type": "phase", "phase": "sandbox", "status": "complete", "scan_id": scan_id})

        sources = _sources_from_target(target)

        record = ScanRecord(
            scan_id=scan_id,
            target=target,
            created_at=datetime.now(timezone.utc),
            status="completed",
            report=report,
            topology=topology,
            sources=sources,
        )
        _persist(record, topology)
        emit({"type": "phase", "phase": "persist", "status": "complete", "scan_id": scan_id})
        return record
    except Exception as e:
        logger.exception("Scan failed")
        err = ScanRecord(
            scan_id=scan_id,
            target=target,
            created_at=datetime.now(timezone.utc),
            status="failed",
            error=str(e),
            report=None,
            topology=None,
        )
        _persist_error(err, traceback.format_exc())
        emit({"type": "phase", "phase": "error", "status": "failed", "scan_id": scan_id, "error": str(e)})
        return err
    finally:
        if ws is not None:
            cleanup_workspace(ws)


def _sources_from_target(target: str) -> list[dict[str, str]]:
    t = target.strip()
    out: list[dict[str, str]] = []
    if is_hf_target(t):
        out.append({"kind": "huggingface", "label": t})
    elif t.startswith("http") and "github.com" in t:
        import re

        m = re.search(r"github\.com/([^/]+/[^/?#]+)", t, re.I)
        slug = m.group(1).rstrip("/") if m else "repo"
        out.append({"kind": "github", "label": slug})
    elif any(t.lower().endswith(ext) for ext in (".gguf", ".safetensors", ".bin", ".pt", ".exe", ".dll", ".so", ".dylib")):
        out.append({"kind": "artifact", "label": Path(t).name or t})
    else:
        out.append({"kind": "file", "label": target})
    out.append({"kind": "mcp", "label": "mcp-tools.json"})
    return out


def _persist(record: ScanRecord, topology: TopologyPayload) -> None:
    store = get_mongo_store()
    doc: dict[str, Any] = {
        "scan_id": record.scan_id,
        "target": record.target,
        "created_at": record.created_at,
        "status": record.status,
        "error": record.error,
        "sources": [dict(s) for s in record.sources],
    }
    if record.report:
        doc["report"] = record.report.model_dump(mode="json")
    if topology:
        doc["topology"] = topology.model_dump(mode="json")
    store.save_scan(doc)


def _persist_error(record: ScanRecord, tb: str) -> None:
    store = get_mongo_store()
    doc = {
        "scan_id": record.scan_id,
        "target": record.target,
        "created_at": record.created_at,
        "status": "failed",
        "error": record.error,
        "traceback": tb[:8000],
    }
    store.save_scan(doc)


def build_nutrition_stub(code_sample: str) -> NutritionLabel:
    """CLI-friendly re-export for tests."""
    return evaluate_intent(code_sample, [])


def _prepare_force_rescan(target: str, emit: Callable[[dict[str, Any]], None]) -> None:
    store = get_mongo_store()
    prior_scan_ids = store.list_scan_ids_by_target(target) if store.available else []
    emit(
        {
            "type": "phase",
            "phase": "force_rescan_prepare",
            "status": "complete",
            "target": target,
            "prior_scan_count": len(prior_scan_ids),
            "history_preserved": True,
            "note": "Force rescan will run fresh analysis without deleting previous scans.",
        }
    )


