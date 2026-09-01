"""REST API for scan lifecycle."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, stream_with_context
from werkzeug.utils import secure_filename

from config import settings
from engine.agents.ingestion import is_remote_target
from engine.database.mongo_client import get_mongo_store
from engine.database.neo4j_client import get_neo4j
from engine.orchestrator import run_scan
from engine.telemetry_links import build_telemetry_payload
from schemas.graph_nodes import TopologyPayload

logger = logging.getLogger(__name__)

bp = Blueprint("scans", __name__)


def _as_bool(raw, default: bool = False) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    txt = str(raw).strip().lower()
    if txt in ("1", "true", "yes", "on"):
        return True
    if txt in ("0", "false", "no", "off", ""):
        return False
    return default


def _gather_multipart_file_storages():
    """Collect uploaded parts with non-empty filenames; tolerate alternate field names."""
    if not request.files:
        return []
    preferred = ("files", "file", "files[]", "skill")
    lower_key = {k.lower(): k for k in request.files}
    seen: set[int] = set()
    out: list = []
    for name in preferred:
        key = lower_key.get(name.lower())
        if not key:
            continue
        for f in request.files.getlist(key):
            if not f or not f.filename:
                continue
            fid = id(f)
            if fid in seen:
                continue
            seen.add(fid)
            out.append(f)
        if out:
            return out
    for key in request.files:
        for f in request.files.getlist(key):
            if not f or not f.filename:
                continue
            fid = id(f)
            if fid in seen:
                continue
            seen.add(fid)
            out.append(f)
    return out


def _is_markdown_upload_name(raw: str) -> bool:
    base = secure_filename(Path(str(raw).replace("\\", "/")).name)
    return bool(base) and base.lower().endswith((".md", ".markdown"))


def _safe_upload_relative_path(raw: str) -> Path | None:
    cleaned = str(raw or "").replace("\\", "/").strip().lstrip("/")
    if not cleaned:
        return None
    parts = []
    for piece in cleaned.split("/"):
        piece = secure_filename(piece)
        if not piece or piece in (".", ".."):
            continue
        parts.append(piece)
    if not parts:
        return None
    rel = Path(*parts)
    if rel.is_absolute():
        return None
    return rel


def _is_folder_upload(parts: list) -> bool:
    if len(parts) > 1:
        return True
    for f in parts:
        raw = str(getattr(f, "filename", "") or "").replace("\\", "/")
        if "/" in raw:
            return True
    return False


def _save_uploaded_parts(tmp_dir: Path, parts: list) -> tuple[int, int]:
    saved_count = 0
    markdown_count = 0
    for f in parts:
        rel_path = _safe_upload_relative_path(getattr(f, "filename", ""))
        if rel_path is None:
            continue
        dst = (tmp_dir / rel_path).resolve()
        try:
            dst.relative_to(tmp_dir.resolve())
        except ValueError:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        f.save(str(dst))
        saved_count += 1
        if dst.suffix.lower() in (".md", ".markdown"):
            markdown_count += 1
    return saved_count, markdown_count


def _cleanup_upload_dir(tmp_dir: Path) -> None:
    shutil.rmtree(tmp_dir, ignore_errors=True)


def _local_target_error(target: str):
    """
    Local filesystem paths are a CLI-only affordance.

    Accepting them over HTTP would let any caller read `.py`/`.md`/`.json` files from
    the host and receive excerpts back in the report. Upload the content instead.
    """
    if is_remote_target(target):
        return None
    return (
        jsonify(
            {
                "error": (
                    "target must be a public GitHub repository URL "
                    "(https://github.com/owner/repo); upload files to scan local content"
                )
            }
        ),
        400,
    )


def _upload_count_error(parts: list):
    limit = int(settings.max_upload_files)
    if len(parts) <= limit:
        return None
    return jsonify({"error": f"too many files in upload (limit {limit})"}), 400


@bp.route("/scans", methods=["POST"])
def create_scan():
    """Accept JSON `{target: url|path}` or multipart file upload."""
    if request.is_json and request.json:
        target = (request.json.get("target") or "").strip()
        if not target:
            return jsonify({"error": "missing target"}), 400
        rejected = _local_target_error(target)
        if rejected:
            return rejected
        dynamic_logs = request.json.get("dynamic_logs")
        force_rescan = _as_bool(request.json.get("force_rescan"), False)
        if dynamic_logs is not None and not isinstance(dynamic_logs, str):
            dynamic_logs = json.dumps(dynamic_logs)
        elif isinstance(dynamic_logs, str):
            dynamic_logs = dynamic_logs.strip() or None
        record = run_scan(target, dynamic_logs=dynamic_logs, force_rescan=force_rescan)
        return _record_response(record), 201 if record.status == "completed" else 500

    if request.files:
        parts = _gather_multipart_file_storages()
        if not parts:
            return jsonify({"error": "missing file field `file` or `files`"}), 400
        too_many = _upload_count_error(parts)
        if too_many:
            return too_many
        is_folder_upload = _is_folder_upload(parts)
        if not is_folder_upload and len(parts) == 1 and not _is_markdown_upload_name(parts[0].filename):
            return jsonify({"error": "single file upload must be a .md/.markdown file"}), 400

        tmp_dir = Path(tempfile.mkdtemp(prefix="ig_upload_dir_"))
        try:
            saved_count, markdown_count = _save_uploaded_parts(tmp_dir, parts)
            if saved_count == 0:
                return jsonify({"error": "uploaded files were empty or invalid"}), 400
            if not is_folder_upload and markdown_count == 0:
                return jsonify({"error": "single file upload must be a .md/.markdown file"}), 400
            force_rescan = _as_bool(request.form.get("force_rescan"), False)
            record = run_scan(str(tmp_dir), force_rescan=force_rescan)
        finally:
            _cleanup_upload_dir(tmp_dir)
        return _record_response(record), 201 if record.status == "completed" else 500

    return jsonify({"error": "expected JSON body or multipart file"}), 400


@bp.route("/scans", methods=["GET"])
def list_scans():
    store = get_mongo_store()
    rows = store.list_scans()
    slim = [
        {
            "scan_id": r.get("scan_id"),
            "target": r.get("target"),
            "created_at": r.get("created_at").isoformat() if r.get("created_at") else None,
            "status": r.get("status"),
        }
        for r in rows
    ]
    return jsonify({"scans": slim})


@bp.route("/scans/<scan_id>/report", methods=["GET"])
def get_report(scan_id: str):
    store = get_mongo_store()
    doc = store.get_scan(scan_id)
    if not doc:
        return jsonify({"error": "not found"}), 404
    if doc.get("status") == "failed":
        return jsonify({"scan_id": scan_id, "status": "failed", "error": doc.get("error")}), 200
    return jsonify({"scan_id": scan_id, "report": doc.get("report"), "sources": doc.get("sources", [])})


@bp.route("/scans/<scan_id>/topology", methods=["GET"])
def get_topology(scan_id: str):
    include_tests = str(request.args.get("include_tests", "false")).lower() in ("1", "true", "yes", "on")
    only_paths = str(request.args.get("only_paths", "true")).lower() not in ("0", "false", "no", "off")
    debug = str(request.args.get("debug", "false")).lower() in ("1", "true", "yes", "on")
    try:
        depth = int(request.args.get("depth", 4))
    except ValueError:
        depth = 4
    try:
        limit = int(request.args.get("limit", 500))
    except ValueError:
        limit = 500
    effective_limit = min(limit, 300) if debug else limit
    neo = get_neo4j()
    if neo.available:
        topo = neo.read_topology(
            scan_id,
            include_tests=include_tests,
            only_paths_of_interest=only_paths,
            debug=debug,
            depth=depth,
            limit=effective_limit,
        )
        if topo:
            return jsonify(topo.model_dump(mode="json"))

    store = get_mongo_store()
    doc = store.get_scan(scan_id)
    if not doc:
        return jsonify({"error": "not found"}), 404
    raw = doc.get("topology")
    if not raw:
        return jsonify({"nodes": [], "edges": []})
    topo = TopologyPayload.model_validate(raw)
    topo = _filter_topology_payload(
        topo,
        include_tests=include_tests,
        only_paths=only_paths and not debug,
        limit=effective_limit,
    )
    return jsonify(topo.model_dump(mode="json"))


@bp.route("/scans/<scan_id>/telemetry", methods=["GET"])
def get_telemetry(scan_id: str):
    """
    Returns ready-made deep-link URLs for LangSmith and Helicone dashboards.
    Uses scan metadata (`scan_id`, `target`, optional created_at) for pre-filtered views.
    """
    store = get_mongo_store()
    doc = store.get_scan(scan_id)
    if not doc:
        return jsonify({"error": "not found"}), 404

    target = str(doc.get("target") or "")
    created_at = doc.get("created_at")
    created_iso = created_at.isoformat() if created_at else None
    telemetry = build_telemetry_payload(scan_id=scan_id, target=target, created_at_iso=created_iso)
    return jsonify(telemetry)


def _record_response(record):
    base = {
        "scan_id": record.scan_id,
        "target": record.target,
        "status": record.status,
        "created_at": record.created_at.isoformat(),
    }
    if record.status == "failed":
        base["error"] = record.error
        return base
    base["report"] = record.report.model_dump(mode="json") if record.report else None
    base["topology"] = record.topology.model_dump(mode="json") if record.topology else None
    return base


def _filter_topology_payload(
    topo: TopologyPayload,
    *,
    include_tests: bool,
    only_paths: bool,
    limit: int,
) -> TopologyPayload:
    nodes = topo.nodes
    edges = topo.edges
    if not include_tests:
        keep_ids = {
            n.id
            for n in nodes
            if not (
                n.path
                and any(
                    t in n.path.lower().replace("\\", "/")
                    for t in ("/tests/", "/test_", "/mock_", "/conftest.py")
                )
            )
        }
        nodes = [n for n in nodes if n.id in keep_ids]
        edges = [e for e in edges if e.source in keep_ids and e.target in keep_ids]
    if only_paths:
        seed_ids = (
            {n.id for n in nodes if n.kind == "external"}
            | {n.id for n in nodes if n.kind == "source"}
            | {n.id for n in nodes if n.kind in ("agent", "tool")}
            | {n.id for n in nodes if n.is_source}
        )
        neighbor_ids = set(seed_ids)
        for e in edges:
            if e.source in seed_ids or e.target in seed_ids:
                neighbor_ids.add(e.source)
                neighbor_ids.add(e.target)
        nodes = [n for n in nodes if n.id in neighbor_ids]
        edges = [e for e in edges if e.source in neighbor_ids and e.target in neighbor_ids]
    nodes = nodes[: max(10, min(int(limit), 1000))]
    node_ids = {n.id for n in nodes}
    edges = [e for e in edges if e.source in node_ids and e.target in node_ids][: max(20, min(int(limit) * 3, 3000))]
    return TopologyPayload(nodes=nodes, edges=edges)


def _sse_format(data: dict) -> str:
    return f"data: {json.dumps(data, default=str)}\n\n"


def _scan_stream_from_target(target: str, dynamic_logs: str | None, force_rescan: bool = False):
    """Generator yielding SSE frames for a scan (runs pipeline in a worker thread)."""
    import queue
    import threading
    import time

    q: queue.Queue = queue.Queue(maxsize=500)

    def emit(ev: dict) -> None:
        try:
            q.put(ev, timeout=30)
        except Exception:
            logger.debug("scan stream queue full or closed", exc_info=True)

    def worker() -> None:
        try:
            record = run_scan(target, dynamic_logs=dynamic_logs, on_event=emit, force_rescan=force_rescan)
            emit({"type": "scan_complete", "record": _record_response(record)})
        except Exception as e:
            logger.exception("streamed scan failed")
            emit({"type": "scan_failed", "error": str(e)})

    threading.Thread(target=worker, name="intentguard-scan-stream", daemon=True).start()

    while True:
        try:
            item = q.get(timeout=30)
        except queue.Empty:
            yield _sse_format({"type": "heartbeat", "ts": time.time()})
            continue
        yield _sse_format(item)
        if item.get("type") in ("scan_complete", "scan_failed"):
            break


@bp.route("/scans/stream", methods=["POST"])
def create_scan_stream():
    """
    Server-Sent Events: live scan phases + LangGraph LLM step markers + telemetry links.
    JSON body same as POST /api/scans, or multipart folder upload same as POST /api/scans.
    """
    if request.is_json and request.json:
        target = (request.json.get("target") or "").strip()
        if not target:
            return jsonify({"error": "missing target"}), 400
        rejected = _local_target_error(target)
        if rejected:
            return rejected
        dynamic_logs = request.json.get("dynamic_logs")
        if dynamic_logs is not None and not isinstance(dynamic_logs, str):
            dynamic_logs = json.dumps(dynamic_logs)
        elif isinstance(dynamic_logs, str):
            dynamic_logs = dynamic_logs.strip() or None
        force_rescan = _as_bool(request.json.get("force_rescan"), False)

        return Response(
            stream_with_context(_scan_stream_from_target(target, dynamic_logs, force_rescan=force_rescan)),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    if request.files:
        parts = _gather_multipart_file_storages()
        if not parts:
            return jsonify({"error": "missing file field `file` or `files`"}), 400
        too_many = _upload_count_error(parts)
        if too_many:
            return too_many
        is_folder_upload = _is_folder_upload(parts)
        if not is_folder_upload and len(parts) == 1 and not _is_markdown_upload_name(parts[0].filename):
            return jsonify({"error": "single file upload must be a .md/.markdown file"}), 400

        tmp_dir = Path(tempfile.mkdtemp(prefix="ig_upload_dir_"))
        try:
            saved_count, markdown_count = _save_uploaded_parts(tmp_dir, parts)
            if saved_count == 0:
                return jsonify({"error": "uploaded files were empty or invalid"}), 400
            if not is_folder_upload and markdown_count == 0:
                return jsonify({"error": "single file upload must be a .md/.markdown file"}), 400
            target_path = str(tmp_dir)

            def gen_folder():
                try:
                    force_rescan = _as_bool(request.form.get("force_rescan"), False)
                    yield from _scan_stream_from_target(target_path, None, force_rescan=force_rescan)
                finally:
                    _cleanup_upload_dir(tmp_dir)

            return Response(
                stream_with_context(gen_folder()),
                mimetype="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )
        except Exception:
            _cleanup_upload_dir(tmp_dir)
            raise

    return jsonify({"error": "expected JSON body or multipart file"}), 400
