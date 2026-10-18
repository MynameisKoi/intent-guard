"""Normalize repository URLs and local paths into a workspace on disk."""

import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import get_settings
from engine.agents.manifest_parser import AgentMarkdownManifest, collect_agent_manifests
from engine.agents.scope import classify_rel, is_excluded_dir, is_excluded_rel

from engine.artifacts.detect import detect_kind, is_candidate
from engine.artifacts.huggingface import fetch_hf_repo, is_hf_target

logger = logging.getLogger(__name__)


_GITHUB_RE = re.compile(
    r"^(https?://github\.com/[^/]+/[^/]+)(?:\.git)?/?$",
    re.IGNORECASE,
)


@dataclass
class Workspace:
    root: Path
    """Temporary directory for remote clones, or the resolved directory for local paths."""

    target: str
    """Original target string from the user."""

    files: list[Path] = field(default_factory=list)
    """Files considered for static analysis."""

    agent_manifests: list[AgentMarkdownManifest] = field(default_factory=list)
    """Markdown files with YAML frontmatter treated as prompt-only agent definitions."""

    cleanup: bool = False
    """If True, delete root on context manager exit (used for git clones / HF scratch)."""

    scan_scope: dict[str, Any] = field(default_factory=dict)
    """Counts of scanned/skipped files and the scope mix, surfaced in the report."""

    artifact_reports: list[Any] = field(default_factory=list)
    """Pre-computed artifact reports (e.g. from Hugging Face model card/weight audits)."""

    artifact_files: list[Path] = field(default_factory=list)
    """Candidate binary or model weight files for artifact inspection."""

    target_type: str = "repo"
    """Classification of target: 'github', 'huggingface', 'local_repo', 'artifact', etc."""


_SCAN_EXTENSIONS = (".py", ".md", ".json")


def _collect_files(root: Path) -> tuple[list[Path], dict[str, Any]]:
    """Walk `root` for analyzable files, pruning vendored and generated content."""
    max_bytes = int(get_settings().scan_max_file_bytes)
    files: list[Path] = []
    skipped = {"pruned_dirs": 0, "excluded_files": 0, "oversized_files": 0}
    for dirpath, dirnames, filenames in os.walk(root):
        keep = [d for d in dirnames if not is_excluded_dir(d)]
        skipped["pruned_dirs"] += len(dirnames) - len(keep)
        dirnames[:] = keep
        base = Path(dirpath)
        for filename in filenames:
            candidate = base / filename
            if candidate.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            try:
                rel = candidate.relative_to(root).as_posix()
            except ValueError:
                rel = filename
            if is_excluded_rel(rel):
                skipped["excluded_files"] += 1
                continue
            try:
                if max_bytes > 0 and candidate.stat().st_size > max_bytes:
                    skipped["oversized_files"] += 1
                    continue
            except OSError:
                continue
            files.append(candidate)
    files = sorted({p.resolve() for p in files})
    return files, skipped


def _collect_artifact_files(root: Path) -> list[Path]:
    """Find candidate model weights or binary files in `root`."""
    artifacts: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not is_excluded_dir(d)]
        base = Path(dirpath)
        for filename in filenames:
            candidate = base / filename
            try:
                rel = candidate.relative_to(root).as_posix()
            except ValueError:
                rel = filename
            if is_excluded_rel(rel):
                continue
            if is_candidate(candidate):
                artifacts.append(candidate.resolve())
    return sorted(set(artifacts))


def _scan_scope_summary(root: Path, files: list[Path], skipped: dict[str, Any]) -> dict[str, Any]:
    scopes: Counter[str] = Counter()
    for path in files:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        scopes[classify_rel(rel)] += 1
    return {"files_scanned": len(files), "scopes": dict(scopes), "skipped": skipped}


def _is_remote_github(target: str) -> bool:
    t = target.strip()
    return bool(re.match(r"^(https?://)?github\.com/[^/]+/[^/]+/?$", t, re.IGNORECASE))


def is_remote_target(target: str) -> bool:
    """Public check used by the HTTP layer, allowing GitHub repositories and Hugging Face models."""
    t = target.strip()
    return _is_remote_github(t) or is_hf_target(t)


def _normalize_github_target(target: str) -> str:
    t = target.strip()
    if re.match(r"^github\.com/[^/]+/[^/]+/?$", t, re.IGNORECASE):
        return f"https://{t}"
    return t


def ingest(target: str) -> Workspace:
    t = target.strip()
    if is_hf_target(t):
        ctx = fetch_hf_repo(t)
        files, skipped = _collect_files(ctx.root)
        artifact_files = _collect_artifact_files(ctx.root)
        manifests = collect_agent_manifests(files, ctx.root)
        return Workspace(
            root=ctx.root,
            target=t,
            files=files,
            agent_manifests=manifests,
            cleanup=True,
            scan_scope=_scan_scope_summary(ctx.root, files, skipped),
            artifact_reports=ctx.reports,
            artifact_files=artifact_files + ctx.binary_paths,
            target_type="huggingface",
        )

    t = _normalize_github_target(t)
    if _is_remote_github(t):
        return _clone_github(t)

    path = Path(t).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {t}")

    if path.is_file():
        kind = detect_kind(path)
        is_art = bool(kind) or is_candidate(path)
        is_source = path.suffix.lower() in _SCAN_EXTENSIONS
        files = [path] if is_source else []
        artifacts = [path] if is_art else []
        root = path.parent
        manifests = collect_agent_manifests(files, root) if files else []
        return Workspace(
            root=root,
            target=t,
            files=files,
            agent_manifests=manifests,
            cleanup=False,
            scan_scope={"files_scanned": len(files), "scopes": {"production": 1}, "skipped": {}},
            artifact_files=artifacts,
            target_type="artifact" if (is_art and not is_source) else "file",
        )

    root = path
    files, skipped = _collect_files(root)
    artifact_files = _collect_artifact_files(root)
    manifests = collect_agent_manifests(files, root)
    return Workspace(
        root=root,
        target=t,
        files=files,
        agent_manifests=manifests,
        cleanup=False,
        scan_scope=_scan_scope_summary(root, files, skipped),
        artifact_files=artifact_files,
        target_type="local_repo",
    )


def _clone_github(url: str) -> Workspace:
    m = _GITHUB_RE.match(url.strip().rstrip("/"))
    if not m:
        raise ValueError(f"Unsupported GitHub URL format: {url}")
    base = m.group(1)
    tmp = Path(tempfile.mkdtemp(prefix="ig_clone_"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", base + ".git", str(tmp)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {e}") from e

    files, skipped = _collect_files(tmp)
    artifact_files = _collect_artifact_files(tmp)
    manifests = collect_agent_manifests(files, tmp)
    logger.info(
        "Ingested GitHub repo into %s (%s files, %s artifacts, skipped %s)",
        tmp,
        len(files),
        len(artifact_files),
        skipped,
    )
    return Workspace(
        root=tmp,
        target=url,
        files=files,
        agent_manifests=manifests,
        cleanup=True,
        scan_scope=_scan_scope_summary(tmp, files, skipped),
        artifact_files=artifact_files,
        target_type="github",
    )


def cleanup_workspace(ws: Workspace) -> None:
    if ws.cleanup and ws.root.exists():
        shutil.rmtree(ws.root, ignore_errors=True)
