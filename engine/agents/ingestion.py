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
    """If True, delete root on context manager exit (used for git clones)."""

    scan_scope: dict[str, Any] = field(default_factory=dict)
    """Counts of scanned/skipped files and the scope mix, surfaced in the report."""


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
    """Public check used by the HTTP layer, where local paths are not acceptable targets."""
    return _is_remote_github(target)


def _normalize_github_target(target: str) -> str:
    t = target.strip()
    if re.match(r"^github\.com/[^/]+/[^/]+/?$", t, re.IGNORECASE):
        return f"https://{t}"
    return t


def ingest(target: str) -> Workspace:
    t = _normalize_github_target(target)
    if _is_remote_github(t):
        return _clone_github(t)
    path = Path(t).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {t}")
    if path.is_file():
        files = [path]
        root = path.parent
        manifests = collect_agent_manifests(files, root)
        return Workspace(
            root=root,
            target=t,
            files=files,
            agent_manifests=manifests,
            cleanup=False,
            scan_scope={"files_scanned": 1, "scopes": {"production": 1}, "skipped": {}},
        )
    root = path
    files, skipped = _collect_files(root)
    manifests = collect_agent_manifests(files, root)
    return Workspace(
        root=root,
        target=t,
        files=files,
        agent_manifests=manifests,
        cleanup=False,
        scan_scope=_scan_scope_summary(root, files, skipped),
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
    manifests = collect_agent_manifests(files, tmp)
    logger.info("Ingested GitHub repo into %s (%s files, skipped %s)", tmp, len(files), skipped)
    return Workspace(
        root=tmp,
        target=url,
        files=files,
        agent_manifests=manifests,
        cleanup=True,
        scan_scope=_scan_scope_summary(tmp, files, skipped),
    )


def cleanup_workspace(ws: Workspace) -> None:
    if ws.cleanup and ws.root.exists():
        shutil.rmtree(ws.root, ignore_errors=True)
