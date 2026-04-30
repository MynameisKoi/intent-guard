"""Normalize repository URLs and local paths into a workspace on disk."""

import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from engine.agents.manifest_parser import AgentMarkdownManifest, collect_agent_manifests

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


def _is_remote_github(target: str) -> bool:
    t = target.strip()
    return bool(re.match(r"^(https?://)?github\.com/[^/]+/[^/]+/?$", t, re.IGNORECASE))


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
        return Workspace(root=root, target=t, files=files, agent_manifests=manifests, cleanup=False)
    else:
        root = path
        files = []
        for ext in ("*.py", "*.md", "*.json"):
            files.extend(root.rglob(ext))
        files = sorted({p.resolve() for p in files if p.is_file()})
    manifests = collect_agent_manifests(files, root)
    return Workspace(root=root, target=t, files=files, agent_manifests=manifests, cleanup=False)


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

    files: list[Path] = []
    for ext in ("*.py", "*.md", "*.json"):
        files.extend(tmp.rglob(ext))
    files = sorted({p for p in files if p.is_file()})
    manifests = collect_agent_manifests(files, tmp)
    logger.info("Ingested GitHub repo into %s (%s files)", tmp, len(files))
    return Workspace(root=tmp, target=url, files=files, agent_manifests=manifests, cleanup=True)


def cleanup_workspace(ws: Workspace) -> None:
    if ws.cleanup and ws.root.exists():
        shutil.rmtree(ws.root, ignore_errors=True)
