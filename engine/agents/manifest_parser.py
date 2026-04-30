"""YAML frontmatter + Markdown body for prompt-only agent repositories."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import frontmatter
import yaml

logger = logging.getLogger(__name__)


@dataclass
class AgentMarkdownManifest:
    """Parsed agent skill / prompt file (--- YAML --- then Markdown body)."""

    rel_path: str
    name: str
    tools: list[str] = field(default_factory=list)
    permissions: Any = None
    model: str | None = None
    frontmatter: dict[str, Any] = field(default_factory=dict)
    system_prompt: str = ""


def _normalize_tools_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            for key in ("name", "id", "tool", "type"):
                v = item.get(key)
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
                    break
            else:
                if len(item) == 1:
                    v = next(iter(item.values()))
                    if isinstance(v, str) and v.strip():
                        out.append(v.strip())
    return out


def parse_agent_markdown_file(path: Path, root: Path) -> AgentMarkdownManifest | None:
    """
    If `path` is a Markdown file with YAML frontmatter (--- ... ---), parse it.
    Treats the file as an agent manifest when frontmatter includes at least one of:
    `name`, `model`, or `tools`.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("Could not read %s: %s", path, e)
        return None
    stripped = raw.lstrip("\ufeff")
    if not stripped.startswith("---"):
        return None
    try:
        post = frontmatter.loads(raw)
    except (yaml.YAMLError, ValueError, OSError) as e:
        logger.warning("Skipping malformed markdown frontmatter in %s: %s", path, e)
        return None
    meta = post.metadata
    if not isinstance(meta, dict):
        return None
    if not any(k in meta for k in ("name", "model", "tools")):
        return None
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    name = str(meta.get("name") or path.stem).strip() or path.stem
    tools = _normalize_tools_list(meta.get("tools"))
    model = meta.get("model")
    model_s = str(model).strip() if model not in (None, "") else None
    perms = meta.get("permissions")
    return AgentMarkdownManifest(
        rel_path=rel.replace("\\", "/"),
        name=name,
        tools=tools,
        permissions=perms,
        model=model_s,
        frontmatter=dict(meta),
        system_prompt=str(post.content or "").strip(),
    )


def collect_agent_manifests(files: list[Path], root: Path) -> list[AgentMarkdownManifest]:
    out: list[AgentMarkdownManifest] = []
    for fp in files:
        if fp.suffix.lower() != ".md":
            continue
        m = parse_agent_markdown_file(fp, root)
        if m:
            out.append(m)
    return out
