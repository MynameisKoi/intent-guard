"""Path scope classification shared by ingestion, tracing, annotation, and scoring.

Repositories routinely contain vendored dependencies, lockfiles, intentional
honeypot samples, and setup documentation. Scoring those as production agent
behaviour is the dominant source of false positives, so the decision is made
once here and reused everywhere.
"""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath

from config import get_settings

PRODUCTION = "production"
FIXTURE = "fixture"
DOCS = "docs"

_DOC_FILENAMES = frozenset(
    {
        "readme.md",
        "readme.markdown",
        "contributing.md",
        "changelog.md",
        "license.md",
        "code_of_conduct.md",
        "security.md",
    }
)
_DOC_DIRS = frozenset({"docs", "doc", "documentation", "wiki"})


def _csv(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in str(raw or "").split(",") if part.strip())


def normalize_rel(rel: str) -> str:
    text = str(rel or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def excluded_dir_names() -> frozenset[str]:
    return frozenset(name.lower() for name in _csv(get_settings().scan_exclude_dirs))


def excluded_file_globs() -> tuple[str, ...]:
    return _csv(get_settings().scan_exclude_globs)


def fixture_dir_names() -> frozenset[str]:
    return frozenset(name.lower() for name in _csv(get_settings().scan_fixture_dirs))


def is_excluded_dir(name: str) -> bool:
    return str(name or "").lower() in excluded_dir_names()


def is_excluded_rel(rel: str) -> bool:
    """True when a workspace-relative path should never reach the analysis pipeline."""
    normalized = normalize_rel(rel)
    if not normalized:
        return True
    parts = PurePosixPath(normalized).parts
    if any(is_excluded_dir(part) for part in parts[:-1]):
        return True
    name = parts[-1].lower()
    return any(fnmatch.fnmatch(name, glob.lower()) for glob in excluded_file_globs())


def classify_rel(rel: str) -> str:
    """Return PRODUCTION, FIXTURE, or DOCS for a workspace-relative path."""
    normalized = normalize_rel(rel)
    if not normalized:
        return PRODUCTION
    path = PurePosixPath(normalized)
    directories = [part.lower() for part in path.parts[:-1]]
    fixtures = fixture_dir_names()
    if any(directory in fixtures for directory in directories):
        return FIXTURE
    if any(directory in _DOC_DIRS for directory in directories):
        return DOCS
    name = path.name.lower()
    if name in _DOC_FILENAMES:
        return DOCS
    # Repo-meta markdown is conventionally upper-case (FINALTEST.md, REALTEST.md);
    # agent skills such as pentest.md are not, so casing keeps the two apart.
    if name.endswith((".md", ".markdown")) and len(path.stem) > 2 and path.stem.isupper():
        return DOCS
    return PRODUCTION


def counts_toward_score(scope: str) -> bool:
    if scope == PRODUCTION:
        return True
    return bool(get_settings().score_fixtures_in_aggregate)
