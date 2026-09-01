"""Pattern-based code annotations for UI (merged with LLM semantic rows)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from engine.agents.scope import classify_rel, normalize_rel

_HEADER_RE = re.compile(r"^===\s+(.+?)\s+===$")
_COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*\s)")
_C_STYLE_COMMENT_RE = re.compile(r"^\s*(//|/\*|\*\s)")
_MARKDOWN_SUFFIXES = (".md", ".markdown", ".mdx")
# A rule-table row ends with a quoted severity, e.g. ("shell=True", "note", "high"),
_RULE_TABLE_RE = re.compile(r"""["'](low|medium|high)["']\s*\)?\s*,?\s*$""", re.I)
_REGEX_DEF_RE = re.compile(r"re\.(compile|search|match|findall|finditer)\s*\(")
_STRING_MEMBERSHIP_RE = re.compile(r"""["'][^"']+["']\s+(?:not\s+)?in\s+\w""")
_MESSAGE_CALL_RE = re.compile(
    r"\b(?:raise\s+\w*(?:Error|Exception)|logger\.\w+|logging\.\w+|print|warnings\.warn)\s*\("
)
_LOOPBACK_URL_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|[^/\s]*\bexample\.(?:com|org|net)\b)", re.I
)
_MAX_URL_ROWS = 5


def _normalize_key_text(value: Any, *, limit: int) -> str:
    return " ".join(str(value or "").strip().lower().split())[:limit]


def _row_from(raw: dict[str, Any], *, file_name: str) -> dict[str, Any]:
    line = raw.get("line", 0)
    severity = str(raw.get("severity") or "medium").lower()
    if severity not in ("low", "medium", "high"):
        severity = "medium"
    scope = str(raw.get("scope") or "") or classify_rel(file_name)
    return {
        "line": int(line) if isinstance(line, (int, float)) and line >= 0 else 0,
        "code": str(raw.get("code") or "")[:300],
        "annotation": str(raw.get("annotation") or "")[:500],
        "severity": severity,
        "file": file_name,
        "scope": scope,
    }


def merge_annotations(*lists: list[dict[str, Any]], limit: int = 150) -> list[dict[str, Any]]:
    """Dedupe by file + vuln signature; preserve order (earlier lists win)."""
    seen: dict[tuple[str, str], int] = {}
    out: list[dict[str, Any]] = []
    for lst in lists:
        for row in lst or []:
            # Tracer paths are OS-native while LLM rows use posix separators; without
            # normalizing, the same finding survives dedupe twice.
            file_name = (normalize_rel(str(row.get("file") or "")) or "unknown")[:220]
            ann = _normalize_key_text(row.get("annotation"), limit=200)
            key = (file_name, ann)
            if key in seen:
                continue
            # If we previously captured this vulnerability as unknown, replace it with file-specific row.
            if file_name != "unknown":
                unknown_key = ("unknown", ann)
                if unknown_key in seen:
                    out_idx = seen[unknown_key]
                    seen.pop(unknown_key, None)
                    seen[key] = out_idx
                    out[out_idx] = _row_from(row, file_name=file_name)
                    continue
            seen[key] = len(out)
            out.append(_row_from(row, file_name=file_name))
            if len(out) >= limit:
                return out
    return out


def file_from_bundle_header(text: str) -> str | None:
    """Return the path from a `=== path ===` bundle header, stripping any label prefix."""
    header = _HEADER_RE.match(text.strip())
    if not header:
        return None
    label = header.group(1).strip()
    # Agent snippets are headed `=== AGENT MARKDOWN (...): path ===`.
    if ": " in label:
        label = label.rsplit(": ", 1)[-1].strip()
    return normalize_rel(label) or "unknown"


def is_noise_line(text: str, *, hash_is_comment: bool = True) -> bool:
    """
    True for lines that describe security patterns rather than perform them.

    Scanning a security tool (or any repo with a rule table, allowlist, or error
    message naming a risky API) otherwise reports the detector as the vulnerability.

    In Markdown, `#` starts a heading, not a comment, so `hash_is_comment` must
    be False or injection text in headings is silently dropped.
    """
    stripped = text.strip()
    if not stripped:
        return True
    if hash_is_comment:
        if _COMMENT_RE.match(stripped):
            return True
    elif _C_STYLE_COMMENT_RE.match(stripped):
        return True
    if _REGEX_DEF_RE.search(stripped):
        return True
    if _RULE_TABLE_RE.search(stripped):
        return True
    if _STRING_MEMBERSHIP_RE.search(stripped):
        return True
    return bool(_MESSAGE_CALL_RE.search(stripped))


def _token_is_invoked(line: str, token: str) -> bool:
    """True when a call-like token is actually called rather than quoted as data."""
    for match in re.finditer(re.escape(token), line):
        tail = line[match.end() :].lstrip()
        if tail.startswith("("):
            return True
    return False


def iter_bundle_lines(code_bundle: str) -> Iterator[tuple[int, str, str, str]]:
    """
    Yield `(line_no, file, scope, line)` for behaviourally meaningful bundle lines.

    Bundle headers, Python docstrings, comments, and detector definitions are
    dropped here so annotation and scoring never disagree about what counts.
    Markdown headings (`# ...`) are kept: they are content, not comments.
    """
    current_file = "unknown"
    current_scope = classify_rel(current_file)
    is_python = False
    is_markdown = False
    in_docstring = False
    for idx, line in enumerate(code_bundle.splitlines(), start=1):
        header = file_from_bundle_header(line)
        if header:
            current_file = header
            current_scope = classify_rel(current_file)
            lower = current_file.lower()
            is_python = lower.endswith(".py")
            is_markdown = lower.endswith(_MARKDOWN_SUFFIXES)
            in_docstring = False
            continue
        text = line.strip()
        if not text:
            continue
        if is_python:
            fences = text.count('"""') + text.count("'''")
            if in_docstring:
                if fences:
                    in_docstring = False
                continue
            if fences % 2:
                in_docstring = True
                continue
        if is_noise_line(text, hash_is_comment=not is_markdown):
            continue
        yield idx, current_file, current_scope, line


def pattern_annotate(code_bundle: str, *, max_items: int = 120) -> list[dict[str, Any]]:
    """
    Fast line-level highlights for Python, Markdown, YAML, and shell snippets in the bundle.
    Complements LLM `annotated_code` when the model omits rows or for heuristic-only scans.
    """
    # (token, note, severity, call_like) — call_like tokens only count when invoked.
    literal_patterns: list[tuple[str, str, str, bool]] = [
        ("shell=True", "Prompt-injection-to-shell risk", "high", False),
        ("subprocess.run", "External command execution", "high", True),
        ("subprocess.Popen", "External command execution", "high", True),
        ("subprocess.call", "External command execution", "high", True),
        ("os.system", "Shell execution surface", "high", True),
        ("requests.post", "Outbound HTTP write (possible exfiltration)", "high", True),
        ("requests.put", "Outbound HTTP write (possible exfiltration)", "high", True),
        ("httpx.post", "Outbound HTTP write (possible exfiltration)", "high", True),
        ("urllib.request", "Outbound HTTP / URL fetch", "medium", False),
        ("aiohttp", "Async outbound network I/O", "medium", False),
        ("fetch_env_vars", "Environment secret access", "high", False),
        ("AWS_ACCESS_KEY_ID", "Cloud credential reference", "high", False),
        ("DATABASE_URL", "Database secret reference", "medium", False),
        ("OPENAI_API_KEY", "API key reference in code or docs", "high", False),
        ("ANTHROPIC_API_KEY", "API key reference in code or docs", "high", False),
        ("Bearer ", "Token-style authorization string", "medium", False),
        ("/.ssh", "Sensitive filesystem scope", "medium", False),
        ("/etc/shadow", "Sensitive system path reference", "high", False),
        ("/etc/passwd", "Sensitive system path reference", "high", False),
        ("/var/log", "Log scraping behavior", "low", False),
        ("timeout=None", "No timeout on network request", "medium", False),
        ("eval(", "Dynamic code evaluation", "high", False),
        ("exec(", "Dynamic code execution", "high", False),
        ("pickle.loads", "Unsafe deserialization pattern", "high", True),
        ("yaml.load(", "YAML load may be unsafe without safe_load", "medium", False),
        ("docker ", "Container / runtime invocation in docs or scripts", "medium", False),
        ("kubectl ", "Cluster control command in docs or scripts", "high", False),
        ("curl ", "Shell HTTP client in documentation or scripts", "medium", False),
        ("wget ", "Shell download in documentation or scripts", "medium", False),
        ("pip install", "Supply-chain / dependency install surface", "low", False),
        ("chmod +x", "Executable permission change", "low", False),
        ("rm -rf", "Destructive filesystem command", "high", False),
    ]

    regex_patterns: list[tuple[re.Pattern[str], str, str]] = [
        (re.compile(r"```\s*(bash|sh|zsh|powershell)\b", re.I), "Executable shell block in Markdown", "medium"),
        (re.compile(r"\bcurl\s+", re.I), "curl usage (network egress)", "medium"),
        (re.compile(r"\bwget\s+", re.I), "wget usage (network egress)", "medium"),
        (re.compile(r"api[_-]?key\s*[:=]\s*[\"'][^\"']", re.I), "API key assignment or documentation", "high"),
        (
            re.compile(r"(secret|password|passwd|token)\s*[:=]\s*[\"'][^\"']|=\s*[\"'](password|changeme|secret|admin)[\"']", re.I),
            "Secret-like configuration",
            "medium",
        ),
        (re.compile(r"https?://[^\s`'\"<>]+", re.I), "Outbound URL reference", "low"),
        (re.compile(r"\bplugin\b|\btool\b.*\b(api|http)\b", re.I), "Agent tool / plugin surface", "medium"),
    ]

    out: list[dict[str, Any]] = []
    url_rows = 0

    def append(line_no: int, file_name: str, scope: str, text: str, note: str, severity: str) -> None:
        out.append(
            {
                "line": line_no,
                "file": file_name,
                "scope": scope,
                "code": text[:300],
                "annotation": note,
                "severity": severity,
            }
        )

    for idx, file_name, scope, line in iter_bundle_lines(code_bundle):
        text = line.strip()
        matched = False
        for token, note, severity, call_like in literal_patterns:
            if token not in line:
                continue
            if call_like and not _token_is_invoked(line, token):
                continue
            append(idx, file_name, scope, text, note, severity)
            matched = True
            break
        if matched:
            if len(out) >= max_items:
                break
            continue

        for rx, note, severity in regex_patterns:
            if not rx.search(line):
                continue
            if note == "Outbound URL reference":
                if _LOOPBACK_URL_RE.search(line) or url_rows >= _MAX_URL_ROWS:
                    break
                url_rows += 1
            append(idx, file_name, scope, text, note, severity)
            break
        if len(out) >= max_items:
            break
    return out
