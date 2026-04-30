"""Pattern-based code annotations for UI (merged with LLM semantic rows)."""

from __future__ import annotations

import re
from typing import Any


def _normalize_key_text(value: Any, *, limit: int) -> str:
    return " ".join(str(value or "").strip().lower().split())[:limit]


def merge_annotations(*lists: list[dict[str, Any]], limit: int = 150) -> list[dict[str, Any]]:
    """Dedupe by file + vuln signature; preserve order (earlier lists win)."""
    seen: dict[tuple[str, str], int] = {}
    out: list[dict[str, Any]] = []
    for lst in lists:
        for row in lst or []:
            line = row.get("line", 0)
            file_name = str(row.get("file") or "unknown")[:220]
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
                    out[out_idx] = {
                        "line": int(line) if isinstance(line, (int, float)) and line >= 0 else 0,
                        "code": str(row.get("code") or "")[:300],
                        "annotation": str(row.get("annotation") or "")[:500],
                        "severity": str(row.get("severity") or "medium").lower()
                        if str(row.get("severity") or "medium").lower() in ("low", "medium", "high")
                        else "medium",
                        "file": file_name,
                    }
                    continue
            sev = str(row.get("severity") or "medium").lower()
            if sev not in ("low", "medium", "high"):
                sev = "medium"
            seen[key] = len(out)
            out.append(
                {
                    "line": int(line) if isinstance(line, (int, float)) and line >= 0 else 0,
                    "code": str(row.get("code") or "")[:300],
                    "annotation": str(row.get("annotation") or "")[:500],
                    "severity": sev,
                    "file": file_name,
                }
            )
            if len(out) >= limit:
                return out
    return out


def pattern_annotate(code_bundle: str, *, max_items: int = 120) -> list[dict[str, Any]]:
    """
    Fast line-level highlights for Python, Markdown, YAML, and shell snippets in the bundle.
    Complements LLM `annotated_code` when the model omits rows or for heuristic-only scans.
    """
    literal_patterns: list[tuple[str, str, str]] = [
        ("shell=True", "Prompt-injection-to-shell risk", "high"),
        ("subprocess.run", "External command execution", "high"),
        ("subprocess.Popen", "External command execution", "high"),
        ("os.system", "Shell execution surface", "high"),
        ("requests.post", "Outbound HTTP write (possible exfiltration)", "high"),
        ("requests.put", "Outbound HTTP write (possible exfiltration)", "high"),
        ("httpx.post", "Outbound HTTP write (possible exfiltration)", "high"),
        ("urllib.request", "Outbound HTTP / URL fetch", "medium"),
        ("aiohttp", "Async outbound network I/O", "medium"),
        ("fetch_env_vars", "Environment secret access", "high"),
        ("AWS_ACCESS_KEY_ID", "Cloud credential reference", "high"),
        ("DATABASE_URL", "Database secret reference", "medium"),
        ("OPENAI_API_KEY", "API key reference in code or docs", "high"),
        ("ANTHROPIC_API_KEY", "API key reference in code or docs", "high"),
        ("Bearer ", "Token-style authorization string", "medium"),
        ("/.ssh", "Sensitive filesystem scope", "medium"),
        ("/etc/", "Sensitive system path reference", "medium"),
        ("/var/log", "Log scraping behavior", "low"),
        ("timeout=None", "No timeout on network request", "medium"),
        ("eval(", "Dynamic code evaluation", "high"),
        ("exec(", "Dynamic code execution", "high"),
        ("pickle.loads", "Unsafe deserialization pattern", "high"),
        ("yaml.load(", "YAML load may be unsafe without safe_load", "medium"),
        ("docker ", "Container / runtime invocation in docs or scripts", "medium"),
        ("kubectl ", "Cluster control command in docs or scripts", "high"),
        ("curl ", "Shell HTTP client in documentation or scripts", "medium"),
        ("wget ", "Shell download in documentation or scripts", "medium"),
        ("pip install", "Supply-chain / dependency install surface", "low"),
        ("chmod +x", "Executable permission change", "low"),
        ("rm -rf", "Destructive filesystem command", "high"),
    ]

    regex_patterns: list[tuple[re.Pattern[str], str, str]] = [
        (re.compile(r"```\s*(bash|sh|zsh|powershell)\b", re.I), "Executable shell block in Markdown", "medium"),
        (re.compile(r"\bcurl\s+", re.I), "curl usage (network egress)", "medium"),
        (re.compile(r"\bwget\s+", re.I), "wget usage (network egress)", "medium"),
        (re.compile(r"api[_-]?key\s*[:=]", re.I), "API key assignment or documentation", "high"),
        (re.compile(r"(secret|password|token)\s*[:=]", re.I), "Secret-like configuration", "medium"),
        (re.compile(r"https?://[^\s`'\"<>]+", re.I), "Outbound URL reference", "low"),
        (re.compile(r"\bplugin\b|\btool\b.*\b(api|http)\b", re.I), "Agent tool / plugin surface", "medium"),
    ]

    lines = code_bundle.splitlines()
    out: list[dict[str, Any]] = []
    current_file = "unknown"
    for idx, line in enumerate(lines, start=1):
        header = re.match(r"^===\s+(.+?)\s+===$", line.strip())
        if header:
            current_file = header.group(1).strip() or "unknown"
            continue
        text = line.strip()
        if not text:
            continue
        matched = False
        for token, note, severity in literal_patterns:
            if token in line:
                out.append(
                    {
                        "line": idx,
                        "file": current_file,
                        "code": text[:300],
                        "annotation": note,
                        "severity": severity,
                    }
                )
                matched = True
                break
        if matched:
            if len(out) >= max_items:
                break
            continue
        for rx, note, severity in regex_patterns:
            if rx.search(line):
                out.append(
                    {
                        "line": idx,
                        "file": current_file,
                        "code": text[:300],
                        "annotation": note,
                        "severity": severity,
                    }
                )
                break
        if len(out) >= max_items:
            break
    return out
