"""
Bridge to REA — Reverse Engineer Anything (https://github.com/morluto/rea).

REA statically inspects native binaries, .NET assemblies, Go/Rust builds, Mach-O
bundles and Electron/JavaScript applications without executing them, and returns
structured Evidence JSON. IntentGuard runs the REA CLI, compacts the Evidence, and
hands it to the semantic LLM (e.g. via OpenRouter) as reverse-engineered context.

Commands are chosen per artifact kind. Engines that need a disassembler (Ghidra,
Hopper, IDA) are only used when ``REA_ANALYSIS_PROVIDER`` is configured.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any

from config import get_settings

logger = logging.getLogger(__name__)

# kind -> REA commands that need no external disassembler.
_COMMANDS_BY_KIND: dict[str, list[str]] = {
    "elf": ["inspect-artifact", "inspect-go-binary", "inspect-rust-binary"],
    "pe": ["inspect-artifact", "inspect-pe-resources", "inspect-go-binary", "inspect-rust-binary"],
    "pe_dotnet": [
        "inspect-artifact",
        "inspect-managed-artifact",
        "inspect-managed-native-boundaries",
        "inspect-managed-members",
    ],
    "macho": ["inspect-artifact", "inspect-macho", "inspect-signature", "inspect-go-binary", "inspect-rust-binary"],
    "apk": ["inspect-artifact", "inspect-android-package"],
    "jar": ["inspect-artifact"],
    "wasm": ["inspect-artifact"],
    "asar": ["analyze-javascript-application"],
    "electron_app": ["analyze-javascript-application"],
}
_NATIVE_KINDS = frozenset({"elf", "pe", "macho"})
# Keys that are pure identifiers/hashes: plenty of tokens, no analytical value.
_DROP_KEYS = frozenset(
    {"evidence_id", "inspection_id", "substep_id", "manifest_id", "artifact_id", "occurrence_id",
     "root_artifact_id", "graph_sha256", "parent_occurrence_id", "predicate_type", "provider", "parameters"}
)


@lru_cache(maxsize=1)
def resolve_rea_command() -> tuple[str, ...] | None:
    s = get_settings()
    choice = (s.rea_command or "auto").strip()
    if choice.lower() in ("off", "none", "false", "0", "disabled"):
        return None
    if choice.lower() != "auto":
        return tuple(choice.split())
    if shutil.which("rea"):
        return ("rea",)
    if shutil.which("npx"):
        return ("npx", "-y", "rea-agents@latest")
    return None


def rea_available() -> bool:
    return resolve_rea_command() is not None


def _compact(obj: Any, *, depth: int = 0, list_cap: int = 25, str_cap: int = 400) -> Any:
    if depth > 9:
        return "…"
    if isinstance(obj, dict):
        return {
            k: _compact(v, depth=depth + 1, list_cap=list_cap, str_cap=str_cap)
            for k, v in obj.items()
            if k not in _DROP_KEYS and v not in (None, [], {}, "")
        }
    if isinstance(obj, list):
        head = [_compact(v, depth=depth + 1, list_cap=list_cap, str_cap=str_cap) for v in obj[:list_cap]]
        if len(obj) > list_cap:
            head.append(f"… {len(obj) - list_cap} more")
        return head
    if isinstance(obj, str) and len(obj) > str_cap:
        return obj[:str_cap] + "…"
    return obj


def _run(args: list[str], *, timeout: int) -> tuple[int, str, str]:
    cmd = resolve_rea_command()
    if not cmd:
        raise RuntimeError("REA is not installed (npm install -g rea-agents)")
    env = dict(os.environ)
    s = get_settings()
    if s.rea_analysis_provider:
        env["REA_ANALYSIS_PROVIDER"] = s.rea_analysis_provider
    env.setdefault("NO_COLOR", "1")
    proc = subprocess.run(
        [*cmd, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _parse(stdout: str) -> Any:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        if start >= 0:
            try:
                return json.loads(text[start:])
            except json.JSONDecodeError:
                pass
    return {"raw_text": text[:4000]}


def _is_rea_error(payload: Any) -> bool:
    return isinstance(payload, dict) and "code" in payload and "message" in payload and "normalized_result" not in payload


def run_rea_command(command: str, target: Path, *, extra: list[str] | None = None) -> dict[str, Any]:
    s = get_settings()
    args = [command, str(target), *(extra or []), "--json"]
    try:
        code, out, err = _run(args, timeout=int(s.rea_timeout))
    except subprocess.TimeoutExpired:
        return {"command": command, "ok": False, "error": f"timed out after {s.rea_timeout}s"}
    except (OSError, RuntimeError) as e:
        return {"command": command, "ok": False, "error": str(e)}
    payload = _parse(out)
    if code != 0 or _is_rea_error(payload):
        msg = payload.get("message") if isinstance(payload, dict) else None
        return {"command": command, "ok": False, "error": (msg or err.strip() or f"exit {code}")[:600]}
    body = payload.get("normalized_result", payload) if isinstance(payload, dict) else payload
    return {"command": command, "ok": True, "result": _compact(body)}


def _analyze_javascript(target: Path) -> dict[str, Any]:
    """Full JS application Evidence can be hundreds of MB; project a summary view from a temp file."""
    s = get_settings()
    with tempfile.TemporaryDirectory(prefix="ig_rea_js_") as tmp:
        evidence = Path(tmp) / "app-evidence.json"
        try:
            cmd = resolve_rea_command()
            if not cmd:
                raise RuntimeError("REA is not installed")
            with evidence.open("w") as fh:
                proc = subprocess.run(
                    [*cmd, "analyze-javascript-application", str(target), "--json"],
                    stdout=fh,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=int(s.rea_timeout),
                    stdin=subprocess.DEVNULL,
                )
            if proc.returncode != 0:
                return {"command": "analyze-javascript-application", "ok": False, "error": proc.stderr.strip()[:600]}
            view = Path(tmp) / "view.json"
            view.write_text(
                json.dumps({"source": {"kind": "inline", "evidence": json.loads(evidence.read_text())}, "view": {"kind": "summary"}})
            )
            code, out, err = _run(["inspect-analysis-view", str(view), "--json"], timeout=int(s.rea_timeout))
            payload = _parse(out)
            if code != 0 or _is_rea_error(payload):
                return {"command": "inspect-analysis-view", "ok": False, "error": (err or out)[:600]}
            return {"command": "analyze-javascript-application", "ok": True, "result": _compact(payload)}
        except subprocess.TimeoutExpired:
            return {"command": "analyze-javascript-application", "ok": False, "error": "timed out"}
        except (OSError, RuntimeError, json.JSONDecodeError) as e:
            return {"command": "analyze-javascript-application", "ok": False, "error": str(e)[:600]}


def reverse_engineer(target: Path, kind: str) -> dict[str, Any]:
    """
    Run the REA commands appropriate for `kind` and return compacted Evidence.

    The result has `available`, `commands` (each with ok/result/error), and a
    size-bounded `evidence_text` for the LLM.
    """
    s = get_settings()
    if not rea_available():
        return {"available": False, "commands": [], "evidence_text": "", "note": "REA not installed; built-in triage only."}

    commands = list(_COMMANDS_BY_KIND.get(kind, ["inspect-artifact"]))
    results: list[dict[str, Any]] = []
    for command in commands:
        if command == "analyze-javascript-application":
            results.append(_analyze_javascript(target))
        else:
            results.append(run_rea_command(command, target))

    if s.rea_analysis_provider and kind in _NATIVE_KINDS:
        provider = ["--provider", s.rea_analysis_provider]
        results.append(run_rea_command("analyze", target, extra=provider))

    ok = [r for r in results if r.get("ok")]
    evidence = {r["command"]: r["result"] for r in ok}
    text = json.dumps(evidence, default=str, ensure_ascii=False)
    limit = int(s.rea_max_output_chars)
    if len(text) > limit:
        text = text[:limit] + "… [truncated]"
    return {
        "available": True,
        "command_prefix": " ".join(resolve_rea_command() or ()),
        "commands": [{k: v for k, v in r.items() if k != "result"} for r in results],
        "evidence_text": text,
    }
