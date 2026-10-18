"""
Pickle disassembly for model files (.pkl/.pt/.pth/.bin/.ckpt).

Loading a pickle runs whatever callables it references, so a "model" can be a
reverse shell. This walks the opcode stream with ``pickletools`` — never
unpickling — and classifies every imported global, the same approach as
picklescan and Hugging Face's own scanner.
"""

from __future__ import annotations

import io
import pickletools
import zipfile
from pathlib import Path
from typing import Any

from engine.artifacts.types import ArtifactIssue, ArtifactReport

# module -> names (or "*") that give code execution, file, or network access.
_DANGEROUS: dict[str, set[str] | str] = {
    "os": "*", "posix": "*", "nt": "*", "subprocess": "*", "sys": "*", "socket": "*", "shutil": "*",
    "runpy": "*", "pty": "*", "webbrowser": "*", "commands": "*", "ctypes": "*", "importlib": "*",
    "requests": "*", "urllib": "*", "urllib.request": "*", "http.client": "*", "httplib": "*",
    "asyncio": "*", "multiprocessing": "*", "code": "*", "pdb": "*", "timeit": "*", "marshal": "*",
    "types": {"CodeType", "FunctionType"}, "pickle": "*", "_pickle": "*", "dill": "*", "torch.hub": "*",
    "builtins": {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "globals", "breakpoint", "input"},
    "__builtin__": {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "globals", "execfile", "file"},
    "operator": {"attrgetter", "methodcaller"}, "functools": {"partial"},
    "numpy.testing._private.utils": "*", "torch.serialization": {"load"}, "torch._inductor.codecache": "*",
}

_SAFE_PREFIXES = (
    "torch._utils.", "torch.nn.", "torch.storage", "torch._tensor", "torch.Size", "torch.device",
    "torch.dtype", "torch.float", "torch.bfloat16", "torch.half", "torch.int", "torch.long", "torch.bool", "torch.uint8",
    "numpy.core.multiarray.", "numpy._core.multiarray.", "numpy.dtype", "numpy.ndarray", "numpy.",
    "collections.OrderedDict", "collections.defaultdict", "builtins.set", "builtins.frozenset",
    "builtins.slice", "builtins.range", "builtins.complex", "builtins.bytearray", "_codecs.encode",
    "sklearn.", "transformers.", "tokenizers.", "accelerate.", "pytorch_lightning.", "lightning.",
    "omegaconf.", "pathlib.PosixPath", "pathlib.WindowsPath", "argparse.Namespace", "typing.",
    "torch.FloatStorage", "torch.HalfStorage", "torch.BFloat16Storage", "torch.LongStorage",
    "torch.IntStorage", "torch.ByteStorage", "torch.BoolStorage", "torch.DoubleStorage", "torch.CharStorage",
    "torch.ShortStorage",
)

_MAX_PICKLE_BYTES = 512 * 1024 * 1024


def _classify(module: str, name: str) -> str:
    rule = _DANGEROUS.get(module)
    if rule is None:
        # submodules of dangerous packages (e.g. "os.path" is benign-ish, "subprocess.x" is not)
        top = module.split(".")[0]
        if top in ("subprocess", "socket", "ctypes", "runpy", "pty", "requests", "urllib", "webbrowser", "multiprocessing"):
            return "dangerous"
    elif rule == "*" or name in rule:
        if module == "os" and name in ("path",):
            return "suspicious"
        return "dangerous"
    full = f"{module}.{name}"
    if full.startswith(_SAFE_PREFIXES):
        return "safe"
    return "unknown"


def scan_pickle_bytes(data: bytes) -> dict[str, Any]:
    """Return imported globals and opcode stats from one pickle stream."""
    globals_found: list[tuple[str, str]] = []
    strings: list[str] = []
    opcodes = 0
    reduce_count = 0
    error = None
    try:
        for op, arg, _pos in pickletools.genops(io.BytesIO(data)):
            opcodes += 1
            if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8", "SHORT_BINSTRING", "BINSTRING", "STRING"):
                strings.append(str(arg))
                if len(strings) > 4:
                    strings.pop(0)
            elif op.name in ("GLOBAL", "INST"):
                mod, _, name = str(arg).partition(" ")
                globals_found.append((mod, name))
            elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                globals_found.append((strings[-2], strings[-1]))
            elif op.name in ("REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "OBJ"):
                reduce_count += 1
    except Exception as e:  # malformed streams are themselves suspicious
        error = f"{type(e).__name__}: {e}"
    return {"globals": globals_found, "opcodes": opcodes, "calls": reduce_count, "error": error}


def _pickle_streams(path: Path) -> list[tuple[str, bytes]]:
    if zipfile.is_zipfile(path):
        out = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".pkl") and info.file_size <= _MAX_PICKLE_BYTES:
                    out.append((info.filename, zf.read(info)))
        return out
    if path.stat().st_size > _MAX_PICKLE_BYTES:
        return []
    return [(path.name, path.read_bytes())]


def inspect_pickle(path: Path, *, name: str | None = None) -> ArtifactReport:
    report = ArtifactReport(name=name or str(path), kind="pickle")
    try:
        streams = _pickle_streams(path)
    except (OSError, zipfile.BadZipFile) as e:
        report.error = str(e)
        return report

    dangerous: set[str] = set()
    unknown: set[str] = set()
    all_globals: set[str] = set()
    errors = []
    for stream_name, data in streams:
        res = scan_pickle_bytes(data)
        if res["error"]:
            errors.append(f"{stream_name}: {res['error']}")
        for mod, gname in res["globals"]:
            full = f"{mod}.{gname}"
            all_globals.add(full)
            verdict = _classify(mod, gname)
            if verdict == "dangerous":
                dangerous.add(full)
            elif verdict in ("unknown", "suspicious"):
                unknown.add(full)

    report.summary = {
        "pickle_streams": [s for s, _ in streams][:10],
        "imported_globals": sorted(all_globals)[:60],
        "format": "torch zip" if zipfile.is_zipfile(path) else "raw pickle",
    }
    report.add(
        ArtifactIssue(
            code="pickle_format",
            title="Model is serialized with pickle (executes code on load)",
            description=(
                "Pickle-based checkpoints run arbitrary callables when loaded with torch.load / "
                "pickle.load unless `weights_only=True` is enforced. Prefer a safetensors or GGUF copy."
            ),
            severity="low",
        )
    )
    if dangerous:
        report.add(
            ArtifactIssue(
                code="pickle_code_execution",
                title="Pickle imports code-execution / system callables",
                description=(
                    "Loading this file would call: " + ", ".join(sorted(dangerous)[:10])
                    + ". This is a malicious-model payload (arbitrary code execution on load)."
                ),
                severity="critical",
                evidence={"dangerous_globals": sorted(dangerous)},
            )
        )
    if unknown:
        report.add(
            ArtifactIssue(
                code="pickle_unknown_globals",
                title="Pickle imports non-standard callables",
                description=(
                    "Imports outside the usual torch/numpy/collections set: " + ", ".join(sorted(unknown)[:10])
                    + ". Review them — custom classes can execute code in `__setstate__` / `__reduce__`."
                ),
                severity="medium",
                evidence={"unknown_globals": sorted(unknown)[:40]},
            )
        )
    if errors:
        report.add(
            ArtifactIssue(
                code="pickle_malformed",
                title="Pickle stream is malformed",
                description="; ".join(errors[:3]) + ". Truncated or crafted streams can confuse scanners.",
                severity="medium",
            )
        )
    return report
