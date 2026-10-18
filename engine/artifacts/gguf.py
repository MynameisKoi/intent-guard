"""
GGUF inspector.

Parses the GGUF container (header, metadata key/values, tensor table) without
loading tensor data, then checks it for the anomalies that matter for supply-chain
security:

* malformed / hostile headers (absurd counts and lengths that target parser bugs)
* chat-template injection (see ``chat_template``)
* tensor table integrity — out-of-bounds, overlapping, or misaligned tensors
* bytes hidden outside the tensor table (appended payloads, gaps)
* metadata that contradicts the tensor layout (mislabelled or tampered models)
* corrupted weights — NaN/Inf/all-zero tensors and quantization scales, sampled

Works against any ``ByteSource`` so Hugging Face files are inspected via HTTP Range.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from typing import Any

from engine.artifacts.byte_source import ByteSource, ByteSourceError
from engine.artifacts.chat_template import check_chat_template
from engine.artifacts.types import ArtifactIssue, ArtifactReport

GGUF_MAGIC = b"GGUF"
DEFAULT_ALIGNMENT = 32

# Sanity ceilings. Real models sit orders of magnitude below these; values above
# them are either corruption or an attempt to trigger integer overflow / OOM in
# a GGUF parser (several llama.cpp CVEs in 2024 were exactly this).
MAX_TENSORS = 1_000_000
MAX_KV = 100_000
MAX_STRING = 64 * 1024 * 1024
MAX_ARRAY = 50_000_000
MAX_DIMS = 8

_VT_UINT8, _VT_INT8, _VT_UINT16, _VT_INT16, _VT_UINT32, _VT_INT32 = 0, 1, 2, 3, 4, 5
_VT_FLOAT32, _VT_BOOL, _VT_STRING, _VT_ARRAY, _VT_UINT64, _VT_INT64, _VT_FLOAT64 = 6, 7, 8, 9, 10, 11, 12
_SCALAR_FMT = {
    _VT_UINT8: "<B", _VT_INT8: "<b", _VT_UINT16: "<H", _VT_INT16: "<h", _VT_UINT32: "<I",
    _VT_INT32: "<i", _VT_FLOAT32: "<f", _VT_BOOL: "<?", _VT_UINT64: "<Q", _VT_INT64: "<q",
    _VT_FLOAT64: "<d",
}

# ggml type id -> (name, block size in elements, bytes per block)
GGML_TYPES: dict[int, tuple[str, int, int]] = {
    0: ("F32", 1, 4), 1: ("F16", 1, 2), 2: ("Q4_0", 32, 18), 3: ("Q4_1", 32, 20),
    6: ("Q5_0", 32, 22), 7: ("Q5_1", 32, 24), 8: ("Q8_0", 32, 34), 9: ("Q8_1", 32, 40),
    10: ("Q2_K", 256, 84), 11: ("Q3_K", 256, 110), 12: ("Q4_K", 256, 144), 13: ("Q5_K", 256, 176),
    14: ("Q6_K", 256, 210), 15: ("Q8_K", 256, 292), 16: ("IQ2_XXS", 256, 66), 17: ("IQ2_XS", 256, 74),
    18: ("IQ3_XXS", 256, 98), 19: ("IQ1_S", 256, 50), 20: ("IQ4_NL", 32, 18), 21: ("IQ3_S", 256, 110),
    22: ("IQ2_S", 256, 82), 23: ("IQ4_XS", 256, 136), 24: ("I8", 1, 1), 25: ("I16", 1, 2),
    26: ("I32", 1, 4), 27: ("I64", 1, 8), 28: ("F64", 1, 8), 29: ("IQ1_M", 256, 56),
    30: ("BF16", 1, 2), 34: ("TQ1_0", 256, 54), 35: ("TQ2_0", 256, 66), 39: ("MXFP4", 32, 17),
}

# Byte offsets of fp16 scale fields inside one quantized block. Corrupted or
# poisoned quantized weights show up as NaN/Inf scales, which can be checked
# without dequantizing anything.
_SCALE_OFFSETS: dict[str, tuple[int, ...]] = {
    "Q4_0": (0,), "Q4_1": (0, 2), "Q5_0": (0,), "Q5_1": (0, 2), "Q8_0": (0,),
    "Q2_K": (80, 82), "Q3_K": (108,), "Q4_K": (0, 2), "Q5_K": (0, 2), "Q6_K": (208,),
    "IQ4_NL": (0,), "IQ4_XS": (0,),
}

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_SHELLISH_RE = re.compile(r"(?i)(?:\bcurl\s+-|\bwget\s+|powershell\s+-e|/bin/(?:ba)?sh\b|\bbase64\s+-d\b|\|\s*sh\b)")
_BLK_RE = re.compile(r"^blk\.(\d+)\.")


class GGUFParseError(ValueError):
    pass


class _Cursor:
    def __init__(self, src: ByteSource, offset: int = 0) -> None:
        self.src = src
        self.pos = offset

    def take(self, n: int) -> bytes:
        data = self.src.read(self.pos, n)
        if len(data) != n:
            raise GGUFParseError(f"unexpected end of file at offset {self.pos} (wanted {n} bytes)")
        self.pos += n
        return data

    def unpack(self, fmt: str) -> Any:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self, len_fmt: str) -> str:
        n = self.unpack(len_fmt)
        if n > MAX_STRING:
            raise GGUFParseError(f"string length {n} at offset {self.pos} exceeds sanity limit")
        return self.take(n).decode("utf-8", errors="replace")


def _read_value(cur: _Cursor, vtype: int, len_fmt: str, *, keep_array: bool) -> Any:
    if vtype in _SCALAR_FMT:
        return cur.unpack(_SCALAR_FMT[vtype])
    if vtype == _VT_STRING:
        return cur.string(len_fmt)
    if vtype == _VT_ARRAY:
        etype = cur.unpack("<I")
        count = cur.unpack(len_fmt)
        if count > MAX_ARRAY:
            raise GGUFParseError(f"array length {count} exceeds sanity limit")
        if etype in _SCALAR_FMT:
            size = struct.calcsize(_SCALAR_FMT[etype])
            raw = cur.take(size * count)
            if not keep_array:
                return {"type": etype, "count": count}
            return list(struct.unpack(f"<{count}{_SCALAR_FMT[etype][1]}", raw))
        if etype == _VT_STRING:
            items = [cur.string(len_fmt) for _ in range(count)]
            return items if keep_array else {"type": etype, "count": count, "sample": items[:8]}
        if etype == _VT_ARRAY:
            return [_read_value(cur, _VT_ARRAY, len_fmt, keep_array=False) for _ in range(count)]
        raise GGUFParseError(f"unknown array element type {etype}")
    raise GGUFParseError(f"unknown metadata value type {vtype}")


# Arrays kept in full because checks need them; everything else is summarized.
_KEEP_ARRAYS = ("tokenizer.ggml.tokens",)


def parse_gguf(src: ByteSource) -> dict[str, Any]:
    cur = _Cursor(src)
    magic = cur.take(4)
    if magic != GGUF_MAGIC:
        raise GGUFParseError(f"bad magic {magic!r}; not a GGUF file")
    version = cur.unpack("<I")
    if version not in (1, 2, 3):
        raise GGUFParseError(f"unsupported GGUF version {version}")
    len_fmt = "<I" if version == 1 else "<Q"
    n_tensors = cur.unpack(len_fmt)
    n_kv = cur.unpack(len_fmt)
    if n_tensors > MAX_TENSORS:
        raise GGUFParseError(f"tensor count {n_tensors} exceeds sanity limit")
    if n_kv > MAX_KV:
        raise GGUFParseError(f"metadata count {n_kv} exceeds sanity limit")

    metadata: dict[str, Any] = {}
    duplicate_keys: list[str] = []
    for _ in range(n_kv):
        key = cur.string(len_fmt)
        vtype = cur.unpack("<I")
        value = _read_value(cur, vtype, len_fmt, keep_array=key in _KEEP_ARRAYS)
        if key in metadata:
            duplicate_keys.append(key)
        metadata[key] = value

    tensors: list[dict[str, Any]] = []
    for _ in range(n_tensors):
        name = cur.string(len_fmt)
        n_dims = cur.unpack("<I")
        if n_dims > MAX_DIMS:
            raise GGUFParseError(f"tensor {name!r} has {n_dims} dimensions")
        dims = [cur.unpack(len_fmt) for _ in range(n_dims)]
        ttype = cur.unpack("<I")
        offset = cur.unpack("<Q")
        tensors.append({"name": name, "dims": dims, "type_id": ttype, "offset": offset})

    alignment = metadata.get("general.alignment", DEFAULT_ALIGNMENT)
    if not isinstance(alignment, int) or alignment <= 0:
        alignment = DEFAULT_ALIGNMENT
    header_end = cur.pos
    data_start = header_end + ((-header_end) % alignment)
    return {
        "version": version,
        "tensor_count": n_tensors,
        "kv_count": n_kv,
        "metadata": metadata,
        "duplicate_keys": duplicate_keys,
        "tensors": tensors,
        "alignment": alignment,
        "header_end": header_end,
        "data_start": data_start,
    }


def _tensor_nbytes(t: dict[str, Any]) -> int | None:
    info = GGML_TYPES.get(t["type_id"])
    if not info:
        return None
    _, block, type_size = info
    n = 1
    for d in t["dims"]:
        n *= d
    if block > 1 and t["dims"] and t["dims"][0] % block:
        return None
    return (n // block) * type_size


def _f16(b: bytes) -> float:
    return struct.unpack("<e", b)[0]


def _bf16(b: bytes) -> float:
    return struct.unpack("<f", b"\x00\x00" + b)[0]


def _sample_tensor(src: ByteSource, abs_off: int, nbytes: int, tname: str, budget: int) -> dict[str, Any] | None:
    """Check NaN/Inf/zero in a prefix of a tensor; quantized types are checked via their scales."""
    if tname in ("F32", "F16", "BF16"):
        width = {"F32": 4, "F16": 2, "BF16": 2}[tname]
        raw = src.read(abs_off, min(nbytes, budget))
        raw = raw[: len(raw) - (len(raw) % width)]
        if not raw:
            return None
        if tname == "F32":
            vals = struct.unpack(f"<{len(raw) // 4}f", raw)
        elif tname == "F16":
            vals = struct.unpack(f"<{len(raw) // 2}e", raw)
        else:
            vals = [_bf16(raw[i : i + 2]) for i in range(0, len(raw), 2)]
    elif tname in _SCALE_OFFSETS:
        _, _, block_bytes = next(v for v in GGML_TYPES.values() if v[0] == tname)
        n_blocks = min(nbytes, budget) // block_bytes
        raw = src.read(abs_off, n_blocks * block_bytes)
        vals = []
        for b in range(len(raw) // block_bytes):
            base = b * block_bytes
            for off in _SCALE_OFFSETS[tname]:
                vals.append(_f16(raw[base + off : base + off + 2]))
        if not vals:
            return None
    else:
        return None
    nan = sum(1 for v in vals if math.isnan(v))
    inf = sum(1 for v in vals if math.isinf(v))
    finite = [abs(v) for v in vals if math.isfinite(v)]
    zero = sum(1 for v in finite if v == 0.0)
    return {
        "sampled": len(vals),
        "nan": nan,
        "inf": inf,
        "zero_fraction": round(zero / len(vals), 4) if vals else 0.0,
        "max_abs": max(finite) if finite else None,
        "via_scales": tname not in ("F32", "F16", "BF16"),
    }


def inspect_gguf(
    src: ByteSource,
    *,
    name: str | None = None,
    sample_tensors: int = 24,
    sample_bytes: int = 65_536,
) -> ArtifactReport:
    report = ArtifactReport(name=name or src.name, kind="gguf")
    try:
        parsed = parse_gguf(src)
    except (GGUFParseError, ByteSourceError, struct.error) as e:
        report.error = str(e)
        report.add(
            ArtifactIssue(
                code="gguf_malformed",
                title="GGUF header is malformed or hostile",
                description=(
                    f"The file could not be parsed as GGUF: {e}. Malformed headers with oversized "
                    "counts or lengths are used to trigger memory-corruption bugs in GGUF loaders; "
                    "do not load this file."
                ),
                severity="high",
                owasp_id="LLM03",
            )
        )
        return report

    md = parsed["metadata"]
    tensors = parsed["tensors"]
    arch = md.get("general.architecture")
    file_size = src.size
    type_counts = Counter(GGML_TYPES.get(t["type_id"], (f"unknown({t['type_id']})",))[0] for t in tensors)
    report.summary = {
        "gguf_version": parsed["version"],
        "architecture": arch,
        "name": md.get("general.name"),
        "author": md.get("general.author") or md.get("general.organization"),
        "license": md.get("general.license"),
        "source_url": md.get("general.source.url") or md.get("general.url"),
        "base_models": [
            md.get(f"general.base_model.{i}.name") or md.get(f"general.base_model.{i}.repo_url")
            for i in range(int(md.get("general.base_model.count", 0) or 0))
        ][:5],
        "file_type": md.get("general.file_type"),
        "quantization_version": md.get("general.quantization_version"),
        "context_length": md.get(f"{arch}.context_length") if arch else None,
        "block_count": md.get(f"{arch}.block_count") if arch else None,
        "tensor_count": parsed["tensor_count"],
        "metadata_count": parsed["kv_count"],
        "tensor_types": dict(type_counts.most_common()),
        "file_size": file_size,
        "header_bytes": parsed["header_end"],
        "has_chat_template": "tokenizer.chat_template" in md,
        "tokenizer_model": md.get("tokenizer.ggml.model"),
    }

    if parsed["duplicate_keys"]:
        report.add(
            ArtifactIssue(
                code="gguf_duplicate_keys",
                title="GGUF metadata defines the same key more than once",
                description=(
                    "Duplicate keys ("
                    + ", ".join(parsed["duplicate_keys"][:8])
                    + ") let different loaders see different values — a classic parser-differential "
                    "trick for hiding a malicious chat template or config from reviewers."
                ),
                severity="high",
            )
        )

    if not arch:
        report.add(
            ArtifactIssue(
                code="gguf_no_architecture",
                title="GGUF has no general.architecture",
                description="Every valid model GGUF declares its architecture. Its absence suggests a hand-built or tampered file.",
                severity="medium",
            )
        )

    # --- chat templates -----------------------------------------------------
    for key, value in md.items():
        if key.startswith("tokenizer.chat_template") and isinstance(value, str):
            for issue in check_chat_template(value, location=f"metadata:{key}"):
                report.add(issue)

    # --- suspicious strings in free-text metadata ---------------------------
    suspicious: list[dict[str, str]] = []
    for key, value in md.items():
        if not isinstance(value, str) or key.startswith("tokenizer.chat_template"):
            continue
        if _SHELLISH_RE.search(value):
            suspicious.append({"key": key, "kind": "shell_command", "value": value[:200]})
        elif len(value) > 4096 and key not in ("general.description",):
            suspicious.append({"key": key, "kind": "oversized_string", "value": f"{len(value)} chars"})
    if suspicious:
        report.add(
            ArtifactIssue(
                code="gguf_suspicious_metadata",
                title="GGUF metadata contains shell commands or oversized blobs",
                description=(
                    "Free-text metadata should be short descriptive strings. Found: "
                    + "; ".join(f"{s['key']} ({s['kind']})" for s in suspicious[:6])
                    + ". Metadata can smuggle payloads that downstream tooling displays or executes."
                ),
                severity="medium",
                evidence={"items": suspicious[:10]},
            )
        )
    urls = sorted({u for v in md.values() if isinstance(v, str) for u in _URL_RE.findall(v)})
    if urls:
        report.summary["metadata_urls"] = urls[:20]

    # --- tensor table integrity --------------------------------------------
    data_start = parsed["data_start"]
    alignment = parsed["alignment"]
    names = Counter(t["name"] for t in tensors)
    dupes = [n for n, c in names.items() if c > 1]
    if dupes:
        report.add(
            ArtifactIssue(
                code="gguf_duplicate_tensors",
                title="Duplicate tensor names in GGUF",
                description=f"Tensors {', '.join(dupes[:6])} appear more than once; loaders disagree on which copy wins.",
                severity="high",
                owasp_id="LLM04",
            )
        )

    unknown = [t["name"] for t in tensors if t["type_id"] not in GGML_TYPES]
    if unknown:
        report.add(
            ArtifactIssue(
                code="gguf_unknown_tensor_type",
                title="Tensors use an unrecognized ggml type",
                description=(
                    f"{len(unknown)} tensor(s) (e.g. {unknown[0]}) use a type id unknown to this "
                    "scanner. This may be a very new quantization; their bounds could not be verified."
                ),
                severity="low",
            )
        )

    spans: list[tuple[int, int, str]] = []
    bad_dims, misaligned, out_of_bounds = [], [], []
    for t in tensors:
        if any(d == 0 for d in t["dims"]) or not t["dims"]:
            bad_dims.append(t["name"])
        nbytes = _tensor_nbytes(t)
        if t["offset"] % alignment:
            misaligned.append(t["name"])
        if nbytes is None:
            continue
        t["nbytes"] = nbytes
        start = data_start + t["offset"]
        end = start + nbytes
        spans.append((start, end, t["name"]))
        if file_size is not None and end > file_size:
            out_of_bounds.append(t["name"])

    if bad_dims:
        report.add(
            ArtifactIssue(
                code="gguf_bad_dims",
                title="Tensors with zero or missing dimensions",
                description=f"{len(bad_dims)} tensor(s) such as {bad_dims[0]} have empty shapes — invalid for a real model.",
                severity="medium",
                owasp_id="LLM04",
            )
        )
    if misaligned:
        report.add(
            ArtifactIssue(
                code="gguf_misaligned",
                title="Tensor offsets violate the declared alignment",
                description=(
                    f"{len(misaligned)} tensor(s) (e.g. {misaligned[0]}) are not aligned to {alignment} bytes. "
                    "Conforming writers never produce this; it indicates manual tampering."
                ),
                severity="medium",
            )
        )
    if out_of_bounds:
        report.add(
            ArtifactIssue(
                code="gguf_out_of_bounds",
                title="Tensor data extends past the end of the file",
                description=(
                    f"{len(out_of_bounds)} tensor(s) (e.g. {out_of_bounds[0]}) point beyond the file's "
                    f"{file_size} bytes. The file is truncated or crafted to make loaders read out of bounds."
                ),
                severity="high",
            )
        )

    spans.sort()
    overlaps = []
    for (s1, e1, n1), (s2, _e2, n2) in zip(spans, spans[1:]):
        if s2 < e1:
            overlaps.append(f"{n1} ↔ {n2}")
    if overlaps:
        report.add(
            ArtifactIssue(
                code="gguf_overlapping_tensors",
                title="Tensors overlap in the data section",
                description=(
                    f"{len(overlaps)} overlapping tensor pair(s), e.g. {overlaps[0]}. Writing to one tensor "
                    "silently changes another; legitimate converters never emit overlaps."
                ),
                severity="high",
                owasp_id="LLM04",
            )
        )

    if spans and file_size is not None:
        covered_end = max(e for _, e, _ in spans)
        trailing = file_size - covered_end
        slack = alignment
        report.summary["trailing_bytes"] = max(trailing, 0)
        if trailing > slack:
            report.add(
                ArtifactIssue(
                    code="gguf_trailing_data",
                    title="Unreferenced data appended after the last tensor",
                    description=(
                        f"{trailing} bytes follow the final tensor and are referenced by nothing. Appended "
                        "data is how polyglot files and hidden payloads ride along inside model downloads."
                    ),
                    severity="high" if trailing > 64 * 1024 else "medium",
                    evidence={"trailing_bytes": trailing, "covered_end": covered_end, "file_size": file_size},
                )
            )
        gaps = []
        for (s1, e1, n1), (s2, _e2, n2) in zip(spans, spans[1:]):
            gap = s2 - (e1 + ((-e1) % alignment))
            if gap > 4096:
                gaps.append((gap, n1, n2))
        if gaps:
            total = sum(g for g, _, _ in gaps)
            report.add(
                ArtifactIssue(
                    code="gguf_internal_gaps",
                    title="Unreferenced byte ranges between tensors",
                    description=(
                        f"{len(gaps)} gap(s) totalling {total} bytes sit between tensors (largest after "
                        f"{max(gaps)[1]}). Space no tensor claims can hide an embedded payload."
                    ),
                    severity="medium",
                    evidence={"gaps": [{"bytes": g, "after": a, "before": b} for g, a, b in gaps[:10]]},
                )
            )

    # --- metadata vs layout consistency ------------------------------------
    blocks = {int(m.group(1)) for t in tensors if (m := _BLK_RE.match(t["name"]))}
    declared_blocks = md.get(f"{arch}.block_count") if arch else None
    if isinstance(declared_blocks, int) and blocks and declared_blocks != max(blocks) + 1:
        report.add(
            ArtifactIssue(
                code="gguf_block_count_mismatch",
                title="Declared layer count does not match tensors present",
                description=(
                    f"Metadata declares {declared_blocks} blocks but tensors cover {max(blocks) + 1}. "
                    "The model was edited after conversion or is mislabelled."
                ),
                severity="medium",
                owasp_id="LLM04",
            )
        )
    tokens = md.get("tokenizer.ggml.tokens")
    embd = next((t for t in tensors if t["name"] == "token_embd.weight"), None)
    if isinstance(tokens, list) and embd and len(embd["dims"]) >= 2:
        vocab_rows = embd["dims"][1]
        report.summary["vocab_size"] = len(tokens)
        if abs(vocab_rows - len(tokens)) > max(256, len(tokens) // 50):
            report.add(
                ArtifactIssue(
                    code="gguf_vocab_mismatch",
                    title="Tokenizer vocabulary size disagrees with the embedding matrix",
                    description=(
                        f"{len(tokens)} tokens in metadata vs {vocab_rows} embedding rows. A swapped "
                        "tokenizer silently changes how text maps to model inputs."
                    ),
                    severity="medium",
                    owasp_id="LLM04",
                )
            )

    # --- weight sampling ----------------------------------------------------
    sample_report: dict[str, Any] = {}
    nan_hits, zero_hits = [], []
    if sample_tensors > 0 and spans:
        sampled_order = sorted(
            (t for t in tensors if t.get("nbytes")),
            key=lambda t: (0 if t["name"].endswith(("attn_q.weight", "ffn_down.weight", "output.weight", "token_embd.weight")) else 1, t["offset"]),
        )
        for t in sampled_order[:sample_tensors]:
            tname = GGML_TYPES[t["type_id"]][0]
            try:
                stats = _sample_tensor(src, data_start + t["offset"], t["nbytes"], tname, sample_bytes)
            except (ByteSourceError, struct.error):
                break
            if not stats:
                continue
            sample_report[t["name"]] = stats
            if stats["nan"] or stats["inf"]:
                nan_hits.append(t["name"])
            if stats["zero_fraction"] >= 0.999 and stats["sampled"] >= 64 and not t["name"].endswith("bias"):
                zero_hits.append(t["name"])
    report.summary["weight_samples"] = len(sample_report)
    if sample_report:
        report.tool_outputs["weight_samples"] = dict(list(sample_report.items())[:12])
    if nan_hits:
        report.add(
            ArtifactIssue(
                code="gguf_nan_weights",
                title="NaN/Inf values found in model weights",
                description=(
                    f"Sampled tensors {', '.join(nan_hits[:5])} contain NaN or infinite values "
                    "(or quantization scales). The weights are corrupted or deliberately sabotaged."
                ),
                severity="high",
                owasp_id="LLM04",
            )
        )
    if zero_hits:
        report.add(
            ArtifactIssue(
                code="gguf_zeroed_weights",
                title="Weight tensors are entirely zero in the sampled region",
                description=(
                    f"{', '.join(zero_hits[:5])} sampled as all-zero. Zeroed layers indicate an "
                    "ablated, stub, or decoy model rather than trained weights."
                ),
                severity="medium",
                owasp_id="LLM04",
            )
        )
    return report
