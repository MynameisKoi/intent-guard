"""safetensors header validation (format: u64 header length, JSON header, raw tensor bytes)."""

from __future__ import annotations

import json
import struct

from engine.artifacts.byte_source import ByteSource, ByteSourceError
from engine.artifacts.types import ArtifactIssue, ArtifactReport

MAX_HEADER = 100 * 1024 * 1024
_DTYPE_BYTES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1, "F8_E8M0": 1, "F4": 1, "F6_E2M3": 1, "F6_E3M2": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2, "I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8, "F64": 8,
}


def inspect_safetensors(src: ByteSource, *, name: str | None = None) -> ArtifactReport:
    report = ArtifactReport(name=name or src.name, kind="safetensors")
    try:
        raw_len = src.read(0, 8)
        if len(raw_len) != 8:
            raise ValueError("file shorter than the 8-byte header length")
        n = struct.unpack("<Q", raw_len)[0]
        if n > MAX_HEADER:
            raise ValueError(f"declared header length {n} exceeds sanity limit")
        header = json.loads(src.read(8, n).decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError("header is not a JSON object")
    except (ValueError, ByteSourceError, UnicodeDecodeError) as e:
        report.error = str(e)
        report.add(
            ArtifactIssue(
                code="safetensors_malformed",
                title="safetensors header is malformed",
                description=f"The header could not be parsed ({e}). The file is corrupt or not genuinely safetensors.",
                severity="high",
            )
        )
        return report

    meta = header.pop("__metadata__", None) or {}
    data_start = 8 + n
    data_len = (src.size - data_start) if src.size is not None else None
    spans = []
    bad = []
    for tname, info in header.items():
        try:
            start, end = info["data_offsets"]
            dtype = info["dtype"]
            shape = info["shape"]
        except (KeyError, TypeError, ValueError):
            bad.append(f"{tname}: missing fields")
            continue
        elems = 1
        for d in shape:
            elems *= int(d)
        width = _DTYPE_BYTES.get(dtype)
        if width and dtype not in ("F4", "F6_E2M3", "F6_E3M2") and end - start != elems * width:
            bad.append(f"{tname}: size {end - start} != shape×dtype {elems * width}")
        if start > end or (data_len is not None and end > data_len):
            bad.append(f"{tname}: offsets {start}-{end} outside data section")
        spans.append((start, end, tname))

    spans.sort()
    overlaps = [f"{a[2]} ↔ {b[2]}" for a, b in zip(spans, spans[1:]) if b[0] < a[1]]
    covered = max((e for _, e, _ in spans), default=0)
    report.summary = {
        "tensor_count": len(header),
        "header_bytes": n,
        "metadata": {k: str(v)[:200] for k, v in list(meta.items())[:20]} if isinstance(meta, dict) else {},
        "file_size": src.size,
    }
    if bad:
        report.add(
            ArtifactIssue(
                code="safetensors_inconsistent",
                title="safetensors tensor table is inconsistent",
                description="; ".join(bad[:6]) + ". The header disagrees with the stored data.",
                severity="high",
                owasp_id="LLM04",
            )
        )
    if overlaps:
        report.add(
            ArtifactIssue(
                code="safetensors_overlap",
                title="safetensors tensors overlap",
                description=f"{len(overlaps)} overlapping pair(s), e.g. {overlaps[0]}. The safetensors spec forbids this.",
                severity="high",
                owasp_id="LLM04",
            )
        )
    if data_len is not None and data_len - covered > 0:
        trailing = data_len - covered
        report.add(
            ArtifactIssue(
                code="safetensors_trailing_data",
                title="Unreferenced data after the last safetensors tensor",
                description=f"{trailing} bytes are not referenced by any tensor; hidden payloads can ride here.",
                severity="medium" if trailing < 1_000_000 else "high",
            )
        )
    return report
