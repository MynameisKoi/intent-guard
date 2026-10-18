"""Classify files by content (magic bytes), never by extension alone."""

from __future__ import annotations

import os
import struct
import zipfile
from pathlib import Path

# Extensions worth sniffing. Anything else is only considered when it is an
# extensionless file with the executable bit set (typical for ELF/Mach-O).
CANDIDATE_EXTENSIONS = frozenset(
    {
        ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".so", ".dylib", ".elf", ".o", ".ko",
        ".bin", ".out", ".app", ".asar", ".wasm", ".jar", ".apk",
        ".gguf", ".ggml", ".safetensors", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib",
        ".mar", ".nemo", ".keras", ".h5",
    }
)

MODEL_KINDS = frozenset({"gguf", "safetensors", "pickle", "torch_zip"})
BINARY_KINDS = frozenset({"pe", "pe_dotnet", "elf", "macho", "asar", "wasm", "jar", "apk"})

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",  # fat/universal (also Java class files — disambiguated below)
}


def _is_dotnet_pe(head: bytes) -> bool:
    """PE with a non-empty CLI (COM descriptor) data directory."""
    try:
        pe_off = struct.unpack_from("<I", head, 0x3C)[0]
        if head[pe_off : pe_off + 4] != b"PE\0\0":
            return False
        opt = pe_off + 24
        magic = struct.unpack_from("<H", head, opt)[0]
        dirs = opt + (96 if magic == 0x10B else 112)
        rva, size = struct.unpack_from("<II", head, dirs + 14 * 8)
        return rva != 0 and size != 0
    except (struct.error, IndexError):
        return False


def _zip_kind(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()[:2000]
    except (zipfile.BadZipFile, OSError, ValueError):
        return None
    if any(n.endswith(("data.pkl", ".pkl")) for n in names):
        return "torch_zip"
    if "AndroidManifest.xml" in names or "classes.dex" in names:
        return "apk"
    if any(n.startswith("META-INF/") for n in names) and any(n.endswith(".class") for n in names):
        return "jar"
    return None


def sniff_bytes(head: bytes, *, suffix: str = "") -> str | None:
    """Kind from leading bytes only (used for remote files fetched by range)."""
    if head[:4] == b"GGUF":
        return "gguf"
    if head[:2] == b"MZ":
        return "pe_dotnet" if _is_dotnet_pe(head) else "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO_MAGICS:
        # 0xCAFEBABE is shared with Java classes; a fat Mach-O has a tiny arch count.
        if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8 and struct.unpack(">I", head[4:8])[0] > 30:
            return None
        return "macho"
    if head[:4] == b"\0asm":
        return "wasm"
    if len(head) >= 8 and suffix == ".safetensors":
        return "safetensors"
    if len(head) >= 16 and head[8:9] == b"{" and suffix in ("", ".safetensors"):
        # safetensors: u64 little-endian header length, then a JSON object.
        n = struct.unpack("<Q", head[:8])[0]
        if 2 <= n <= 100_000_000:
            return "safetensors"
    if head[:1] == b"\x80" and len(head) > 1 and head[1] in range(2, 6):
        return "pickle"
    if suffix in (".pkl", ".pickle", ".joblib", ".bin", ".pt", ".pth", ".ckpt") and head[:1] in (b"(", b"]", b"}", b"c"):
        return "pickle"  # protocol 0/1 pickles have no PROTO opcode
    if head[:4] == b"\x04\x00\x00\x00" and suffix == ".asar":
        return "asar"
    return None


def detect_kind(path: Path) -> str | None:
    """Return an artifact kind for `path`, or None when it is not an auditable artifact."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    suffix = path.suffix.lower()
    kind = sniff_bytes(head, suffix=suffix)
    if kind:
        return kind
    if head[:4] == b"PK\x03\x04":
        return _zip_kind(path)
    return None


def is_candidate(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in CANDIDATE_EXTENSIONS:
        return True
    if not suffix:
        try:
            return os.access(path, os.X_OK) and path.is_file()
        except OSError:
            return False
    return False


def is_model_kind(kind: str | None) -> bool:
    return kind in MODEL_KINDS


def is_binary_kind(kind: str | None) -> bool:
    return kind in BINARY_KINDS
