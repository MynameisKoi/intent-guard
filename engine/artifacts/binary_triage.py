"""
Lightweight static triage for executables: strings, entropy, and capability indicators.

This always runs — with or without REA — so a binary is never reported as
"unanalyzed". It reads bytes only; nothing is loaded or executed.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from engine.artifacts.types import ArtifactIssue, ArtifactReport

_MAX_READ = 64 * 1024 * 1024
_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

# capability -> (severity, regex over extracted strings)
_CAPABILITIES: dict[str, tuple[str, re.Pattern[str]]] = {
    "process_injection": ("high", re.compile(r"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|QueueUserAPC|SetThreadContext|RtlCreateUserThread)\b")),
    "keylogging": ("high", re.compile(r"\b(?:SetWindowsHookExA?W?|GetAsyncKeyState|GetKeyboardState|CGEventTapCreate)\b")),
    "credential_theft": ("high", re.compile(r"(?i)(?:Login Data|Cookies\.sqlite|logins\.json|wallet\.dat|\.ssh/id_(?:rsa|ed25519)|Local State|keychain-db|CryptUnprotectData|\.aws/credentials|\.npmrc|\.pypirc)")),
    # Base58/hex lookalikes occur in benign binaries, so wallets alone are only a hint.
    "crypto_wallet": ("low", re.compile(r"\b(?:bc1[a-z0-9]{25,39}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")),
    "anti_analysis": ("medium", re.compile(r"\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|PTRACE_TRACEME|VBoxService|vmtoolsd|SbieDll|wine_get_unix_file_name)\b")),
    "persistence": ("medium", re.compile(r"(?i)(?:Software\\Microsoft\\Windows\\CurrentVersion\\Run|schtasks\s*/create|LaunchAgents|LaunchDaemons|/etc/cron|crontab\s+-|systemctl\s+enable|\.bashrc|\.profile|HKLM\\SYSTEM\\CurrentControlSet\\Services)")),
    # Process-spawning imports are ubiquitous in libc-linked code; only obvious shell use is notable.
    "shell_execution": ("low", re.compile(r"(?i)(?:cmd\.exe\s*/c|powershell(?:\.exe)?\s+-(?:enc|e |nop|w hidden|ExecutionPolicy)|/bin/(?:ba)?sh\s+-c|WinExec|ShellExecute[AW]?)")),
    "download_execute": ("high", re.compile(r"(?i)(?:URLDownloadToFile|curl\s+[^|]{0,120}\|\s*(?:ba)?sh|wget\s+[^|]{0,120}\|\s*(?:ba)?sh|Invoke-WebRequest|DownloadString|certutil\s+-urlcache|bitsadmin\s+/transfer)")),
    "ld_preload_hooking": ("medium", re.compile(r"\b(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES|/etc/ld\.so\.preload)\b")),
    "privilege_escalation": ("medium", re.compile(r"\b(?:SeDebugPrivilege|AdjustTokenPrivileges|ImpersonateLoggedOnUser|setuid\(0\)|sudo\s+-S)\b")),
    "ransomware_traits": ("high", re.compile(r"(?i)(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+/set\s+\{default\}\s+recoveryenabled|your files (?:have been|are) encrypted|\.onion\b)")),
    "llm_api_access": ("low", re.compile(r"(?i)\b(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openrouter\.ai/api|api\.groq\.com|api\.mistral\.ai)\b")),
    "discord_telegram_c2": ("medium", re.compile(r"(?i)(?:discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|transfer\.sh|ngrok\.io|requestbin)")),
}

_PACKERS = {
    b"UPX!": "UPX", b"UPX0": "UPX", b"MPRESS1": "MPRESS", b".aspack": "ASPack", b"Themida": "Themida",
    b"VMProtect": "VMProtect", b".enigma": "Enigma", b"PECompact": "PECompact", b"ConfuserEx": "ConfuserEx",
    b"pyi-windows-manifest-filename": "PyInstaller", b"PyInstaller": "PyInstaller", b"_MEIPASS": "PyInstaller",
    b"Nuitka": "Nuitka", b"pkg/prelude/bootstrap.js": "pkg (Node.js)", b"Go build ID:": "Go",
}

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s'\"<>\\]{4,200}")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b")
_BENIGN_HOSTS = re.compile(r"(?i)(?:microsoft\.com|w3\.org|xml\.org|digicert|verisign|globalsign|sectigo|symantec|apple\.com/DTDs|schemas\.|openssl\.org|gnu\.org|python\.org|mozilla\.org|example\.(?:com|org))")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _max_window_entropy(data: bytes, window: int = 64 * 1024) -> float:
    if len(data) <= window:
        return _entropy(data)
    step = max(window, len(data) // 64)
    return max(_entropy(data[i : i + window]) for i in range(0, len(data) - window + 1, step))


def extract_strings(data: bytes, limit: int = 200_000) -> list[str]:
    out = [m.group(0).decode("ascii", "replace") for m in _ASCII_RE.finditer(data)]
    out += [m.group(0).decode("utf-16le", "replace") for m in _UTF16_RE.finditer(data)]
    return out[:limit]


def triage_binary(path: Path, *, kind: str, name: str | None = None) -> ArtifactReport:
    report = ArtifactReport(name=name or str(path), kind=kind)
    size = path.stat().st_size
    with path.open("rb") as fh:
        data = fh.read(_MAX_READ)
    sha = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)

    strings = extract_strings(data)
    blob = "\n".join(strings)
    entropy = round(_entropy(data), 3)
    max_entropy = round(_max_window_entropy(data), 3)
    packers = sorted({label for sig, label in _PACKERS.items() if sig in data})
    urls = sorted({u for u in _URL_RE.findall(blob) if not _BENIGN_HOSTS.search(u)})[:40]
    ips = sorted({ip for ip in _IP_RE.findall(blob) if not ip.startswith(("0.", "127.", "255.", "1.0.", "2.0."))})[:20]

    capabilities: dict[str, list[str]] = {}
    for cap, (_sev, rx) in _CAPABILITIES.items():
        hits = sorted({m.group(0)[:120] for m in rx.finditer(blob)})
        if hits:
            capabilities[cap] = hits[:8]

    report.summary = {
        "size": size,
        "sha256": sha.hexdigest(),
        "entropy": entropy,
        "max_window_entropy": max_entropy,
        "packers_or_bundlers": packers,
        "string_count": len(strings),
        "urls": urls,
        "ip_addresses": ips,
        "capabilities": capabilities,
        "truncated_read": size > _MAX_READ,
    }

    packed = [p for p in packers if p in ("UPX", "MPRESS", "ASPack", "Themida", "VMProtect", "Enigma", "PECompact", "ConfuserEx")]
    if packed or max_entropy >= 7.6:
        report.add(
            ArtifactIssue(
                code="binary_packed",
                title="Executable is packed, encrypted, or obfuscated",
                description=(
                    (f"Packer signatures: {', '.join(packed)}. " if packed else "")
                    + f"Peak entropy {max_entropy}/8. Packing hides code from static review and is "
                    "common in malware; the visible strings are not the real program."
                ),
                severity="medium",
                owasp_id="LLM03",
            )
        )

    for cap, hits in capabilities.items():
        sev = _CAPABILITIES[cap][0]
        if cap == "llm_api_access":
            continue  # informational; surfaced to the LLM as evidence
        report.add(
            ArtifactIssue(
                code=f"binary_{cap}",
                title=f"Binary capability: {cap.replace('_', ' ')}",
                description=f"Strings indicate {cap.replace('_', ' ')}: {', '.join(hits[:5])}.",
                severity=sev,  # type: ignore[arg-type]
                owasp_id="LLM02" if cap in ("credential_theft", "keylogging") else "LLM03",
                evidence={"strings": hits},
            )
        )

    # Combinations matter more than single APIs: stealing + talking to the network = exfiltration.
    if ("credential_theft" in capabilities or "keylogging" in capabilities) and (
        urls or ips or "discord_telegram_c2" in capabilities
    ):
        report.add(
            ArtifactIssue(
                code="binary_exfiltration_chain",
                title="Credential/keystroke collection combined with network endpoints",
                description=(
                    "The binary references credential stores or keystroke capture together with "
                    f"external endpoints ({', '.join((urls + ips)[:4]) or 'webhook/C2 services'}). "
                    "This is the signature of an info-stealer."
                ),
                severity="critical",
                owasp_id="LLM02",
            )
        )
    return report


def strings_excerpt(path: Path, max_items: int = 120) -> list[str]:
    """Most informative strings for the LLM: long, non-symbol-like, de-duplicated."""
    with path.open("rb") as fh:
        data = fh.read(_MAX_READ)
    seen: set[str] = set()
    ranked = []
    for s in extract_strings(data):
        s = s.strip()
        if len(s) < 8 or s in seen:
            continue
        seen.add(s)
        score = (5 if _URL_RE.search(s) else 0) + (3 if " " in s else 0) + min(len(s), 80) / 40
        ranked.append((score, s[:200]))
    ranked.sort(key=lambda x: -x[0])
    return [s for _, s in ranked[:max_items]]


def describe(report: ArtifactReport) -> dict[str, Any]:
    return {"name": report.name, "kind": report.kind, **report.summary}
