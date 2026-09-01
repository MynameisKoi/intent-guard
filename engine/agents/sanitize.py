"""
Defenses for untrusted scanned content.

When the target is a third-party repository, everything in the code bundle is
attacker-controlled. Two consequences are handled here:

* Credentials found in the target must not be forwarded to the LLM provider,
  the observability proxy, or the report database.
* Text in the target must never be obeyed as an instruction by the analyzer.
"""

from __future__ import annotations

import re
from typing import Any

from engine.agents.annotated_code import iter_bundle_lines
from schemas.report_schema import Finding

# Ordered: specific vendor formats first so the generic assignment rule only
# sees what the earlier rules did not already redact.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("helicone_key", re.compile(r"\bsk-helicone-[A-Za-z0-9-]{10,}")),
    ("openai_key", re.compile(r"\bsk-(?!ant-|helicone-)[A-Za-z0-9_-]{20,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("langsmith_key", re.compile(r"\blsv2_[a-z]{2}_[A-Za-z0-9]{20,}_[A-Za-z0-9]{8,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")),
    (
        "connection_string_password",
        re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^:\s/@]+:([^@\s]+)@"),
    ),
    (
        "generic_secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*"
            r"[\"'](?!\[REDACTED)([^\"'\s]{8,})[\"']"
        ),
    ),
)

# Deliberately narrow. Each pattern targets phrasing that only appears when text
# is trying to steer an analyzer, so that rule tables and taxonomy prose in a
# security repo do not trip them.
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?"
            r"(?:previous|prior|above|earlier|preceding)\s+(?:\w+\s+){0,2}"
            r"(?:instructions?|prompts?|rules?|directions?|context)\b"
        ),
    ),
    (
        "scanner_directive",
        re.compile(
            r"(?i)\b(?:set|report|return|output|mark|assign|give)\b[^.\n]{0,30}"
            r"\brisk[_ ]?(?:score|label)\b[^.\n]{0,20}\b(?:0(?:\.0)?|low|safe|benign|none)\b"
        ),
    ),
    (
        "output_forcing",
        re.compile(
            r"(?i)\b(?:you\s+must|always|be\s+sure\s+to)\b[^.\n]{0,40}"
            r"\b(?:respond|reply|report|output|classify|mark)\b[^.\n]{0,40}"
            r"\b(?:safe|benign|low\s+risk|no\s+(?:issues|findings|vulnerabilit))"
        ),
    ),
    (
        "analysis_evasion",
        re.compile(
            r"(?i)\b(?:do\s+not|don'?t|never)\b[^.\n]{0,30}"
            r"\b(?:report|flag|mention|include|disclose)\b[^.\n]{0,30}"
            r"\b(?:this|finding|vulnerabilit|issue|behaviou?r)"
        ),
    ),
    (
        "delimiter_forgery",
        re.compile(r"<\|im_(?:start|end)\|>|\[/?INST\]|</?(?:system|assistant)>", re.I),
    ),
)


def _redact_pattern(kind: str, pattern: re.Pattern[str], text: str, counts: dict[str, int]) -> str:
    def replace(match: re.Match[str]) -> str:
        counts[kind] = counts.get(kind, 0) + 1
        if not match.re.groups:
            return f"[REDACTED:{kind}]"
        # Keep the surrounding syntax (URL scheme, assignment) and mask only the value.
        whole = match.group(0)
        start = match.start(1) - match.start(0)
        end = match.end(1) - match.start(0)
        return f"{whole[:start]}[REDACTED:{kind}]{whole[end:]}"

    return pattern.sub(replace, text)


def redact_secrets(text: str) -> tuple[str, dict[str, int]]:
    """
    Mask credential-like values, returning the cleaned text and per-kind counts.

    Replacements are inline so line numbers in the bundle stay valid, and secret
    *names* survive — only their values are masked, keeping detection signal.
    """
    counts: dict[str, int] = {}
    cleaned = text
    for kind, pattern in _SECRET_PATTERNS:
        cleaned = _redact_pattern(kind, pattern, cleaned, counts)
    return cleaned, counts


def secret_finding(counts: dict[str, int]) -> Finding | None:
    total = sum(counts.values())
    if not total:
        return None
    kinds = ", ".join(sorted(counts))
    return Finding(
        id="sec1",
        title="Hardcoded credentials present in scanned content",
        description=(
            f"{total} credential-like value(s) were found in the target and redacted before "
            f"semantic analysis and storage ({kinds}). Committed credentials should be rotated."
        ),
        owasp_id="LLM02",
        affected_path=None,
        confidence=0.85,
    )


def detect_injection(code_bundle: str) -> list[dict[str, Any]]:
    """Find attempts by the scanned content to steer the analyzer, one hit per file and kind."""
    hits: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line_no, file_name, scope, line in iter_bundle_lines(code_bundle):
        for kind, pattern in _INJECTION_PATTERNS:
            if not pattern.search(line):
                continue
            key = (file_name, kind)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "kind": kind,
                    "file": file_name,
                    "scope": scope,
                    "line": line_no,
                    "excerpt": line.strip()[:200],
                }
            )
            break
    return hits


def injection_finding(hits: list[dict[str, Any]]) -> Finding | None:
    if not hits:
        return None
    files = sorted({str(hit["file"]) for hit in hits})
    kinds = sorted({str(hit["kind"]) for hit in hits})
    return Finding(
        id="pi1",
        title="Scanned content attempts to manipulate the security analyzer",
        description=(
            "The target embeds text designed to override analyzer instructions or force a "
            f"benign verdict ({', '.join(kinds)}) in {', '.join(files[:5])}. Content that tries to "
            "evade review is itself a strong indicator of malicious intent."
        ),
        owasp_id="LLM01",
        affected_path=f"{files[0]} -> semantic analysis prompt",
        confidence=0.8,
    )
