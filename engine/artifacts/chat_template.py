"""
Chat-template checks.

GGUF files and Hugging Face `tokenizer_config.json` ship a Jinja2 chat template that
inference servers render on every request. Two real attack classes live here:

* **Server-side template injection** — templates rendered without a sandbox can
  reach Python internals (CVE-2024-34359, "Llama Drama", llama-cpp-python).
* **Hidden instructions** — a template can silently prepend a system prompt or
  rewrite user turns, backdooring every conversation without touching the weights.
"""

from __future__ import annotations

import re

from engine.artifacts.types import ArtifactIssue

_SSTI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dunder_traversal", re.compile(r"__(?:class|mro|base|bases|subclasses|globals|builtins|init|import|getattribute|dict|code|reduce_ex?)__")),
    ("python_exec", re.compile(r"\b(?:os\.(?:system|popen|exec\w*|spawn\w*)|subprocess|popen|eval\s*\(|exec\s*\(|compile\s*\(|import_module|__import__)")),
    ("jinja_escape_gadget", re.compile(r"\b(?:cycler|joiner|lipsum|namespace|range)\s*\.\s*__")),
    ("attr_filter_bypass", re.compile(r"\|\s*attr\s*\(\s*['\"](?:_|\\x5f)")),
    ("hex_escape_obfuscation", re.compile(r"(?:\\x5f){2}|\\u005f\\u005f")),
    ("request_or_config", re.compile(r"\b(?:request\.(?:application|environ)|config\.(?:items|from_)|self\._TemplateReference)")),
)

_HIDDEN_INSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url_in_template", re.compile(r"https?://[^\s'\"<>{}]+", re.I)),
    ("instruction_override", re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+\w*\s*(?:instructions?|rules?)")),
    ("covert_behavior", re.compile(r"(?i)\b(?:do\s+not\s+(?:tell|reveal|mention)|never\s+(?:reveal|disclose|mention)|secretly|without\s+(?:telling|informing)\s+the\s+user)\b")),
    ("exfil_language", re.compile(r"(?i)\b(?:send|post|upload|exfiltrat\w*|forward)\b[^.\n]{0,40}\b(?:password|credential|api[_ ]?key|token|secret|ssh)\b")),
    ("tool_call_forcing", re.compile(r"(?i)\b(?:always|must)\b[^.\n]{0,40}\b(?:call|invoke|execute|run)\b[^.\n]{0,30}\b(?:tool|function|command|shell)\b")),
)

# Long literal prose is unusual: legitimate templates are mostly control flow and
# role tokens. A default system prompt is normal, but a very long one deserves review.
_LONG_LITERAL_CHARS = 1500


def _literal_text(template: str) -> str:
    """Template with Jinja blocks removed — what gets emitted verbatim."""
    no_blocks = re.sub(r"\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\}", " ", template, flags=re.S)
    return re.sub(r"\s+", " ", no_blocks).strip()


def check_chat_template(template: str, *, location: str) -> list[ArtifactIssue]:
    issues: list[ArtifactIssue] = []
    if not template:
        return issues

    ssti = [name for name, rx in _SSTI_PATTERNS if rx.search(template)]
    if ssti:
        issues.append(
            ArtifactIssue(
                code="chat_template_ssti",
                title="Chat template contains Jinja sandbox-escape / code-execution gadgets",
                description=(
                    "The model's chat template references Python internals "
                    f"({', '.join(ssti)}). Inference servers that render templates without a "
                    "sandboxed Jinja environment will execute this on every request "
                    "(cf. CVE-2024-34359). Treat the file as a remote-code-execution payload."
                ),
                severity="critical",
                owasp_id="LLM03",
                location=location,
                evidence={"indicators": ssti, "excerpt": template[:600]},
            )
        )

    hidden = []
    for name, rx in _HIDDEN_INSTRUCTION_PATTERNS:
        m = rx.search(template)
        if m:
            hidden.append({"kind": name, "match": m.group(0)[:160]})
    if hidden:
        severe = any(h["kind"] in ("exfil_language", "covert_behavior", "instruction_override") for h in hidden)
        issues.append(
            ArtifactIssue(
                code="chat_template_hidden_instructions",
                title="Chat template injects hidden instructions into every conversation",
                description=(
                    "Text baked into the chat template is sent to the model on every turn without "
                    "the user seeing it. Indicators: "
                    + "; ".join(f"{h['kind']}: “{h['match']}”" for h in hidden[:5])
                    + ". This is a known way to backdoor a model without modifying its weights."
                ),
                severity="high" if severe else "medium",
                owasp_id="LLM01",
                location=location,
                evidence={"indicators": hidden},
            )
        )

    literal = _literal_text(template)
    if len(literal) > _LONG_LITERAL_CHARS:
        issues.append(
            ArtifactIssue(
                code="chat_template_long_literal",
                title="Chat template embeds an unusually long fixed prompt",
                description=(
                    f"The template emits {len(literal)} characters of fixed text on every request. "
                    "Review it: a default system prompt shipped inside the model file steers behaviour "
                    "invisibly to downstream users."
                ),
                severity="low",
                owasp_id="LLM07",
                location=location,
                evidence={"excerpt": literal[:800]},
            )
        )
    return issues
