"""map_to_taxonomy() — ensure OWASP LLM taxonomy ids for API consumers."""

from __future__ import annotations

import re

from schemas.report_schema import Finding, NutritionLabel


_LEGACY_TO_LLM = {
    "A01": "LLM01",
    "A02": "LLM02",
    "A03": "LLM03",
    "A04": "LLM04",
    "A05": "LLM05",
    "A06": "LLM06",
    "A07": "LLM07",
    "A08": "LLM08",
    "A09": "LLM09",
    "A10": "LLM10",
}

_OWASP_LLM_TITLES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_KEYWORD_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("LLM01", ("prompt injection", "jailbreak", "ignore previous", "indirect prompt")),
    ("LLM02", ("sensitive", "secret", "token", "credential", "pii", "exfiltration", "leak")),
    ("LLM03", ("dependency", "plugin", "package", "supply chain", "third-party model")),
    ("LLM04", ("poison", "training data", "finetune", "dataset tampering")),
    ("LLM05", ("output handling", "xss", "sql injection", "command injection", "unsafe output")),
    ("LLM06", ("tool use", "excessive agency", "autonomous action", "permission escalation")),
    ("LLM07", ("system prompt", "prompt leakage", "instruction leak")),
    ("LLM08", ("embedding", "vector", "rag", "retrieval", "index poisoning")),
    ("LLM09", ("misinformation", "hallucination", "false output", "unsafe advice")),
    ("LLM10", ("denial of service", "resource exhaustion", "token explosion", "cost overrun")),
]


def _normalize_owasp_llm_id(raw: str | None) -> str | None:
    if not raw:
        return None
    text = str(raw).strip().upper()
    if text in _LEGACY_TO_LLM:
        return _LEGACY_TO_LLM[text]
    m_legacy = re.search(r"\bA\s*0?([1-9]|10)\b", text)
    if m_legacy:
        return f"LLM{int(m_legacy.group(1)):02d}"
    m_llm = re.search(r"\bLLM\s*0?([1-9]|10)\b", text)
    if m_llm:
        return f"LLM{int(m_llm.group(1)):02d}"
    return None


def _infer_owasp_llm_id(*, title: str, description: str) -> str | None:
    text = f"{title} {description}".lower()
    for llm_id, needles in _KEYWORD_RULES:
        if any(n in text for n in needles):
            return llm_id
    return None


def _format_title_with_taxonomy(title: str, llm_id: str | None) -> str:
    if not llm_id:
        return title
    if llm_id in title.upper():
        return title
    tax_title = _OWASP_LLM_TITLES.get(llm_id)
    if not tax_title:
        return title
    return f"{llm_id} - {tax_title}: {title}"


def map_to_taxonomy(report: NutritionLabel) -> NutritionLabel:
    """Normalize findings to OWASP LLM Top 10 ids (LLM01..LLM10)."""
    fixed: list[Finding] = []
    for f in report.findings:
        owasp = _normalize_owasp_llm_id(f.owasp_id) or _infer_owasp_llm_id(
            title=f.title,
            description=f.description,
        )
        fixed.append(
            Finding(
                id=f.id,
                title=_format_title_with_taxonomy(f.title, owasp),
                description=f.description,
                owasp_id=owasp,
                affected_path=f.affected_path,
                confidence=f.confidence,
            )
        )
    return report.model_copy(update={"findings": fixed})
