from engine.agents.owasp import map_to_taxonomy
from schemas.report_schema import Finding, NutritionLabel


def test_map_to_taxonomy_normalizes_to_llm_ids():
    report = NutritionLabel(
        intent_summary="x",
        risk_score=5.0,
        findings=[
            Finding(id="f1", title="Prompt risk", description="prompt injection path", owasp_id="A01"),
            Finding(id="f2", title="Leak risk", description="sensitive token exfiltration", owasp_id="LLM02:2025"),
        ],
    )
    mapped = map_to_taxonomy(report)
    assert mapped.findings[0].owasp_id == "LLM01"
    assert mapped.findings[1].owasp_id == "LLM02"
    assert mapped.findings[0].title.startswith("LLM01 - ")


def test_map_to_taxonomy_infers_id_when_missing():
    report = NutritionLabel(
        intent_summary="x",
        risk_score=5.0,
        findings=[
            Finding(
                id="f3",
                title="Unsafe tool autonomy",
                description="Agent can perform autonomous action with no permission checks",
                owasp_id=None,
            )
        ],
    )
    mapped = map_to_taxonomy(report)
    assert mapped.findings[0].owasp_id == "LLM06"
