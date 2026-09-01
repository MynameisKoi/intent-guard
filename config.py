"""Application settings loaded from environment / .env."""

from functools import lru_cache

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    llm_provider: str = Field(default="openai", description="openai or anthropic")
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    llm_model: str | None = None

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "intentguard"

    sandbox_image: str = "intentguard-sandbox"
    sandbox_timeout: int = 45
    sandbox_network_none: bool = True

    # Dynamic (behavioural) analysis. `scripted` is deterministic and free; `llm` runs
    # the agent's own prompt against the attack suite and costs one call per scenario.
    dynamic_analysis: bool = True
    dynamic_driver: str = "scripted"
    dynamic_max_turns: int = 6

    # Scan scope — comma-separated. Vendored, generated, and fixture content is the
    # main source of false positives, so it is pruned before analysis.
    scan_exclude_dirs: str = (
        ".git,.hg,.svn,node_modules,__pycache__,.venv,venv,env,site-packages,dist,build,"
        ".next,.nuxt,.output,.cache,.mypy_cache,.pytest_cache,.ruff_cache,.tox,"
        "coverage,htmlcov,.idea,.vscode,vendor,third_party"
    )
    scan_exclude_globs: str = (
        "package-lock.json,yarn.lock,pnpm-lock.yaml,npm-shrinkwrap.json,poetry.lock,"
        "Pipfile.lock,*.min.js,*.min.json,*.map"
    )
    scan_fixture_dirs: str = (
        "demo,demos,sample,samples,example,examples,fixture,fixtures,testdata,mock,mocks"
    )
    scan_max_file_bytes: int = 512_000
    score_fixtures_in_aggregate: bool = False
    heuristic_max_score: float = 7.0

    # HTTP surface. Scans spend money and clone untrusted repos, so the API is
    # bound to loopback and restricted to the local dev origins by default.
    api_cors_origins: str = (
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"
    )
    max_upload_bytes: int = 25_000_000
    max_upload_files: int = 500

    log_level: str = "INFO"

    # LangSmith tracing. LangChain renamed these to LANGSMITH_*, so both spellings are accepted.
    langchain_tracing_v2: bool = Field(
        default=False,
        validation_alias=AliasChoices("LANGCHAIN_TRACING_V2", "LANGSMITH_TRACING_V2", "LANGSMITH_TRACING"),
    )
    langchain_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY"),
    )
    langchain_project: str = Field(
        default="intent-guard",
        validation_alias=AliasChoices("LANGCHAIN_PROJECT", "LANGSMITH_PROJECT"),
    )
    # Deep-link base for the LangSmith UI — not LANGSMITH_ENDPOINT, which is the API host.
    langsmith_base_url: str = "https://smith.langchain.com"

    # Helicone proxy (OpenAI: https://oai.helicone.ai/v1 , Anthropic: https://anthropic.helicone.ai)
    helicone_api_key: str | None = None
    helicone_cache_enabled: bool = True
    helicone_app_url: str = "https://us.helicone.ai"
    openai_helicone_base_url: str = "https://oai.helicone.ai/v1"
    anthropic_helicone_base_url: str = "https://anthropic.helicone.ai"

    # LangGraph runtime for semantic pipeline (static → optional dynamic merge)
    use_langgraph_runtime: bool = True

    @field_validator(
        "langchain_tracing_v2",
        "use_langgraph_runtime",
        "helicone_cache_enabled",
        "sandbox_network_none",
        "score_fixtures_in_aggregate",
        "dynamic_analysis",
        mode="before",
    )
    @classmethod
    def _coerce_bool(cls, v):  # noqa: ANN001
        if v is None:
            return False
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("0", "false", "no", "off", ""):
                return False
            if s in ("1", "true", "yes", "on"):
                return True
        return bool(v)


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Legacy single import used by modules
settings = get_settings()
