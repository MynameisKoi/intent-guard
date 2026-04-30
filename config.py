"""Application settings loaded from environment / .env."""

from functools import lru_cache

from pydantic import Field, field_validator
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

    log_level: str = "INFO"

    # LangSmith (LangChain tracing) — set LANGCHAIN_API_KEY in .env
    langchain_tracing_v2: bool = False
    langchain_api_key: str | None = None
    langchain_project: str = "intent-guard"
    langsmith_base_url: str = "https://smith.langchain.com"

    # Helicone proxy (OpenAI: https://oai.helicone.ai/v1 , Anthropic: https://anthropic.helicone.ai)
    helicone_api_key: str | None = None
    helicone_cache_enabled: bool = True
    helicone_app_url: str = "https://app.helicone.ai"
    openai_helicone_base_url: str = "https://oai.helicone.ai/v1"
    anthropic_helicone_base_url: str = "https://anthropic.helicone.ai"

    # LangGraph runtime for semantic pipeline (static → optional dynamic merge)
    use_langgraph_runtime: bool = True

    @field_validator(
        "langchain_tracing_v2",
        "use_langgraph_runtime",
        "helicone_cache_enabled",
        "sandbox_network_none",
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
