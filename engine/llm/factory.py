import logging

from config import settings
from engine.llm.anthropic_client import AnthropicLLM
from engine.llm.base import LLMClient
from engine.llm.openai_client import OpenAILLM

logger = logging.getLogger(__name__)


def get_llm_client() -> LLMClient | None:
    provider = (settings.llm_provider or "openai").lower().strip()
    try:
        if provider == "openai":
            return OpenAILLM()
        if provider == "anthropic":
            return AnthropicLLM()
        logger.warning("Unknown LLM_PROVIDER %s", provider)
        return None
    except Exception as e:
        logger.warning("LLM client unavailable: %s", e)
        return None
