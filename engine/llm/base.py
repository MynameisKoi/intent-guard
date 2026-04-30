from abc import ABC, abstractmethod


class LLMClient(ABC):
    """Minimal chat interface for semantic analysis."""

    @abstractmethod
    def complete(self, *, system: str, user: str, no_cache: bool = False) -> str:
        raise NotImplementedError
