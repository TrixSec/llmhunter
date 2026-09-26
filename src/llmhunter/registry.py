"""Provider registry with decorator-based auto-registration."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llmhunter.providers.base import ProviderAdapter

_PROVIDER_REGISTRY: dict[str, type[ProviderAdapter]] = {}


def register_provider(cls: type[ProviderAdapter]) -> type[ProviderAdapter]:
    """Decorator to register a provider adapter class."""
    _PROVIDER_REGISTRY[cls.name] = cls
    return cls


def get_provider(name: str) -> ProviderAdapter:
    """Get an instantiated provider adapter by name."""
    cls = _PROVIDER_REGISTRY.get(name)
    if cls is None:
        available = ", ".join(sorted(_PROVIDER_REGISTRY)) or "(none)"
        raise ValueError(f"Unknown provider '{name}'. Available: {available}")
    return cls()


def list_providers() -> list[str]:
    """Return sorted list of registered provider names."""
    return sorted(_PROVIDER_REGISTRY)


def all_providers() -> list[ProviderAdapter]:
    """Return instantiated adapters for all registered providers."""
    return [cls() for cls in _PROVIDER_REGISTRY.values()]


def _ensure_loaded() -> None:
    """Import all known provider modules to trigger registration."""
    from llmhunter.providers import google  # noqa: F401
    from llmhunter.providers import openai  # noqa: F401
    from llmhunter.providers import anthropic  # noqa: F401
    from llmhunter.providers import nvidia  # noqa: F401
