"""Provider adapter interface for multi-LLM key hunting."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    import httpx

    from llmhunter.models import BypassDetail, KeyIntelligence, ValidatedKey
    from llmhunter.network.session import SessionManager


@dataclass(frozen=True)
class KeyPattern:
    """Describes one key format for a provider."""

    name: str
    regex: re.Pattern[str]
    prefix: str
    length: int | None = None
    split_prefix: str | None = None
    base64_prefix: str | None = None
    hex_prefix: str | None = None

    def validate_format(self, key: str) -> bool:
        if self.length is not None and len(key) != self.length:
            return False
        if not key.startswith(self.prefix):
            return False
        return bool(self.regex.fullmatch(key))


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating a single key against a provider API."""

    status: str  # "valid", "forbidden", "rate_limited", "invalid", "unknown"
    status_code: int = 0
    raw_response: str = ""
    detail: str | None = None


class ProviderAdapter(ABC):
    """Contract that every LLM provider adapter must implement."""

    name: ClassVar[str]
    display_name: ClassVar[str]

    @abstractmethod
    def key_patterns(self) -> list[KeyPattern]:
        """Return all key formats this provider uses."""
        ...

    @abstractmethod
    def key_material_markers(self) -> tuple[str, ...]:
        """Cheap substring prefilter markers for may_contain_key_material()."""
        ...

    def validate_key_format(self, key: str) -> bool:
        """Post-extraction validation. Default checks against all patterns."""
        for pattern in self.key_patterns():
            if pattern.validate_format(key):
                return True
        return False

    @abstractmethod
    def validation_base_url(self) -> str:
        """Base URL for the provider's API."""
        ...

    @abstractmethod
    async def validate_key(
        self,
        key: str,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> ValidationResult:
        """Validate a single key against the provider's API."""
        ...

    @abstractmethod
    async def attempt_bypass(
        self,
        key: str,
        target_domain: str,
        source_urls: list[str],
        target_domains: list[str],
        client: httpx.AsyncClient,
        session: SessionManager,
        concurrency: int = 10,
        initial_reason: str | None = None,
    ) -> BypassDetail | None:
        """Attempt to bypass 403 restrictions. Returns BypassDetail or None."""
        ...

    @abstractmethod
    async def gather_intel(
        self,
        validated_key: ValidatedKey,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> dict[str, Any]:
        """Gather provider-specific intelligence. Returns flexible dict."""
        ...

    @abstractmethod
    def intel_field_names(self) -> list[str]:
        """Names of intelligence fields this provider populates."""
        ...

    @abstractmethod
    def generate_evidence_curls(self, result: KeyIntelligence) -> list[str]:
        """Generate curl commands that reproduce the finding."""
        ...
