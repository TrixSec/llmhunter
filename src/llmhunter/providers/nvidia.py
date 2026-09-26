"""NVIDIA NIM provider adapter."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from llmhunter.models import BypassDetail, KeyIntelligence, ValidatedKey
from llmhunter.providers.base import KeyPattern, ProviderAdapter, ValidationResult
from llmhunter.registry import register_provider

if TYPE_CHECKING:
    import httpx

    from llmhunter.network.session import SessionManager

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com"


@register_provider
class NvidiaProvider(ProviderAdapter):
    name: ClassVar[str] = "nvidia"
    display_name: ClassVar[str] = "NVIDIA NIM"

    def key_patterns(self) -> list[KeyPattern]:
        return [
            KeyPattern(
                name="api_key",
                regex=re.compile(r"nvapi-[a-zA-Z0-9_-]{56}"),
                prefix="nvapi-",
                length=62,
            ),
        ]

    def key_material_markers(self) -> tuple[str, ...]:
        return ("nvapi-",)

    def validation_base_url(self) -> str:
        return NVIDIA_BASE_URL

    async def validate_key(
        self,
        key: str,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> ValidationResult:
        url = f"{NVIDIA_BASE_URL}/v1/models"
        headers = {"Authorization": f"Bearer {key}"}
        resp = await session.fetch(
            client, url, headers=headers, timeout=10.0, max_retries=1
        )
        if resp is None:
            return ValidationResult(status="unknown", detail="Request failed")

        if resp.status_code == 200:
            return ValidationResult(
                status="valid", status_code=200, raw_response=resp.text
            )
        if resp.status_code == 429:
            return ValidationResult(
                status="rate_limited",
                status_code=429,
                raw_response=resp.text,
                detail="Rate limited",
            )
        if resp.status_code == 401:
            return ValidationResult(
                status="invalid",
                status_code=401,
                raw_response=resp.text,
                detail="Invalid API key",
            )
        if resp.status_code == 403:
            return ValidationResult(
                status="forbidden",
                status_code=403,
                raw_response=resp.text,
            )
        return ValidationResult(
            status="invalid",
            status_code=resp.status_code,
            raw_response=resp.text,
        )

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
        return None

    async def gather_intel(
        self,
        validated_key: ValidatedKey,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> dict[str, Any]:
        return {}

    def intel_field_names(self) -> list[str]:
        return ["available_models"]

    def generate_evidence_curls(self, result: KeyIntelligence) -> list[str]:
        return []
