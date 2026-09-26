"""Anthropic provider adapter."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from llmhunter.models import BypassDetail, KeyIntelligence, ValidatedKey
from llmhunter.providers.base import KeyPattern, ProviderAdapter, ValidationResult
from llmhunter.registry import register_provider

if TYPE_CHECKING:
    import httpx

    from llmhunter.network.session import SessionManager

ANTHROPIC_BASE_URL = "https://api.anthropic.com"


@register_provider
class AnthropicProvider(ProviderAdapter):
    name: ClassVar[str] = "anthropic"
    display_name: ClassVar[str] = "Anthropic"

    def key_patterns(self) -> list[KeyPattern]:
        return [
            KeyPattern(
                name="api_key",
                regex=re.compile(r"sk-ant-api03-[a-zA-Z0-9_-]{95}"),
                prefix="sk-ant-api03-",
                length=108,
            ),
            KeyPattern(
                name="api_key_legacy",
                regex=re.compile(r"sk-ant-[a-zA-Z0-9_-]{32,}"),
                prefix="sk-ant-",
            ),
        ]

    def key_material_markers(self) -> tuple[str, ...]:
        return ("sk-ant-api03-", "sk-ant-")

    def validation_base_url(self) -> str:
        return ANTHROPIC_BASE_URL

    async def validate_key(
        self,
        key: str,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> ValidationResult:
        url = f"{ANTHROPIC_BASE_URL}/v1/messages"
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        body = (
            '{"model":"claude-sonnet-4-20250514","max_tokens":1,'
            '"messages":[{"role":"user","content":"hi"}]}'
        )
        resp = await session.fetch(
            client,
            url,
            method="POST",
            headers=headers,
            data=body,
            timeout=10.0,
            max_retries=1,
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
        return ["available_models", "rate_limit_status"]

    def generate_evidence_curls(self, result: KeyIntelligence) -> list[str]:
        return []
