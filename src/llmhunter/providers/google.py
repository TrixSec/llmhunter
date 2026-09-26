"""Google Gemini provider adapter."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

from llmhunter.models import BypassDetail, KeyIntelligence, KeyStatus, ValidatedKey
from llmhunter.providers.base import KeyPattern, ProviderAdapter, ValidationResult
from llmhunter.registry import register_provider

if TYPE_CHECKING:
    import httpx

    from llmhunter.network.session import SessionManager

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"


@register_provider
class GoogleProvider(ProviderAdapter):
    name: ClassVar[str] = "google"
    display_name: ClassVar[str] = "Google Gemini"

    def key_patterns(self) -> list[KeyPattern]:
        return [
            KeyPattern(
                name="api_key",
                regex=re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}"),
                prefix="AIzaSy",
                length=39,
                split_prefix="AIzaSy",
                base64_prefix="QUl6YVN5",
                hex_prefix=r"\x41\x49\x7a\x61\x53\x79",
            ),
        ]

    def key_material_markers(self) -> tuple[str, ...]:
        return (
            "AIzaSy",
            "QUl6YVN5",
            "\\x41\\x49\\x7a\\x61\\x53\\x79",
            "ySazIA",
        )

    def validation_base_url(self) -> str:
        return GEMINI_BASE_URL

    async def validate_key(
        self,
        key: str,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> ValidationResult:
        url = f"{GEMINI_BASE_URL}/v1beta/models?key={key}"
        resp = await session.fetch(client, url, timeout=10.0, max_retries=1)
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
        if resp.status_code == 403:
            reason = _google_error_reason(resp)
            return ValidationResult(
                status="forbidden",
                status_code=403,
                raw_response=resp.text,
                detail=reason,
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
        from llmhunter.providers.google_bypass import BypassEngine

        engine = BypassEngine()
        return await engine.run(
            key=key,
            target_domain=target_domain,
            client=client,
            session=session,
            source_urls=source_urls,
            target_domains=target_domains,
            concurrency=concurrency,
            initial_reason=initial_reason,
        )

    async def gather_intel(
        self,
        validated_key: ValidatedKey,
        client: httpx.AsyncClient,
        session: SessionManager,
    ) -> dict[str, Any]:
        return {}

    def intel_field_names(self) -> list[str]:
        return [
            "available_models",
            "tuned_models",
            "project_id",
            "project_name",
            "billing_enabled",
            "quota_remaining",
            "quota_limit",
        ]

    def generate_evidence_curls(self, result: KeyIntelligence) -> list[str]:
        return []


def _google_error_reason(resp: httpx.Response) -> str | None:
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("error"), dict):
        return None
    details = payload["error"].get("details", [])
    if not isinstance(details, list):
        return None
    for detail in details:
        if isinstance(detail, dict):
            reason = detail.get("reason")
            if isinstance(reason, str):
                return reason
    return None
