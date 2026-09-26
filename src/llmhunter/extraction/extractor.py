"""Multi-provider API key extraction and deduplication engine."""

from __future__ import annotations

import base64
import logging
import re
from typing import TYPE_CHECKING

from llmhunter.models import DiscoveredSource, ExtractedKey

if TYPE_CHECKING:
    from llmhunter.providers.base import ProviderAdapter

logger = logging.getLogger("llmhunter")

# Generic obfuscation patterns applied per-provider prefix
_SPLIT_CONCAT_TPL = r"""["']{prefix}["']\s*\+\s*["']([a-zA-Z0-9_-]+)["']"""
_ARRAY_JOIN_TPL = r"""\["{prefix}"\s*,\s*"([a-zA-Z0-9_-]+)"\]\s*\.\s*join\s*\(\s*["']["']\s*\)"""
_TEMPLATE_TPL = r"""`{prefix}\$\{{([^}}]+)\}}`"""
_MULTILINE_CONCAT_TPL = r"""["']{prefix}["']\s*(?:\+\s*["'][a-zA-Z0-9_-]+["']\s*){{2,}}"""
_FALLBACK_TPL = r"""\|\|\s*["']({prefix}[a-zA-Z0-9_-]{{{suffix_len}}})["']"""
_HEX_PREFIX_TPL = r"""(?:{hex_prefix})([a-zA-Z0-9_-]{{{suffix_len}}})"""
_BASE64_TPL = r"""["']({b64_prefix}[A-Za-z0-9+/\-_]{{{b64_suffix_len}}}=?=?)["']"""
_REVERSE_TPL = r"""["']([a-zA-Z0-9_-]{{{suffix_len}}}{reversed_prefix})["']"""
_CONCAT_PART_RE = re.compile(r"""["']([a-zA-Z0-9_-]+)["']""")


def _build_obfuscation_patterns(
    prefix: str,
    suffix_len: int,
    hex_prefix: str | None = None,
    base64_prefix: str | None = None,
) -> dict[str, re.Pattern[str]]:
    patterns: dict[str, re.Pattern[str]] = {}
    escaped = re.escape(prefix)

    patterns["split_concat"] = re.compile(
        _SPLIT_CONCAT_TPL.format(prefix=escaped), re.MULTILINE
    )
    patterns["array_join"] = re.compile(
        _ARRAY_JOIN_TPL.format(prefix=escaped), re.MULTILINE
    )
    patterns["template"] = re.compile(
        _TEMPLATE_TPL.format(prefix=escaped), re.MULTILINE
    )
    patterns["multiline_concat"] = re.compile(
        _MULTILINE_CONCAT_TPL.format(prefix=escaped), re.DOTALL
    )
    patterns["fallback"] = re.compile(
        _FALLBACK_TPL.format(prefix=escaped, suffix_len=suffix_len)
    )
    patterns["reverse"] = re.compile(
        _REVERSE_TPL.format(
            suffix_len=suffix_len, reversed_prefix=re.escape(prefix[::-1])
        )
    )

    if hex_prefix:
        patterns["hex"] = re.compile(
            _HEX_PREFIX_TPL.format(hex_prefix=hex_prefix, suffix_len=suffix_len)
        )

    if base64_prefix:
        b64_suffix_len = max(1, (len(prefix) + suffix_len) * 4 // 3 - len(base64_prefix))
        patterns["base64"] = re.compile(
            _BASE64_TPL.format(
                b64_prefix=re.escape(base64_prefix), b64_suffix_len=b64_suffix_len
            )
        )

    return patterns


class KeyExtractor:
    """Extracts and deduplicates API keys from multiple providers."""

    def __init__(self, providers: list[ProviderAdapter]):
        self._providers = providers
        self._seen: dict[str, ExtractedKey] = {}

        self._all_markers: tuple[str, ...] = tuple(
            m for p in providers for m in p.key_material_markers()
        )

        self._provider_patterns: list[
            tuple[ProviderAdapter, list[re.Pattern[str]], dict[str, re.Pattern[str]]]
        ] = []
        for provider in providers:
            direct_regexes = [kp.regex for kp in provider.key_patterns()]
            obf_patterns: dict[str, re.Pattern[str]] = {}
            for kp in provider.key_patterns():
                if kp.split_prefix or kp.hex_prefix or kp.base64_prefix:
                    suffix_len = (kp.length - len(kp.prefix)) if kp.length else 33
                    obf_patterns.update(
                        _build_obfuscation_patterns(
                            kp.prefix,
                            suffix_len,
                            kp.hex_prefix,
                            kp.base64_prefix,
                        )
                    )
            self._provider_patterns.append((provider, direct_regexes, obf_patterns))

    def may_contain_key_material(self, text: str) -> bool:
        return any(marker in text for marker in self._all_markers)

    def extract_from_source(
        self, source: DiscoveredSource, content: str | None = None
    ) -> list[str]:
        text = content if content is not None else source.content
        found_keys: set[tuple[str, str]] = set()

        for provider, direct_regexes, obf_patterns in self._provider_patterns:
            for regex in direct_regexes:
                for match in regex.findall(text):
                    if provider.validate_key_format(match):
                        found_keys.add((match, provider.name))

            if "split_concat" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.split_prefix:
                        continue
                    suffix_len = (kp.length - len(kp.prefix)) if kp.length else 33
                    for match in obf_patterns["split_concat"].finditer(text):
                        suffix = match.group(1)
                        if len(suffix) == suffix_len:
                            candidate = f"{kp.prefix}{suffix}"
                            if provider.validate_key_format(candidate):
                                found_keys.add((candidate, provider.name))

            if "array_join" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.split_prefix:
                        continue
                    suffix_len = (kp.length - len(kp.prefix)) if kp.length else 33
                    for match in obf_patterns["array_join"].finditer(text):
                        suffix = match.group(1)
                        if len(suffix) == suffix_len:
                            candidate = f"{kp.prefix}{suffix}"
                            if provider.validate_key_format(candidate):
                                found_keys.add((candidate, provider.name))

            if "reverse" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.split_prefix:
                        continue
                    for match in obf_patterns["reverse"].finditer(text):
                        reversed_key = match.group(1)[::-1]
                        if provider.validate_key_format(reversed_key):
                            found_keys.add((reversed_key, provider.name))

            if "template" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.split_prefix:
                        continue
                    suffix_len = (kp.length - len(kp.prefix)) if kp.length else 33
                    for match in obf_patterns["template"].finditer(text):
                        inner = match.group(1).strip().strip("\"'")
                        if re.fullmatch(rf"[a-zA-Z0-9_-]{{{suffix_len}}}", inner):
                            candidate = f"{kp.prefix}{inner}"
                            if provider.validate_key_format(candidate):
                                found_keys.add((candidate, provider.name))

            if "multiline_concat" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.split_prefix:
                        continue
                    suffix_len = (kp.length - len(kp.prefix)) if kp.length else 33
                    for match in obf_patterns["multiline_concat"].finditer(text):
                        parts = _CONCAT_PART_RE.findall(match.group(0))
                        if parts and parts[0] == kp.prefix:
                            suffix = "".join(parts[1:])
                            if len(suffix) == suffix_len:
                                candidate = f"{kp.prefix}{suffix}"
                                if provider.validate_key_format(candidate):
                                    found_keys.add((candidate, provider.name))

            if "fallback" in obf_patterns:
                for match in obf_patterns["fallback"].finditer(text):
                    candidate = match.group(1)
                    if provider.validate_key_format(candidate):
                        found_keys.add((candidate, provider.name))

            if "hex" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.hex_prefix:
                        continue
                    for match in obf_patterns["hex"].finditer(text):
                        candidate = f"{kp.prefix}{match.group(1)}"
                        if provider.validate_key_format(candidate):
                            found_keys.add((candidate, provider.name))

            if "base64" in obf_patterns:
                for kp in provider.key_patterns():
                    if not kp.base64_prefix:
                        continue
                    for match in obf_patterns["base64"].finditer(text):
                        try:
                            b64str = match.group(1).replace("-", "+").replace("_", "/")
                            decoded = base64.b64decode(b64str).decode("ascii")
                            if provider.validate_key_format(decoded):
                                found_keys.add((decoded, provider.name))
                        except Exception:
                            pass

        new_keys: list[str] = []
        for key, prov_name in found_keys:
            if key in self._seen:
                existing = self._seen[key]
                if source.url not in existing.sources:
                    existing.sources.append(source.url)
                if source.source_type not in existing.source_types:
                    existing.source_types.append(source.source_type)
                if (
                    source.target_domain
                    and source.target_domain not in existing.target_domains
                ):
                    existing.target_domains.append(source.target_domain)
            else:
                self._seen[key] = ExtractedKey(
                    key=key,
                    provider=prov_name,
                    sources=[source.url],
                    source_types=[source.source_type],
                    target_domain=source.target_domain,
                    target_domains=(
                        [source.target_domain] if source.target_domain else []
                    ),
                )
                new_keys.append(key)

        if new_keys:
            logger.info(f"Found {len(new_keys)} new key(s) in {source.url}")

        return new_keys

    @property
    def all_keys(self) -> list[ExtractedKey]:
        return list(self._seen.values())

    @property
    def count(self) -> int:
        return len(self._seen)
