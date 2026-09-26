"""Unit tests for multi-provider key extraction and deobfuscation."""

from __future__ import annotations

from llmhunter.extraction.extractor import KeyExtractor
from llmhunter.models import DiscoveredSource, SourceType
from llmhunter.registry import all_providers
from tests.sandbox.fixtures import (
    MOCK_APP_JS,
    MOCK_CHUNK_0_JS,
    MOCK_CHUNK_1_JS,
    TEST_KEYS,
)


def test_extraction_from_mock_app():
    providers = all_providers()
    extractor = KeyExtractor(providers)

    source = DiscoveredSource(
        url="http://127.0.0.1/static/app.js",
        source_type=SourceType.JS_FILE,
        target_domain="127.0.0.1",
        content=MOCK_APP_JS,
    )

    extracted_strings = extractor.extract_from_source(source)
    found_keys = set(extracted_strings)

    assert TEST_KEYS["google_valid"] in found_keys
    assert TEST_KEYS["openai_project"] in found_keys
    assert TEST_KEYS["google_bypass"] in found_keys
    assert TEST_KEYS["google_rate_limited"] in found_keys
    assert TEST_KEYS["openai_standard"] in found_keys


def test_extraction_from_webpack_chunks():
    providers = all_providers()
    extractor = KeyExtractor(providers)

    chunk0 = DiscoveredSource(
        url="http://127.0.0.1/static/chunks/chunk.0.js",
        source_type=SourceType.WEBPACK_CHUNK,
        target_domain="127.0.0.1",
        content=MOCK_CHUNK_0_JS,
    )
    chunk1 = DiscoveredSource(
        url="http://127.0.0.1/static/chunks/chunk.1.js",
        source_type=SourceType.WEBPACK_CHUNK,
        target_domain="127.0.0.1",
        content=MOCK_CHUNK_1_JS,
    )

    extractor.extract_from_source(chunk0)
    extractor.extract_from_source(chunk1)
    found_keys = {k.key for k in extractor.all_keys}

    assert TEST_KEYS["openai_org"] in found_keys
    assert TEST_KEYS["google_bypass"] in found_keys
    assert TEST_KEYS["nvidia_valid"] in found_keys
