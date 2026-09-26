"""Pytest integration tests for LLMHunter using the testing sandbox."""

from __future__ import annotations

import pytest

from tests.sandbox.runner import SandboxRunner, patch_provider_urls


@pytest.fixture(scope="module")
def sandbox():
    runner = SandboxRunner()
    runner.start_servers()
    yield runner
    runner.stop_servers()


@pytest.mark.asyncio
async def test_full_web_scan_scenario(sandbox: SandboxRunner):
    passed, msg, details = await sandbox.run_scenario_full_web_scan()
    assert passed, f"Full web scan failed: {msg} (Details: {details})"


@pytest.mark.asyncio
async def test_direct_keys_scenario(sandbox: SandboxRunner):
    passed, msg, details = await sandbox.run_scenario_direct_keys()
    assert passed, f"Direct keys validation failed: {msg} (Details: {details})"


@pytest.mark.asyncio
async def test_provider_filtering_scenario(sandbox: SandboxRunner):
    passed, msg, details = await sandbox.run_scenario_provider_filtering()
    assert passed, f"Provider filtering failed: {msg} (Details: {details})"
