"""Offline Testing Sandbox Runner for LLMHunter.

Spins up a mock target web server and mock LLM provider API server,
executes comprehensive end-to-end tests against all supported providers,
and displays test results in the terminal.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import time
from typing import Generator

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import llmhunter.providers.anthropic as anthropic_mod
import llmhunter.providers.google as google_mod
import llmhunter.providers.google_bypass as google_bypass_mod
import llmhunter.providers.nvidia as nvidia_mod
import llmhunter.providers.openai as openai_mod
from llmhunter.config import Config
from llmhunter.models import KeyStatus
from llmhunter.pipeline import Pipeline
from tests.sandbox.fixtures import TEST_KEYS
from tests.sandbox.mock_provider_server import MockProviderServer
from tests.sandbox.mock_target_server import MockTargetServer

console = Console(force_terminal=True, legacy_windows=False)


@contextlib.contextmanager
def patch_provider_urls(base_url: str) -> Generator[None, None, None]:
    """Redirect all provider adapters to the local mock LLM provider server."""
    orig_google = google_mod.GEMINI_BASE_URL
    orig_google_bp = google_bypass_mod.GEMINI_BASE_URL
    orig_openai = openai_mod.OPENAI_BASE_URL
    orig_anthropic = anthropic_mod.ANTHROPIC_BASE_URL
    orig_nvidia = nvidia_mod.NVIDIA_BASE_URL

    try:
        google_mod.GEMINI_BASE_URL = base_url
        google_bypass_mod.GEMINI_BASE_URL = base_url
        openai_mod.OPENAI_BASE_URL = base_url
        anthropic_mod.ANTHROPIC_BASE_URL = base_url
        nvidia_mod.NVIDIA_BASE_URL = base_url
        yield
    finally:
        google_mod.GEMINI_BASE_URL = orig_google
        google_bypass_mod.GEMINI_BASE_URL = orig_google_bp
        openai_mod.OPENAI_BASE_URL = orig_openai
        anthropic_mod.ANTHROPIC_BASE_URL = orig_anthropic
        nvidia_mod.NVIDIA_BASE_URL = orig_nvidia


class SandboxRunner:
    """Orchestrates sandbox lifecycle and runs test scenarios."""

    def __init__(self) -> None:
        self.target_server = MockTargetServer()
        self.provider_server = MockProviderServer()
        self.target_url = ""
        self.provider_url = ""

    def start_servers(self) -> None:
        self.target_url = self.target_server.start()
        self.provider_url = self.provider_server.start()

    def stop_servers(self) -> None:
        self.target_server.stop()
        self.provider_server.stop()

    async def run_scenario_full_web_scan(self) -> tuple[bool, str, dict]:
        """Scenario 1: Full web discovery, deobfuscation, sourcemaps, chunks & validation."""
        config = Config(
            targets=[self.target_url],
            depth=2,
            wayback=False,
            sourcemaps=True,
            bypass=True,
            quiet=True,
            evidence=True,
        )
        with patch_provider_urls(self.provider_url):
            pipeline = Pipeline(config)
            result = await pipeline.execute()

        keys_by_status = {
            KeyStatus.VALID: [r.key for r in result.results if r.status == KeyStatus.VALID],
            KeyStatus.BYPASSED: [r.key for r in result.results if r.status == KeyStatus.BYPASSED],
            KeyStatus.RATE_LIMITED: [r.key for r in result.results if r.status == KeyStatus.RATE_LIMITED],
        }

        # Assertions:
        # 1. Google valid key extracted and validated
        has_google_valid = TEST_KEYS["google_valid"] in keys_by_status[KeyStatus.VALID]
        # 2. Google bypass key extracted and bypassed
        has_google_bypassed = TEST_KEYS["google_bypass"] in keys_by_status[KeyStatus.BYPASSED]
        # 3. OpenAI project key extracted and validated
        has_openai_proj = TEST_KEYS["openai_project"] in keys_by_status[KeyStatus.VALID]
        # 4. Anthropic key extracted from sourcemap and validated
        has_anthropic = TEST_KEYS["anthropic_valid"] in keys_by_status[KeyStatus.VALID]
        # 5. NVIDIA key extracted from sourcemap / chunks and validated
        has_nvidia = TEST_KEYS["nvidia_valid"] in keys_by_status[KeyStatus.VALID]

        passed = all([
            has_google_valid,
            has_google_bypassed,
            has_openai_proj,
            has_anthropic,
            has_nvidia,
        ])

        details = {
            "Total Keys Found": result.keys_found,
            "Valid Keys": result.keys_valid,
            "Bypassed Keys": result.keys_bypassed,
            "Sources Crawled": result.sources_crawled,
            "Duration": f"{result.duration_seconds}s",
        }
        msg = "Discovered & validated across all 4 providers (Google, OpenAI, Anthropic, NVIDIA)" if passed else "Some expected keys were missing"
        return passed, msg, details

    async def run_scenario_direct_keys(self) -> tuple[bool, str, dict]:
        """Scenario 2: Direct key input mode (skipping web crawler)."""
        test_inputs = [
            TEST_KEYS["google_valid"],
            TEST_KEYS["openai_invalid"],
            TEST_KEYS["nvidia_valid"],
        ]
        config = Config(
            keys=test_inputs,
            bypass=False,
            quiet=True,
        )
        with patch_provider_urls(self.provider_url):
            pipeline = Pipeline(config)
            result = await pipeline.execute()

        valid_keys = [r.key for r in result.results if r.status == KeyStatus.VALID]
        invalid_keys = [r.key for r in result.results if r.status == KeyStatus.INVALID]

        passed = (
            TEST_KEYS["google_valid"] in valid_keys
            and TEST_KEYS["nvidia_valid"] in valid_keys
            and TEST_KEYS["openai_invalid"] in invalid_keys
        )
        details = {
            "Direct Keys Supplied": len(test_inputs),
            "Valid Keys": result.keys_valid,
            "Invalid Keys": result.keys_invalid,
        }
        msg = "Direct key validation accurate for valid and invalid credentials" if passed else "Direct key validation mismatch"
        return passed, msg, details

    async def run_scenario_provider_filtering(self) -> tuple[bool, str, dict]:
        """Scenario 3: Provider filter (--provider anthropic)."""
        config = Config(
            targets=[self.target_url],
            providers=["anthropic"],
            depth=2,
            wayback=False,
            sourcemaps=True,
            quiet=True,
        )
        with patch_provider_urls(self.provider_url):
            pipeline = Pipeline(config)
            result = await pipeline.execute()

        # Should only find anthropic keys
        all_keys = [r.key for r in result.results]
        only_anthropic = all(k.startswith("sk-ant-") for k in all_keys) and len(all_keys) > 0

        details = {
            "Filtered Provider": "anthropic",
            "Extracted Keys": len(all_keys),
            "Valid Anthropic Keys": result.keys_valid,
        }
        msg = "Strictly isolated Anthropic provider keys" if only_anthropic else "Provider filtering failed"
        return only_anthropic, msg, details


async def run_all_sandbox_tests() -> int:
    """Run all sandbox scenarios and print formatted summary."""
    runner = SandboxRunner()
    console.print(Panel.fit("[bold blue]Starting LLMHunter Testing Sandbox[/bold blue]"))

    runner.start_servers()
    console.print(f"  [cyan]* Mock Target Web Server:[/cyan]     [bold]{runner.target_url}[/bold]")
    console.print(f"  [cyan]* Mock LLM Provider API:[/cyan]     [bold]{runner.provider_url}[/bold]\n")

    table = Table(title="Sandbox Test Results", header_style="bold magenta")
    table.add_column("Scenario", style="cyan", width=38)
    table.add_column("Status", width=10)
    table.add_column("Details", style="dim")

    exit_code = 0
    try:
        scenarios = [
            ("Full Discovery & Multi-Provider Scan", runner.run_scenario_full_web_scan),
            ("Direct Key Mode Validation", runner.run_scenario_direct_keys),
            ("Single Provider Filtering (--provider)", runner.run_scenario_provider_filtering),
        ]

        for name, fn in scenarios:
            t0 = time.monotonic()
            passed, summary, details = await fn()
            elapsed = round(time.monotonic() - t0, 2)

            status_badge = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
            if not passed:
                exit_code = 1

            detail_str = f"{summary} ({elapsed}s) | " + ", ".join(f"{k}: {v}" for k, v in details.items())
            table.add_row(name, status_badge, detail_str)

    finally:
        runner.stop_servers()

    console.print(table)
    if exit_code == 0:
        console.print("\n[bold green][PASS] All sandbox scenarios passed successfully![/bold green]\n")
    else:
        console.print("\n[bold red][FAIL] Some sandbox scenarios failed.[/bold red]\n")

    return exit_code


def main() -> None:
    code = asyncio.run(run_all_sandbox_tests())
    sys.exit(code)


if __name__ == "__main__":
    main()
