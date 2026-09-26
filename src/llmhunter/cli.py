"""CLI entry point for llmhunter with Rich UI styling."""

from __future__ import annotations

import asyncio
import logging
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from llmhunter.config import Config
from llmhunter.pipeline import Pipeline
from llmhunter.registry import _ensure_loaded, list_providers

console = Console(stderr=True)


def _render_banner() -> None:
    title = Text()
    title.append("  LLMHUNTER  ", style="bold white on blue")
    title.append("  v0.1.0\n", style="bold cyan")
    title.append("Multi-Provider LLM API Key Scanner & Intelligence Engine", style="dim italic")

    providers = list_providers()
    provider_badges = " ".join(f"[bold cyan]•[/bold cyan] {p}" for p in providers)
    
    content = f"{title}\n\n[dim]Supported Providers:[/dim]  {provider_badges}"
    console.print(Panel(content, border_style="bright_blue", padding=(1, 2)))


def _setup_logging(verbose: bool, quiet: bool) -> None:
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # Suppress third-party noisy HTTP logs during progress rendering
    for logger_name in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(logger_name).setLevel(
            logging.DEBUG if verbose else logging.WARNING
        )


def _collect_targets(
    cli_targets: tuple[str, ...],
    target_file: str | None,
) -> list[str]:
    targets: list[str] = []
    targets.extend(cli_targets)
    if target_file:
        with open(target_file) as f:
            targets.extend(
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            )
    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return list(dict.fromkeys(targets))


def _collect_keys(
    key_input: tuple[str, ...],
    key_file: str | None,
) -> list[str]:
    keys: list[str] = []
    keys.extend(key_input)
    if key_file:
        with open(key_file) as f:
            keys.extend(
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            )
    return list(dict.fromkeys(keys))


@click.command()
@click.argument("targets", nargs=-1)
@click.option("-k", "--key", "key_input", multiple=True, help="Direct API key(s) to validate.")
@click.option("-K", "--key-file", type=click.Path(exists=True), help="File with API keys (one per line).")
@click.option("-t", "--target-file", type=click.Path(exists=True), help="File with target URLs (one per line).")
@click.option(
    "-p", "--provider", "providers", multiple=True,
    help="Provider(s) to scan for. Repeatable. Default: all.",
)
@click.option("-d", "--depth", default=2, type=int, help="Crawl depth (default: 2).")
@click.option("--no-wayback", is_flag=True, help="Skip Wayback Machine lookup.")
@click.option("--no-sourcemaps", is_flag=True, help="Skip source map chasing.")
@click.option("--no-bypass", is_flag=True, help="Skip bypass probing on 403 keys.")
@click.option("--proxy", type=str, default=None, help="HTTP proxy or proxy file.")
@click.option("--rate-limit", type=float, default=10.0, help="Max requests/sec (default: 10).")
@click.option("--delay", type=float, default=0.0, help="Delay between requests in seconds.")
@click.option("--timeout", type=float, default=15.0, help="Request timeout in seconds.")
@click.option("-c", "--concurrency", type=int, default=20, help="Max concurrent requests.")
@click.option("--user-agent", type=str, default="rotate", help="User-Agent string or 'rotate'.")
@click.option("--insecure", is_flag=True, help="Disable TLS verification.")
@click.option("-j", "--json", "json_mode", is_flag=True, help="Output results as JSON.")
@click.option("-o", "--output", "output_path", type=str, default=None, help="Write results to file.")
@click.option("-e", "--evidence", is_flag=True, help="Generate PoC curl commands.")
@click.option("-v", "--verbose", is_flag=True, help="Verbose debug output.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress status output.")
def main(
    targets: tuple[str, ...],
    key_input: tuple[str, ...],
    key_file: str | None,
    target_file: str | None,
    providers: tuple[str, ...],
    depth: int,
    no_wayback: bool,
    no_sourcemaps: bool,
    no_bypass: bool,
    proxy: str | None,
    rate_limit: float,
    delay: float,
    timeout: float,
    concurrency: int,
    user_agent: str,
    insecure: bool,
    json_mode: bool,
    output_path: str | None,
    evidence: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Discover and validate LLM API keys from web targets.

    Supports Google Gemini, OpenAI, Anthropic, NVIDIA NIM, and more.
    """
    _setup_logging(verbose, quiet)
    _ensure_loaded()

    if not quiet and not json_mode:
        _render_banner()

    all_targets = _collect_targets(targets, target_file)
    all_keys = _collect_keys(key_input, key_file)

    provider_list = list(providers) if providers else ["all"]

    available = list_providers()
    for p in provider_list:
        if p != "all" and p not in available:
            console.print(f"[red]Unknown provider '{p}'. Available: {', '.join(available)}[/red]")
            raise SystemExit(1)

    config = Config(
        targets=all_targets,
        keys=all_keys,
        providers=provider_list,
        depth=depth,
        wayback=not no_wayback,
        sourcemaps=not no_sourcemaps,
        bypass=not no_bypass,
        proxy=proxy,
        rate_limit=rate_limit,
        delay=delay,
        timeout=timeout,
        concurrency=concurrency,
        user_agent=user_agent,
        insecure=insecure,
        json_mode=json_mode,
        verbose=verbose,
        quiet=quiet,
        evidence=evidence,
        output_path=output_path,
    )

    pipeline = Pipeline(config)
    result = asyncio.run(pipeline.execute())

    has_working = any(
        r.status.value in ("valid", "bypassed") for r in result.results
    )
    raise SystemExit(0 if not has_working else 2)


if __name__ == "__main__":
    main()
