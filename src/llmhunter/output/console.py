"""Rich terminal output for multi-provider scan results."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from llmhunter.config import Config
from llmhunter.models import KeyIntelligence, KeyStatus, ScanResult

console = Console(stderr=True)

STATUS_STYLES = {
    KeyStatus.VALID: ("VALID", "bold green"),
    KeyStatus.BYPASSED: ("BYPASSED", "bold yellow"),
    KeyStatus.RATE_LIMITED: ("429", "bold yellow"),
    KeyStatus.FORBIDDEN: ("403", "red"),
    KeyStatus.INVALID: ("INVALID", "dim"),
    KeyStatus.UNKNOWN: ("ERR", "dim red"),
}

BYPASS_CODE_LABEL = {
    200: ("200 OK", "bold green"),
    403: ("403 Permission changed", "yellow"),
    429: ("429 Rate-limited", "bold yellow"),
}


def render_table(
    result: ScanResult,
    config: Config,
    out_console: Console | None = None,
) -> str:
    target_console = out_console or console
    if not result.results:
        target_console.print("  [dim]No results to display.[/dim]")
        return (
            target_console.export_text()
            if getattr(target_console, "record", False)
            else ""
        )

    timing_parts = [f"{result.duration_seconds}s total"]
    for phase, secs in result.phase_timings.items():
        timing_parts.append(f"{phase}: {secs}s")
    timing_str = " | ".join(timing_parts)

    providers_str = ", ".join(result.providers_scanned) if result.providers_scanned else "all"

    target_console.print(
        f"  [bold]Results[/bold]  "
        f"[green]{result.keys_valid} valid[/green]  "
        f"[yellow]{result.keys_bypassed} bypassed[/yellow]  "
        f"[yellow]{result.keys_rate_limited} rate-limited[/yellow]  "
        f"[red]{result.keys_forbidden} forbidden[/red]  "
        f"[dim]{result.keys_invalid} invalid[/dim]  "
        f"[dim]({timing_str})[/dim]"
        f"  [dim]providers: {providers_str}[/dim]\n"
    )

    header = Text()
    header.append(
        f"  {'Status':<10}  {'Provider':<12}  {'Key':<22}  Bypass",
        style="bold",
    )
    target_console.print(header)

    for r in result.results:
        key_display = f"{r.key[:10]}...{r.key[-6:]}"
        label, style = STATUS_STYLES.get(r.status, ("?", "dim"))
        provider_label = r.provider or "?"

        if r.bypass:
            code = r.bypass.bypass_status_code
            bp_label, bp_style = BYPASS_CODE_LABEL.get(code, (str(code), "yellow"))
        else:
            bp_label, bp_style = "-", "dim"

        line = Text()
        line.append(f"  {label:<10}", style=style)
        line.append(f"  {provider_label:<12}", style="magenta")
        line.append(f"  {key_display:<22}", style="cyan")
        line.append(f"  {bp_label}", style=bp_style)
        target_console.print(line)

        sources = [s for s in r.sources if s != "direct_input"]
        if sources:
            target_console.print(
                f"  [dim]found in:[/dim] [blue]{escape(sources[0])}[/blue]"
            )
            for s in sources[1:3]:
                target_console.print(f"           [dim]{escape(s)}[/dim]")
            if len(sources) > 3:
                target_console.print(
                    f"           [dim]+{len(sources) - 3} more[/dim]"
                )

        target_console.print()

    working = [
        r
        for r in result.results
        if r.status in (KeyStatus.VALID, KeyStatus.BYPASSED, KeyStatus.RATE_LIMITED)
        or r.bypass
    ]
    for r in working:
        _print_key_detail(r, config, target_console)

    return (
        target_console.export_text()
        if getattr(target_console, "record", False)
        else ""
    )


def _print_key_detail(
    r: KeyIntelligence,
    config: Config,
    target_console: Console,
) -> None:
    lines: list[str] = []

    lines.append(f"  [bold cyan]Key[/bold cyan]      {escape(r.key)}")
    lines.append(f"  [bold cyan]Provider[/bold cyan] {escape(r.provider or 'unknown')}")

    if r.target_domain and r.target_domain != "direct":
        lines.append(f"  [bold cyan]Domain[/bold cyan]   {escape(r.target_domain)}")

    if r.sources and r.sources != ["direct_input"]:
        lines.append(f"  [bold cyan]Source[/bold cyan]   {escape(r.sources[0])}")
        for src in r.sources[1:3]:
            lines.append(f"           {escape(src)}")
        if len(r.sources) > 3:
            lines.append(f"           [dim]+{len(r.sources) - 3} more[/dim]")

    if r.bypass:
        code = r.bypass.bypass_status_code
        code_label, code_style = BYPASS_CODE_LABEL.get(code, (str(code), "yellow"))
        if code == 403 and r.bypass.error_reason == "SERVICE_DISABLED":
            code_label, code_style = "403 Service disabled", "yellow"
        lines.append(f"  [bold cyan]Bypass[/bold cyan]   {escape(r.bypass.technique)}")
        lines.append(
            f"  [bold cyan]Status[/bold cyan]   403 → [{code_style}]{code_label}[/{code_style}]"
        )
        if r.bypass.error_reason:
            lines.append(
                f"  [bold cyan]Reason[/bold cyan]   {escape(r.bypass.error_reason)}"
            )
        for k, v in r.bypass.headers.items():
            lines.append(f"           [dim]{escape(k)}: {escape(v)}[/dim]")

    if r.detail:
        lines.append(f"  [bold cyan]Detail[/bold cyan]   {escape(r.detail)}")

    for field_name, value in r.intel_data.items():
        if value is None:
            continue
        label = field_name.replace("_", " ").title()
        if isinstance(value, list):
            if not value:
                continue
            lines.append(
                f"  [bold cyan]{label:<8}[/bold cyan] {len(value)} items"
            )
            for item in value[:5]:
                lines.append(f"           [dim]{escape(str(item))}[/dim]")
            if len(value) > 5:
                lines.append(f"           [dim]+{len(value) - 5} more[/dim]")
        elif isinstance(value, bool):
            style = "[green]Yes[/green]" if value else "[red]No[/red]"
            lines.append(f"  [bold cyan]{label:<8}[/bold cyan] {style}")
        else:
            lines.append(
                f"  [bold cyan]{label:<8}[/bold cyan] {escape(str(value))}"
            )

    if r.restrictions:
        rx = r.restrictions
        if rx.unrestricted:
            lines.append(
                "  [bold cyan]Restrict[/bold cyan] [bold red]None (unrestricted key)[/bold red]"
            )
        elif rx.referrer_restricted:
            lines.append("  [bold cyan]Restrict[/bold cyan] HTTP Referrer")
            if rx.referrer_pattern:
                lines.append(
                    f"           [dim]pattern: {escape(rx.referrer_pattern)}[/dim]"
                )
        elif rx.restriction_type:
            lines.append(
                f"  [bold cyan]Restrict[/bold cyan] {escape(rx.restriction_type)}"
            )

    panel_content = "\n".join(lines)
    border = (
        "green"
        if r.status == KeyStatus.VALID
        else "red"
        if r.status == KeyStatus.FORBIDDEN
        else "yellow"
    )
    label = f"[bold {border}]{r.status.value.upper()}[/bold {border}]"
    target_console.print(
        Panel(panel_content, title=label, border_style=border, padding=(1, 1))
    )

    if config.evidence and r.curl_commands:
        target_console.print("  [bold cyan]PoC curls:[/bold cyan]")
        for cmd in r.curl_commands:
            target_console.print(f"  {cmd}\n", style="dim", markup=False, soft_wrap=True)
