"""Evidence generation — curl commands to reproduce findings."""

from __future__ import annotations

import shlex

from llmhunter.models import KeyIntelligence, KeyStatus


def _build_curl(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> str:
    parts = ["curl -s"]
    if method != "GET":
        parts.append(f"-X {shlex.quote(method)}")
    for k, v in (headers or {}).items():
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if body:
        parts.append(f"-d {shlex.quote(body)}")
    parts.append(shlex.quote(url))
    return " \\\n  ".join(parts)


def generate_curl_commands(result: KeyIntelligence) -> list[str]:
    """Generate generic curl commands. Provider adapters override this."""
    commands: list[str] = []

    if result.bypass:
        bp = result.bypass
        url = bp.curl_command
        if not url:
            base_url = ""
            if bp.api_version and bp.endpoint:
                base_url = f"{bp.api_version}/{bp.endpoint}"
            if base_url:
                commands.append(
                    _build_curl(bp.method, base_url, bp.headers, bp.body)
                )

    return commands
