"""workspace.mode.set must refuse unknown profiles at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.workspace import build_workspace_tools


def test_workspace_mode_set_schema_matches_known_profiles() -> None:
    """The catalog accepted any profile string.

    Measured: input schema profile has no pattern. workspace_mode_set only
    accepts full, pe, android and web after strip/lower. A caller that sends
    an unknown name still occupies a worker until that check, and overnight
    retries the same unknown profile as if it never arrived.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "workspace.py"
    ).read_text(encoding="utf-8")
    assert 'PROFILES: tuple[str, ...] = ("full", "pe", "android", "web")' in source
    handler = next(
        binding.handler
        for binding in build_workspace_tools(object())  # type: ignore[arg-type]
        if binding.name == "workspace.mode.set"
    )
    props = input_schema_for(handler)["properties"]
    assert props["profile"]["pattern"] == "^(full|pe|android|web)$"
