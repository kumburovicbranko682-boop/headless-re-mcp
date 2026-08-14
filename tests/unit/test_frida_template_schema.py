"""frida.hook.template must refuse unknown names at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools


def test_frida_hook_template_schema_matches_canned_names() -> None:
    """The catalog accepted an unbounded template name.

    Measured: input schema template has no pattern. The client only has
    noop, android_ssl_unpin, android_crypto_monitor and android_root_bypass;
    anything else is unknown hook template after attach work has started.
    A caller that pastes a script into template still occupies a worker
    until that lookup fails.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "frida"
        / "client.py"
    ).read_text(encoding="utf-8")
    start = source.index("_HOOK_TEMPLATES = {")
    chunk = source[start : source.index("class FridaError", start)]
    names = ("noop", "android_ssl_unpin", "android_crypto_monitor", "android_root_bypass")
    for name in names:
        assert f'"{name}":' in chunk
    handler = next(
        binding.handler
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == "frida.hook.template"
    )
    props = input_schema_for(handler)["properties"]
    assert props["template"]["pattern"] == "^(" + "|".join(names) + ")$"
