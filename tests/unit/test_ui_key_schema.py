"""ui.key must refuse oversized text and out-of-range vk at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_key_schema_matches_win32_text_and_vk_caps() -> None:
    """The catalog accepted unbounded key text and vk.

    Measured: input schema text has no maxLength and vk has no maximum.
    send_key refuses text above 32 characters and vk outside 1..254. A caller
    that sends a 2 MiB string still occupies a worker until that check runs.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = source.index("def send_key")
    chunk = source[start : source.index("def invoke_hwnd", start)]
    assert "len(text) > 32" in chunk
    assert "1 <= vk <= 0xFE" in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.key"
    )
    props = input_schema_for(handler)["properties"]
    integer_vk = next(item for item in props["vk"]["anyOf"] if item.get("type") == "integer")
    text_schema = next(item for item in props["text"]["anyOf"] if item.get("type") == "string")
    assert text_schema["minLength"] == 1
    assert text_schema["maxLength"] == 32
    assert integer_vk["minimum"] == 1
    assert integer_vk["maximum"] == 0xFE
