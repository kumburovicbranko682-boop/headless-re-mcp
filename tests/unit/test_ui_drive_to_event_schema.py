"""ui.drive_to_event must refuse oversized step lists at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_drive_to_event_schema_matches_drive_step_cap() -> None:
    """The catalog accepted an unbounded UI drive step list.

    Measured: input schema steps has no maxItems. normalize_drive_steps
    refuses above _MAX_STEPS (32). A caller that posts thousands of steps
    still occupies a worker until that check runs.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_drive.py"
    ).read_text(encoding="utf-8")
    assert "_MAX_STEPS = 32" in source
    assert "len(steps) > _MAX_STEPS" in source
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.drive_to_event"
    )
    props = input_schema_for(handler)["properties"]
    steps_schema = next(
        item for item in props["steps"]["anyOf"] if item.get("type") == "array"
    )
    assert steps_schema["maxItems"] == 32
