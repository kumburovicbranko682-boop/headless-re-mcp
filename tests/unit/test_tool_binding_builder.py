"""Coverage for ToolSetBuilder's duplicate-name guard."""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.tools.binding import ToolSetBuilder


def test_toolset_builder_rejects_a_duplicate_name() -> None:
    builder = ToolSetBuilder()

    @builder.tool(name="dup.tool")
    def _first() -> dict[str, Any]:
        return {}

    with pytest.raises(ValueError, match="duplicate tool binding: dup.tool"):

        @builder.tool(name="dup.tool")
        def _second() -> dict[str, Any]:
            return {}

    # The first (valid) binding stays; the duplicate never registered.
    assert [binding.name for binding in builder.bindings] == ["dup.tool"]
