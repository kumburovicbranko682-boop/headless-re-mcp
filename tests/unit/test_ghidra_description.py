from __future__ import annotations

from unittest.mock import MagicMock


def test_ghidra_analyze_description_does_not_promise_a_kept_project() -> None:
    """The docstring used to say later ghidra tools read what analyze produced.

    Measured: analyze_binary and functions both call _run_headless with
    delete_project=True, and every headless invocation includes -import. An
    unattended agent that spent minutes on analyze then expected cached
    analysis was paying twice and reading a lie.
    """
    from headless_re_mcp.tools.ghidra import build_ghidra_tools

    tools = {item.name: item for item in build_ghidra_tools(MagicMock())}
    doc = tools["ghidra.analyze"].handler.__doc__ or ""
    lowered = doc.casefold()
    assert "one-shot" in lowered or "import the file again" in lowered
    assert "read what this produced" not in lowered
    assert "run it first" not in lowered
