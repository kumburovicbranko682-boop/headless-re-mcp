from __future__ import annotations

import json
from typing import Any

import pytest

from headless_re_mcp.openai_bridge import (
    MAX_FUNCTION_NAME,
    build_openai_tools,
    openai_function_name,
)
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)


def _handler(**_: Any) -> dict[str, Any]:

    return {}


def _spec(name: str, effects: frozenset[ToolEffect]) -> CommandSpec:

    return CommandSpec(

        name=name,

        service_method=name.replace(".", "_"),

        transports=frozenset({CommandTransport.MCP}),

        effects=effects,

        handler=_handler,

        input_schema={"type": "object", "properties": {}},

        description="desc",

    )


def test_openai_function_name_sanitizes_dotted_names() -> None:

    assert openai_function_name("static.functions") == "static_functions"

    assert openai_function_name("ui.virtual_desktop.capture") == "ui_virtual_desktop_capture"

    assert len(openai_function_name("a" * 200)) <= MAX_FUNCTION_NAME


def test_build_openai_tools_maps_names_and_flags_writes() -> None:

    catalog = CommandCatalog(

        (

            _spec("static.functions", frozenset({ToolEffect.READ_ONLY})),

            _spec(

                "static.open",

                frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE}),

            ),

        )

    )

    payload = build_openai_tools(catalog)

    assert payload["count"] == 2

    assert payload["name_map"] == {

        "static_functions": "static.functions",

        "static_open": "static.open",

    }

    assert payload["write_tools"] == ["static_open"]

    entry = payload["tools"][0]

    assert entry["type"] == "function"

    assert entry["function"]["name"] == "static_functions"

    assert entry["function"]["parameters"] == {"type": "object", "properties": {}}


def test_build_openai_tools_rejects_unbound_catalog() -> None:

    catalog = CommandCatalog(

        (

            CommandSpec(

                name="static.functions",

                service_method="static_functions",

                transports=frozenset({CommandTransport.MCP}),

                effects=frozenset({ToolEffect.READ_ONLY}),

            ),

        )

    )

    with pytest.raises(RuntimeError, match="not bound"):

        build_openai_tools(catalog)


def test_every_exported_name_is_openai_safe_and_maps_back() -> None:

    """The sanitisation is the whole point, so check it against the real catalog."""

    import re

    from headless_re_mcp.openai_bridge import build_bound_catalog, build_openai_tools
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    payload = build_openai_tools(build_bound_catalog())

    pattern = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

    names = [entry["function"]["name"] for entry in payload["tools"]]

    assert names, "no tools were exported"

    assert len(set(names)) == len(names), "sanitised names collided"

    for name in names:

        assert pattern.fullmatch(name), f"not an OpenAI-safe function name: {name}"

    assert len(payload["name_map"]) == payload["count"]

    for mcp_name in payload["name_map"].values():

        assert COMMAND_CATALOG.get(mcp_name) is not None, mcp_name


def test_build_openai_tools_detects_name_collisions() -> None:

    catalog = CommandCatalog(

        (

            _spec("ui.window.close", frozenset({ToolEffect.READ_ONLY})),

            _spec("ui.window_close", frozenset({ToolEffect.READ_ONLY})),

        )

    )

    with pytest.raises(RuntimeError, match="collision"):

        build_openai_tools(catalog)


def test_the_export_covers_every_mcp_tool_and_matches_the_write_classification() -> None:
    """An OpenAI bridge keys its approval policy on ``write_tools``.

    Two things a bridge relies on that names alone do not prove: no MCP tool is
    silently dropped from the export (a dropped tool is uncallable), and the
    exported write set is exactly the catalog's write classification -- the same
    set ``test_write_policy_surface`` enforces at the guard. If the bridge's list
    drifts, an OpenAI caller could auto-run a call the project treats as a write.
    """

    from headless_re_mcp.openai_bridge import build_bound_catalog, build_openai_tools
    from headless_re_mcp.tools.catalog import CommandTransport

    catalog = build_bound_catalog()
    payload = build_openai_tools(catalog)

    mcp_specs = catalog.for_transport(CommandTransport.MCP)
    expected_names = {spec.name for spec in mcp_specs}

    # Every MCP tool is exported exactly once -- nothing dropped or duplicated.
    assert payload["count"] == len(expected_names)
    assert set(payload["name_map"].values()) == expected_names

    # write_tools, mapped back to MCP names, is exactly the catalog's write set.
    exported_writes = {payload["name_map"][name] for name in payload["write_tools"]}
    catalog_writes = {spec.name for spec in mcp_specs if spec.write}
    assert exported_writes == catalog_writes
    # A non-empty write set -- an empty one would mean everything looked
    # auto-runnable to a bridge that trusts this list.
    assert catalog_writes


def test_cli_prints_the_full_export_as_json_by_default(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`python openai_bridge.py` is the shape a caller pipes into its client."""
    from headless_re_mcp.openai_bridge import main

    assert main([]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == len(payload["tools"]) == len(payload["name_map"])
    assert payload["count"] > 0


def test_cli_names_only_drops_the_tool_bodies(capsys: pytest.CaptureFixture[str]) -> None:
    """--names-only is the CI smoke; it must stay just the map and the count."""
    from headless_re_mcp.openai_bridge import main

    assert main(["--names-only"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"name_map", "count"}
    assert payload["count"] == len(payload["name_map"])
    assert payload["count"] > 0


def test_cli_output_writes_a_file_and_reports_it(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    from headless_re_mcp.openai_bridge import main

    out = tmp_path / "nested" / "openai_tools.json"
    assert main(["--output", str(out)]) == 0

    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["count"] == len(written["tools"]) > 0
    printed = capsys.readouterr().out
    assert f"wrote {written['count']}" in printed
    # The file path is reported, and the tool bodies went to disk, not stdout.
    assert str(out) in printed
    assert "\"type\": \"function\"" not in printed
