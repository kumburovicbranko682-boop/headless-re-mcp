"""The tool surface stays named and restricted -- no free-form command escape.

The security boundary stated in SECURITY.md and the README is that every
capability is a named, argument-validated tool: there is deliberately no
`dynamic.command`, no `device.shell`, no `web.evaluate`, and no tool that runs a
caller-supplied script. That boundary is easy to erode one convenient tool at a
time, so it is pinned here: a future tool that reintroduces an arbitrary
command/eval surface, or ships without the metadata clients route on, fails.
"""

from __future__ import annotations

from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandTransport,
    ToolEffect,
)

# Names that would each amount to an arbitrary command/eval passthrough. The
# project calls these out by name as things it intentionally does not offer, so
# their reappearance in the catalog is the regression to catch.
FORBIDDEN_TOOL_NAMES = frozenset(
    {
        "dynamic.command",
        "dynamic.exec",
        "dynamic.execute",
        "device.shell",
        "device.exec",
        "adb.shell",
        "shell.run",
        "shell.exec",
        "web.evaluate",
        "web.eval",
        "js.eval",
        "frida.eval",
        "frida.script",
    }
)


def _all_specs(catalog: CommandCatalog) -> list:
    seen: dict[str, object] = {}
    for transport in CommandTransport:
        for spec in catalog.for_transport(transport):
            seen[spec.name] = spec
    return list(seen.values())


def test_no_free_form_command_or_eval_tool_is_registered() -> None:
    catalog = CommandCatalog()
    names = {spec.name for spec in _all_specs(catalog)}
    present = FORBIDDEN_TOOL_NAMES & names
    assert present == set(), (
        "the catalog exposes a free-form command/eval tool, which breaks the "
        f"'every capability is a named tool' boundary: {sorted(present)}"
    )


def test_every_declared_tool_is_classified_exactly_once() -> None:
    catalog = CommandCatalog()
    specs = _all_specs(catalog)
    assert specs, "the catalog is empty"

    uncategorized = catalog.uncategorized_names()
    assert uncategorized == (), uncategorized

    for spec in specs:
        assert spec.effects, spec.name
        # write is state_change/file_write; read is read_only alone. The two are
        # complementary, so a tool cannot be simultaneously both or neither.
        is_read = spec.effects == frozenset({ToolEffect.READ_ONLY})
        assert spec.write != is_read, (
            f"{spec.name} has an ambiguous effect set: {sorted(spec.effects)}"
        )
        if spec.write:
            assert ToolEffect.READ_ONLY not in spec.effects, (
                f"{spec.name} mixes read_only with a write effect"
            )


def test_every_bound_tool_carries_a_description_and_object_schema() -> None:
    from headless_re_mcp.core.service import AnalysisService
    from headless_re_mcp.tools.assembly import bind_all_tools

    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
        missing_doc: list[str] = []
        bad_schema: list[str] = []
        for binding in bindings:
            spec = catalog.get(binding.name)
            assert spec is not None
            description = (spec.description or "").strip()
            # A blank or name-only description leaves an MCP client with nothing
            # to route on; bind_all_tools falls back to the name, so require more.
            if not description or description == binding.name:
                missing_doc.append(binding.name)
            schema = spec.input_schema
            if not isinstance(schema, dict) or schema.get("type") != "object":
                bad_schema.append(binding.name)
        assert missing_doc == [], missing_doc
        assert bad_schema == [], bad_schema
    finally:
        analysis.close_all()
