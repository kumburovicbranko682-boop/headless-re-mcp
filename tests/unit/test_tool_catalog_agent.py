from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.server import create_server
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import (
    COMMAND_CATALOG,
    CommandCatalog,
    CommandTransport,
    ToolEffect,
)


def test_all_mcp_tools_share_explicit_agent_catalog() -> None:
    analysis = AnalysisService()
    # This test asserts the full surface, independent of any machine-local
    # workspace profile that would otherwise trim it.
    object.__setattr__(analysis.settings, "workspace_profile", "full")
    server = create_server(analysis)
    mcp_names = set(server._tool_manager._tools)
    catalog_names = {item.name for item in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}
    agent_names = {item.name for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)}
    assert len(mcp_names) == 265
    assert mcp_names == catalog_names == agent_names
    assert COMMAND_CATALOG.uncategorized_names() == ()
    assert all(item.effects for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT))
    assert all(
        item.agent_auto_execute == (item.effects == frozenset({ToolEffect.READ_ONLY}))
        for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
    )
    assert all(item.input_schema is not None for item in COMMAND_CATALOG.for_transport(CommandTransport.MCP))
    assert COMMAND_CATALOG.require("static.open").resource_policy.timeout_seconds == 1800.0
    assert COMMAND_CATALOG.require("session.list").resource_policy.timeout_seconds == 60.0


def test_protocol_independent_tool_domains_bind_complete_fresh_catalog() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
    finally:
        analysis.close_all()

    specs = catalog.for_transport(CommandTransport.MCP)
    assert len(bindings) == len(specs) == 265
    assert {binding.name for binding in bindings} == {spec.name for spec in specs}
    assert all(spec.handler is not None for spec in specs)
    assert all(spec.input_schema is not None for spec in specs)
    assert all(spec.description for spec in specs)
    for binding in bindings:
        service_methods = [
            name
            for name in binding.handler.__code__.co_names
            if hasattr(AnalysisService, name)
        ]
        assert service_methods == [catalog.require(binding.name).service_method]

    tools_root = Path(__file__).parents[2] / "src" / "headless_re_mcp" / "tools"
    transport_imports = [
        path
        for path in tools_root.glob("*.py")
        if "headless_re_mcp.mcp" in path.read_text(encoding="utf-8")
        or "mcp.server" in path.read_text(encoding="utf-8")
        or "fastapi" in path.read_text(encoding="utf-8")
    ]
    assert transport_imports == []


def test_mutating_catalog_tools_are_writes_not_auto_execute() -> None:
    """Breakpoint put/disable and page-rights changes must not auto-run."""
    for name in (
        "workflow.breakpoint.put",
        "workflow.breakpoint.disable",
        "memory.protection",
        "frida.hook.template",
    ):
        spec = COMMAND_CATALOG.require(name)
        assert spec.write is True
        assert spec.agent_auto_execute is False
        assert spec.effects == frozenset({ToolEffect.STATE_CHANGE})


def test_query_catalog_tools_are_read_only() -> None:
    """Text search and patch listing are queries, not writes."""
    for name in ("static.search.text", "patches.list", "dynamic.stealth.status"):
        spec = COMMAND_CATALOG.require(name)
        assert spec.write is False
        assert spec.agent_auto_execute is True
        assert spec.effects == frozenset({ToolEffect.READ_ONLY})


def test_stealth_set_is_a_file_write() -> None:
    spec = COMMAND_CATALOG.require("dynamic.stealth.set")
    assert spec.write is True
    assert spec.agent_auto_execute is False
    assert spec.effects == frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE})


def test_tool_effect_sets_are_pairwise_disjoint() -> None:
    """No tool may appear in two effect sets.

    ``_declared_spec`` resolves ``_READ_ONLY_NAMES`` before the write sets, so a
    mutating tool copied into the read-only set as well would be silently served
    as read_only -- skipping ``guard_write`` and the confirmation prompt -- while
    the union-count guard still passed because some other name was dropped to
    keep the total at 265. Pin the sets as disjoint so that downgrade cannot
    slip in unnoticed.
    """
    from headless_re_mcp.tools.catalog import (
        _FILE_WRITE_NAMES,
        _READ_ONLY_NAMES,
        _STATE_CHANGE_NAMES,
    )

    assert _READ_ONLY_NAMES.isdisjoint(_STATE_CHANGE_NAMES)
    assert _READ_ONLY_NAMES.isdisjoint(_FILE_WRITE_NAMES)
    assert _STATE_CHANGE_NAMES.isdisjoint(_FILE_WRITE_NAMES)
    total = len(_READ_ONLY_NAMES) + len(_STATE_CHANGE_NAMES) + len(_FILE_WRITE_NAMES)
    assert total == 265


def test_validated_tool_names_returns_the_union_for_a_clean_partition() -> None:
    """The happy path returns exactly the union of the three effect sets."""
    from headless_re_mcp.tools.catalog import (
        _FILE_WRITE_NAMES,
        _READ_ONLY_NAMES,
        _STATE_CHANGE_NAMES,
        _validated_tool_names,
    )

    names = _validated_tool_names(
        _READ_ONLY_NAMES, _STATE_CHANGE_NAMES, _FILE_WRITE_NAMES
    )
    assert names == _READ_ONLY_NAMES | _STATE_CHANGE_NAMES | _FILE_WRITE_NAMES
    assert len(names) == 265


def test_validated_tool_names_rejects_a_conflicting_classification() -> None:
    """The insidious drift -- a moved tool left in its old set -- must raise by name.

    The realistic mistake is moving a tool between categories by pasting its
    name into the new set and forgetting to delete it from the old one. The
    union is unchanged (the name was already present), so a plain ``!= 265``
    count guard still passes, yet the tool now resolves to whichever set
    ``_declared_spec`` checks first (read_only), silently dropping its write
    guard. The size sum, however, gains one. Drive the real guard, not just the
    arithmetic, so the refusal branch is exercised and names the offender.
    """
    from headless_re_mcp.tools import catalog

    read_only = catalog._READ_ONLY_NAMES
    file_write = catalog._FILE_WRITE_NAMES
    victim = "modules.dump"
    assert victim in file_write and victim not in read_only
    mutated_read_only = read_only | {victim}
    # The union is unchanged, so the count check alone would wave this through.
    assert len(mutated_read_only | catalog._STATE_CHANGE_NAMES | file_write) == 265

    with pytest.raises(RuntimeError, match="conflicting effects") as excinfo:
        catalog._validated_tool_names(
            mutated_read_only, catalog._STATE_CHANGE_NAMES, file_write
        )
    assert victim in str(excinfo.value)


def test_validated_tool_names_rejects_a_count_drift() -> None:
    """A disjoint partition whose total is wrong hits the count refusal.

    Dropping a read-only name keeps the sets disjoint but takes the union to
    264, so the disjointness check passes and the count check must fire. This
    exercises the second refusal branch, distinct from the overlap one.
    """
    from headless_re_mcp.tools import catalog

    trimmed_read_only = catalog._READ_ONLY_NAMES - {"audit.list"}
    with pytest.raises(RuntimeError, match="duplicates or omissions"):
        catalog._validated_tool_names(
            trimmed_read_only, catalog._STATE_CHANGE_NAMES, catalog._FILE_WRITE_NAMES
        )
