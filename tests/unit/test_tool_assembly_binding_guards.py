"""Coverage for bind_all_tools' catalog-integrity guards.

``test_write_policy_surface.py`` exercises the happy binding path. These pin the
two fail-closed guards: a duplicate binding name across factories, and a
mismatch between the bound handlers and the catalog's declared MCP surface.
"""

from __future__ import annotations

import pytest

import headless_re_mcp.tools.assembly as assembly
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)


def test_duplicate_binding_name_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Run one factory twice so its tool names appear more than once.
    monkeypatch.setattr(
        assembly,
        "TOOL_FACTORIES",
        assembly.TOOL_FACTORIES + (assembly.TOOL_FACTORIES[0],),
    )
    analysis = AnalysisService()
    try:
        with pytest.raises(ValueError, match="duplicate protocol-independent tool binding"):
            bind_all_tools(analysis, CommandCatalog())
    finally:
        analysis.close_all()


def test_binding_mismatch_against_the_declared_surface_is_rejected() -> None:
    # A catalog carrying an extra MCP tool no factory binds must fail closed
    # rather than ship a surface that drifts from the declared policy.
    catalog = CommandCatalog()
    catalog.register(
        CommandSpec(
            name="test.extra.readonly",
            service_method="test_extra_readonly",
            transports=frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
            effects=frozenset({ToolEffect.READ_ONLY}),
        )
    )
    analysis = AnalysisService()
    try:
        with pytest.raises(ValueError, match="tool binding mismatch"):
            bind_all_tools(analysis, catalog)
    finally:
        analysis.close_all()
