"""Pin that the MCP server registers exactly the catalog's MCP surface.

``test_workspace_profiles.py`` asserts the full profile exposes ``265`` tools
and spot-checks a handful of names, but a bare count is a weak wiring guard: a
``register_*`` function that forgets one tool while another is accidentally
registered under a name the catalog does not know would keep the count at 265
with the *sets* diverging. Pin the stronger invariant instead -- the created
server's registered tool set equals the catalog's MCP-transport set, exactly --
so the assertion self-updates with the catalog and catches asymmetric drift in
either direction: a catalog MCP tool no ``register_*`` wires up (missing from
the server) or a tool bound onto the server that is not an MCP command (a leak).
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandTransport
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.server import create_server


def _full_profile_service(tmp_path: Path) -> AnalysisService:
    settings = Settings.load()
    object.__setattr__(settings, "artifact_root", tmp_path)
    # "full" makes _apply_workspace_profile a no-op, so the server carries the
    # complete MCP surface rather than a trimmed one.
    object.__setattr__(settings, "workspace_profile", "full")
    return AnalysisService(settings=settings)


def test_created_server_registers_exactly_the_mcp_catalog_surface(tmp_path: Path) -> None:
    # create_server writes COMMAND_CATALOG.write_allowed from settings; snapshot
    # and restore it so this test does not perturb the shared catalog for others.
    previous_write_allowed = COMMAND_CATALOG.write_allowed
    analysis = _full_profile_service(tmp_path)
    try:
        server = create_server(analysis)
        registered = set(server._tool_manager._tools)
    finally:
        analysis.close_all()
        COMMAND_CATALOG.write_allowed = previous_write_allowed

    catalog_mcp = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}

    missing_from_server = catalog_mcp - registered
    leaked_onto_server = registered - catalog_mcp
    assert not missing_from_server, (
        "catalog declares these tools on the MCP transport but no register_* "
        f"function wired them onto the server: {sorted(missing_from_server)}"
    )
    assert not leaked_onto_server, (
        "these tools are registered on the MCP server but are not MCP-transport "
        f"commands in the catalog: {sorted(leaked_onto_server)}"
    )
    assert registered == catalog_mcp


def test_every_web_and_agent_command_is_also_reachable_over_mcp() -> None:
    # The MCP server is the single authority: the web console and the agent both
    # invoke the same catalog. Pin that no command is exposed on those transports
    # without also being an MCP command, which is the topology register_bound_tools
    # enforces (it refuses to register a tool whose spec omits the MCP transport).
    mcp = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}
    web = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.WEB)}
    agent = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)}

    assert web, "expected a non-empty WEB transport surface"
    assert agent, "expected a non-empty AGENT transport surface"
    assert web <= mcp, f"WEB-only commands not exposed over MCP: {sorted(web - mcp)}"
    assert agent <= mcp, f"AGENT-only commands not exposed over MCP: {sorted(agent - mcp)}"
