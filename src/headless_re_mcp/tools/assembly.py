"""Application assembly for all protocol-independent analysis tools."""

from __future__ import annotations

from collections.abc import Callable

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import BoundTool, input_schema_for
from headless_re_mcp.tools.catalog import (
    COMMAND_CATALOG,
    CommandCatalog,
    CommandTransport,
)
from headless_re_mcp.tools.core import (
    build_core_session_tools,
    build_detect_tools,
    build_dotnet_tools,
    build_static_core_tools,
    build_static_extended_tools,
    build_workflow_tools,
)
from headless_re_mcp.tools.device import build_device_tools
from headless_re_mcp.tools.dex import build_dex_tools
from headless_re_mcp.tools.dynamic import build_dynamic_tools
from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools
from headless_re_mcp.tools.elf import build_elf_tools
from headless_re_mcp.tools.frida import build_frida_tools
from headless_re_mcp.tools.ghidra import build_ghidra_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools
from headless_re_mcp.tools.macho import build_macho_tools
from headless_re_mcp.tools.meta import build_meta_tools
from headless_re_mcp.tools.proxy import build_proxy_tools
from headless_re_mcp.tools.r2 import build_r2_tools
from headless_re_mcp.tools.trace import build_trace_tools
from headless_re_mcp.tools.ui import build_ui_tools
from headless_re_mcp.tools.unpack import build_unpack_tools
from headless_re_mcp.tools.web import build_web_tools
from headless_re_mcp.tools.windbg import build_windbg_tools
from headless_re_mcp.tools.workspace import build_workspace_tools

ToolFactory = Callable[[AnalysisService], tuple[BoundTool, ...]]

TOOL_FACTORIES: tuple[ToolFactory, ...] = (
    build_core_session_tools,
    build_static_core_tools,
    build_detect_tools,
    build_static_extended_tools,
    build_workflow_tools,
    build_dotnet_tools,
    build_dynamic_tools,
    build_dynamic_analysis_tools,
    build_frida_tools,
    build_ghidra_tools,
    build_meta_tools,
    build_r2_tools,
    build_trace_tools,
    build_ui_tools,
    build_unpack_tools,
    build_windbg_tools,
    build_apk_tools,
    build_dex_tools,
    build_elf_tools,
    build_macho_tools,
    build_device_tools,
    build_js_wasm_tools,
    build_web_tools,
    build_proxy_tools,
    build_workspace_tools,
)


def bind_all_tools(
    analysis: AnalysisService,
    catalog: CommandCatalog = COMMAND_CATALOG,
) -> tuple[BoundTool, ...]:
    """Build every domain handler and bind complete metadata into one catalog."""

    # Set before binding, since bind_mcp reads it to decide whether to guard.
    # The agent route and the OpenAI bridge come through here rather than the MCP
    # server, and would otherwise stay writable in a read-only deployment.
    catalog.write_allowed = bool(analysis.settings.local_full_access)
    bindings = tuple(binding for factory in TOOL_FACTORIES for binding in factory(analysis))
    names = [binding.name for binding in bindings]
    if len(names) != len(set(names)):
        raise ValueError("duplicate protocol-independent tool binding")
    expected = {
        spec.name for spec in catalog.for_transport(CommandTransport.MCP)
    }
    actual = set(names)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"tool binding mismatch: missing={missing}, extra={extra}")
    for binding in bindings:
        catalog.bind_handler(
            binding.name,
            binding.handler,
            input_schema=input_schema_for(binding.handler),
            description=binding.handler.__doc__ or binding.name,
        )
    return bindings
