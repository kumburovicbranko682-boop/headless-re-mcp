from __future__ import annotations

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.server import create_server


@pytest.mark.asyncio
async def test_minimal_mcp_tool_surface() -> None:
    server = create_server(AnalysisService())
    tools = await server.list_tools()
    names = {tool.name for tool in tools}
    assert names == {
        "doctor",
        "detect.scan",
        "detect.explain",
        "packer.classify",
        "unpack.recommend",
        "dotnet.inspect",
        "dotnet.deobfuscate",
        "dotnet.reactor.unpack",
        "dotnet.enumerate",
        "dotnet.il",
        "dotnet.xrefs",
        "dotnet.verify",
        "unpack.upx.test",
        "unpack.upx.unpack",
        "unpack.external.probe",
        "unpack.xvlkc.unpack",
        "unpack.vmp.dump",
        "unpack.scylla.rebuild",
        "unpack.auto",
        "unpack.plan",
        "unpack.start",
        "unpack.status",
        "unpack.cancel",
        "unpack.artifacts",
        "unpack.score_oep",
        "unpack.confirm_oep",
        "session.create",
        "session.get",
        "session.list",
        "session.close",
        "static.open",
        "static.functions",
        "static.strings",
        "static.decompile",
        "static.metadata",
        "static.segments",
        "static.imports",
        "static.exports",
        "static.entrypoints",
        "static.disassemble",
        "static.xrefs_to",
        "static.xrefs_from",
        "static.callers",
        "static.callees",
        "static.basic_blocks",
        "static.cfg",
        "static.globals",
        "static.names",
        "static.types",
        "static.structs",
        "static.enums",
        "static.bytes.read",
        "static.search.bytes",
        "static.search.text",
        "static.search.immediate",
        "static.name.set",
        "static.comment.set",
        "static.type.apply",
        "static.function.create",
        "static.function.delete",
        "static.bytes.patch",
        "static.batch",
        "dynamic.open",
        "dynamic.state",
        "ui.windows.list",
        "ui.process_tree",
        "ui.tree",
        "ui.resolve",
        "ui.click",
        "ui.click_at",
        "ui.window.close",
        "ui.text.set",
        "ui.key",
        "ui.invoke",
        "ui.wait",
        "ui.screenshot",
        "ui.ocr",
        "ui.drive_to_event",
        "ui.drive_to_breakpoint",
        "capabilities.search",
        "capabilities.describe",
        "r2.info",
        "r2.open",
        "r2.functions",
        "r2.strings",
        "r2.imports",
        "r2.exports",
        "r2.disasm",
        "r2.xrefs",
        "ghidra.analyze",
        "ghidra.functions",
        "ghidra.symbols",
        "ghidra.xrefs",
        "ghidra.decompile",
        "frida.attach",
        "frida.modules",
        "frida.exports",
        "frida.memory.read",
        "frida.hook.template",
        "windbg.open_dump",
        "windbg.threads",
        "windbg.modules",
        "windbg.disasm",
        "windbg.attach",
        "windbg.live_threads",
        "windbg.live_modules",
        "windbg.live_disasm",
        "artifacts.list",
        "artifacts.describe",
        "artifacts.read",
        "artifacts.gc",
        "timeline.list",
        "sessions.unclean",
        "audit.list",
        "dynamic.events",
        "dynamic.wait",
        "dynamic.launch",
        "dynamic.attach",
        "dynamic.stop",
        "dynamic.pause",
        "dynamic.resume",
        "dynamic.step_into",
        "dynamic.step_over",
        "dynamic.registers.read",
        "dynamic.registers.write",
        "dynamic.memory.read",
        "dynamic.memory.write",
        "memory.regions",
        "memory.protect.query",
        "memory.protection",
        "threads.list",
        "threads.current",
        "threads.context.read",
        "threads.context.write",
        "stack.read",
        "stack.trace",
        "disassembly.read",
        "symbols.list",
        "symbols.resolve",
        "dynamic.modules",
        "modules.list",
        "modules.resolve",
        "modules.dump",
        "pe.headers.runtime",
        "imports.scan",
        "imports.read",
        "unpack.dump_module",
        "unpack.stub_coupling",
        "unpack.iat.scan",
        "unpack.iat.validate",
        "unpack.iat.rebuild",
        "unpack.pe.rebuild",
        "unpack.verify",
        "dynamic.breakpoints",
        "dynamic.breakpoint.set",
        "dynamic.breakpoint.remove",
        "breakpoints.hardware.set",
        "breakpoints.hardware.remove",
        "breakpoints.hardware.list",
        "breakpoints.memory.set",
        "breakpoints.memory.remove",
        "breakpoints.memory.list",
        "breakpoints.condition.set",
        "breakpoints.condition.get",
        "patches.list",
        "patches.apply",
        "patches.restore",
        "trace.start",
        "trace.stop",
        "trace.status",
        "sync.static_to_runtime",
        "sync.runtime_to_static",
        "sync.module_preferred_to_runtime",
        "sync.module_runtime_to_preferred",
        "workflow.status",
        "workflow.reset",
        "workflow.cancel",
        "workflow.events.consume",
        "workflow.module.track",
        "workflow.module.untrack",
        "workflow.module.refresh",
        "workflow.breakpoint.put",
        "workflow.breakpoint.disable",
        "workflow.breakpoint.remove",
        "workflow.breakpoint.list",
        "workflow.navigate_to_event",
        "workflow.navigate_to_breakpoint",
    }

    events_tool = next(tool for tool in tools if tool.name == "dynamic.events")
    properties = events_tool.inputSchema["properties"]
    assert set(properties) == {"session_id", "limit", "timeout"}
    assert "cursor" not in properties
    assert properties["limit"]["minimum"] == 1
    assert properties["limit"]["maximum"] == 256
    assert properties["timeout"]["exclusiveMinimum"] == 0
    assert properties["timeout"]["maximum"] == 30.0

    workflow_events = next(
        tool for tool in tools if tool.name == "workflow.events.consume"
    )
    workflow_event_properties = workflow_events.inputSchema["properties"]
    assert set(workflow_event_properties) == {"session_id", "limit", "timeout"}
    assert "cursor" not in workflow_event_properties

    navigate = next(tool for tool in tools if tool.name == "workflow.navigate_to_event")
    navigate_properties = navigate.inputSchema["properties"]
    assert navigate_properties["timeout"]["maximum"] == 300.0
    assert navigate_properties["event_budget"]["minimum"] == 1
    assert navigate_properties["event_budget"]["maximum"] == 100_000

    resolve_tool = next(tool for tool in tools if tool.name == "modules.resolve")
    assert set(resolve_tool.inputSchema["properties"]) == {"session_id", "selector"}
    selector_schema = resolve_tool.inputSchema["$defs"]["ModuleSelector"]
    assert selector_schema["additionalProperties"] is False
    assert selector_schema["anyOf"] == [
        {"required": ["base"]},
        {"required": ["path"]},
        {"required": ["name"]},
    ]
    assert set(selector_schema["properties"]) == {"base", "path", "name", "sha256"}

    for name in {
        "sync.module_preferred_to_runtime",
        "sync.module_runtime_to_preferred",
    }:
        tool = next(item for item in tools if item.name == name)
        assert set(tool.inputSchema["properties"]) == {
            "session_id",
            "selector",
            "address",
        }
