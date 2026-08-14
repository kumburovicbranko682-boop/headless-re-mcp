from __future__ import annotations

import pytest

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.server import create_server


@pytest.mark.asyncio
async def test_minimal_mcp_tool_surface() -> None:
    analysis = AnalysisService()
    object.__setattr__(analysis.settings, "workspace_profile", "full")
    server = create_server(analysis)
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
        "session.health",
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
        "ui.virtual_desktop.snapshot",
        "ui.virtual_desktop.capture",
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
        "sync.resolve_runtime_address",
        "dynamic.analyze_function",
        "dynamic.trace_api_arguments",
        "meta.metrics",
        "knowledge.record",
        "knowledge.query",
        "report.generate",
        "session.recover",
        "batch.analyze",
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
        # Android static (apk.*)
        "apk.open",
        "apk.manifest",
        "apk.permissions",
        "apk.certificates",
        "apk.components",
        "apk.native_libs",
        "apk.classes",
        "apk.methods",
        "apk.strings",
        "apk.xrefs",
        "apk.decompile",
        "apk.export_sources",
        "apk.decode",
        "apk.repack",
        "apk.sign",
        # Device control (device.*)
        "device.list",
        "device.connect",
        "device.info",
        "device.properties",
        "device.packages",
        "device.install",
        "device.uninstall",
        "device.launch",
        "device.force_stop",
        "device.current_activity",
        "device.logcat",
        "device.screenshot",
        "device.pull",
        "device.push",
        "device.forward",
        # Frida device dimension
        "frida.devices",
        "frida.device.connect",
        "frida.server.ensure",
        "frida.applications",
        "frida.spawn",
        "frida.java.classes",
        "frida.java.methods",
        # Web static (js.* / wasm.*)
        "js.deobfuscate",
        "js.beautify",
        "js.unpack_bundle",
        "wasm.info",
        "wasm.wat",
        # Web dynamic (web.*)
        "web.open",
        "web.navigate",
        "web.close",
        "web.network.list",
        "web.network.get",
        "web.console",
        "web.scripts",
        "web.script.source",
        "web.wasm.list",
        "web.dom.snapshot",
        "web.screenshot",
        "web.har.export",
        # Interception (proxy.*)
        "proxy.start",
        "proxy.stop",
        "proxy.status",
        "proxy.flows",
        "proxy.flow.get",
        "proxy.replay",
        "proxy.export_har",
        "proxy.ca.install_android",
        # Workspace work direction
        "workspace.mode.get",
        "workspace.mode.set",
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


@pytest.mark.asyncio
async def test_every_timeout_parameter_declares_an_upper_bound() -> None:
    """No caller may buy an unbounded wait.

    A synchronous tool holds one slot of the bounded MCP thread pool for its
    whole duration, so a tool that accepts ``timeout`` without a maximum lets a
    single call park a slot for as long as it likes. Schema validation has to
    reject that before any backend is reached.
    """
    server = create_server(AnalysisService())
    tools = await server.list_tools()
    unbounded: list[str] = []
    for tool in tools:
        for parameter, schema in tool.inputSchema.get("properties", {}).items():
            if "timeout" not in parameter and not parameter.endswith(("_ms", "_seconds")):
                continue
            # Optional parameters are wrapped in anyOf with a null branch.
            candidates = schema.get("anyOf") or [schema]
            numeric = [item for item in candidates if item.get("type") in {"number", "integer"}]
            if numeric and not any(
                "maximum" in item or "exclusiveMaximum" in item for item in numeric
            ):
                unbounded.append(f"{tool.name}.{parameter}")
    assert unbounded == []


def test_a_nested_stdio_request_gets_an_error_named_after_it() -> None:
    """pydantic gives up around 200 levels; json.loads does not.

    The SDK put that ValidationError on the read stream. The server logged
    Internal Server Error and never wrote a JSON-RPC response, so a tools/call
    nested 200 deep produced no reply at all.
    """
    import json

    from headless_re_mcp.mcp.stdio_errors import error_message_for_unreadable_line

    nested = '{"a":' * 200 + "1" + "}" * 200
    line = (
        '{"jsonrpc":"2.0","id":7,"method":"tools/call",'
        '"params":{"name":"session.get","arguments":' + nested + "}}"
    )
    reply = error_message_for_unreadable_line(line)
    assert reply is not None, "a request with an id has to get an error, not silence"
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 7
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" in dumped["error"]["message"]


def test_a_valid_stdio_line_is_not_turned_into_an_error() -> None:
    from headless_re_mcp.mcp.stdio_errors import error_message_for_unreadable_line

    line = '{"jsonrpc":"2.0","id":1,"method":"ping"}'
    assert error_message_for_unreadable_line(line) is None


def test_garbage_without_an_id_stays_silent() -> None:
    from headless_re_mcp.mcp.stdio_errors import error_message_for_unreadable_line

    assert error_message_for_unreadable_line("{not-json") is None


def test_server_instructions_cover_apk_and_web_not_just_pe() -> None:
    """The initialize payload told the model it could only open a PE.

    Measured: instructions were 290 characters, mentioned PE and IDA,
    mentioned neither APK nor web, while session.create already accepts
    both and the live catalog had 42 apk-family tools and 25 web-family
    tools. A caller that follows the instructions will not start those
    sessions.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        text = (server.instructions or "").casefold()
        assert "apk" in text
        assert "web" in text
        assert "authorized local pe, then open its static ida" not in text
        tools = server._tool_manager._tools
        apk = [name for name in tools if name.startswith(("apk.", "device."))]
        web = [name for name in tools if name.startswith(("web.", "js.", "wasm.", "proxy."))]
        assert len(apk) >= 20
        assert len(web) >= 15
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_batch_analyze_description_names_live_fields() -> None:
    """The catalog did not name the fields a successful batch actually returns.

    Measured: keys are entries, count, succeeded, failed, max_workers; each
    entry has binary, ok, session_id, and error when that sample failed. A
    caller looking for sessions or results at the top level reads an empty
    batch that in fact created two sessions.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "batch.analyze")
        text = tool.description or ""
        for name in ("entries", "count", "succeeded", "failed", "session_id", "max_workers"):
            assert name in text, name
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_knowledge_record_description_names_live_fields() -> None:
    """The catalog did not say the write reply omits the value.

    Measured keys are session_id, kind, key, created_at, updated_at, replaced.
    There is no value field. A caller that looks for the fact it just stored
    reads a successful write as if nothing was recorded.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "knowledge.record")
        text = tool.description or ""
        for name in ("replaced", "created_at", "updated_at", "session_id"):
            assert name in text, name
        assert "not echoed" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_knowledge_query_description_names_live_fields() -> None:
    """The catalog did not name the paged list a query actually returns.

    Measured keys are entries, count, total, offset, limit, has_more, kinds
    and session_id. A caller looking for a top-level facts array reads an
    empty query that in fact held the page in entries.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "knowledge.query")
        text = tool.description or ""
        for name in ("entries", "total", "has_more", "kinds"):
            assert name in text, name
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_meta_metrics_description_names_live_fields() -> None:
    """The catalog did not name the objects the percentiles actually live in.

    Measured keys are tools, recent, sampled_calls, distinct_tools, failures,
    calls_total, failures_total and capacity. A caller looking for a top-level
    p95_ms reads an empty metrics reply that in fact held the series in tools.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "meta.metrics")
        text = tool.description or ""
        for name in ("tools", "recent", "sampled_calls", "p95_ms", "capacity"):
            assert name in text, name
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_report_generate_description_names_live_fields() -> None:
    """The catalog did not name where the rendered report actually is.

    Measured keys are markdown, path, bytes, findings and artifact_id. A
    caller looking for a top-level report or text field reads a successful
    generate as if nothing was written.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "report.generate")
        text = tool.description or ""
        for name in ("markdown", "path", "bytes", "findings", "artifact_id"):
            assert name in text, name
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_artifacts_read_description_names_live_fields() -> None:
    """The catalog did not say the bytes come back as a hex string.

    Measured keys are artifact_id, data, encoding, offset, limit and size.
    encoding is hex. A caller that treats data as UTF-8 text misreads every
    dump and every spilled decompilation.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "artifacts.read")
        text = tool.description or ""
        for name in ("data", "encoding", "hex", "offset", "size"):
            assert name in text, name
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_artifacts_list_description_names_the_array_field() -> None:
    """The catalog named the columns and not the list they live in.

    Measured keys are artifacts, count, total, offset, limit and has_more.
    There is no items field. A caller looking for items after a successful
    list reads the tree as empty.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "artifacts.list")
        text = tool.description or ""
        assert "Answers with artifacts" in text
        assert "no items field" in text
        assert "has_more" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_timeline_list_description_names_live_fields() -> None:
    """The catalog did not name the events array a successful list returns.

    Measured keys are events, count, total, offset, limit, has_more and path.
    A missing session is session_not_found, not an empty list. A caller
    looking for a top-level timeline field reads a live session as idle.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "timeline.list")
        text = tool.description or ""
        assert "Answers with events" in text
        assert "session_not_found" in text
        assert "has_more" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_artifacts_describe_description_names_the_nested_object() -> None:
    """The catalog listed origin and the columns as if they were top-level.

    Measured: the payload is artifact holding id, kind, path, size, sha256,
    source, session_id and created_at. There is no origin. A caller looking
    for kind on the reply reads a successful describe as empty.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "artifacts.describe")
        text = tool.description or ""
        assert "Answers with artifact" in text
        assert "source" in text
        assert "no origin field" in text
        assert "not top-level" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_artifacts_gc_description_names_live_fields() -> None:
    """The catalog did not name what a collection pass actually returns.

    Measured keys are removed, count, skipped, skipped_count and
    bytes_remaining_estimate. A caller looking for deleted or freed_bytes
    cannot tell whether anything was collected.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "artifacts.gc")
        text = tool.description or ""
        for name in ("removed", "skipped", "skipped_count", "bytes_remaining_estimate"):
            assert name in text, name
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_session_health_description_names_live_fields() -> None:
    """The catalog did not name backends, count or the three-state healthy flag.

    Measured keys are backends, count and healthy. healthy is null when
    nothing is open, which is not a clean bill of health. A caller looking
    for a top-level ok reads an empty health check as if every backend died.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "session.health")
        text = tool.description or ""
        for name in ("backends", "count", "healthy"):
            assert name in text, name
        assert "null" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_audit_list_description_names_live_fields() -> None:
    """The catalog did not name the entries array a successful list returns.

    Measured keys are entries, count, total, offset, limit and has_more.
    There is no events field. A caller looking for events after a successful
    list reads the audit as empty.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "audit.list")
        text = tool.description or ""
        assert "Answers with entries" in text
        assert "no events field" in text
        assert "has_more" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_sessions_unclean_description_names_the_array_field() -> None:
    """The catalog named total and has_more but not the list they page.

    Measured keys are sessions, count, total, offset and has_more. A caller
    looking for items after a successful list reads leftover work as none.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "sessions.unclean")
        text = tool.description or ""
        assert "Answers with sessions" in text
        assert "has_more" in text
        assert "total" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_capabilities_search_description_names_live_fields() -> None:
    """The catalog did not name the list a successful search returns.

    Measured keys are capabilities and count. Each item has id, backend,
    status, status_probe, summary and tools. A caller looking for items
    reads an empty catalog that in fact listed every backend.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "capabilities.search")
        text = tool.description or ""
        assert "Answers with capabilities" in text
        assert "no items field" in text
        assert "status_probe" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_capabilities_describe_description_names_the_nested_object() -> None:
    """The catalog did not say the record is nested under capability.

    Measured payload is capability holding id, backend, status, status_probe,
    summary and tools. A caller looking for status on the reply reads a
    successful describe as missing.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "capabilities.describe")
        text = tool.description or ""
        assert "Answers with capability" in text
        assert "not top-level" in text
        assert "not_found" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_dynamic_state_description_names_both_pid_fields() -> None:
    """The catalog named debuggee_pid and not process_id, which is 0 when idle.

    Measured keys are state, running, debugging, process_id, thread_id,
    debuggee_pid, debugger_pid and pid_note. A caller that treats process_id
    as the target attaches to pid 0.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "dynamic.state")
        text = tool.description or ""
        assert "process_id" in text
        assert "debuggee_pid" in text
        assert "pid_note" in text
    finally:
        analysis.close_all()


@pytest.mark.asyncio
async def test_dynamic_open_description_names_live_fields() -> None:
    """The catalog did not name backend, reused or the nested session.

    Measured keys are backend, reused and session. A caller looking for a
    top-level session_id after a successful open cannot tell whether the
    debugger is already running.
    """
    analysis = AnalysisService()
    try:
        object.__setattr__(analysis.settings, "workspace_profile", "full")
        server = create_server(analysis)
        tools = await server.list_tools()
        tool = next(item for item in tools if item.name == "dynamic.open")
        text = tool.description or ""
        for name in ("backend", "reused", "session"):
            assert name in text, name
    finally:
        analysis.close_all()
