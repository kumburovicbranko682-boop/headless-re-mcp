"""Protocol-independent catalog for every bounded analysis tool."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from enum import StrEnum
from functools import wraps
from typing import Any


class CommandTransport(StrEnum):
    MCP = "mcp"
    WEB = "legacy_web"
    AGENT = "agent"


class ToolEffect(StrEnum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    FILE_WRITE = "file_write"


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    timeout_seconds: float = 60.0
    max_result_bytes: int = 262_144


@dataclass(frozen=True, slots=True)
class CommandSpec:
    name: str
    service_method: str
    transports: frozenset[CommandTransport]
    effects: frozenset[ToolEffect]
    handler: Callable[..., dict[str, Any]] | None = None
    input_schema: dict[str, Any] | None = None
    description: str | None = None
    resource_policy: ResourcePolicy = ResourcePolicy()

    @property
    def write(self) -> bool:
        return bool(self.effects & {ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE})

    @property
    def confirm_required(self) -> bool:
        return self.write

    @property
    def agent_auto_execute(self) -> bool:
        return self.effects == frozenset({ToolEffect.READ_ONLY})

    def bind_mcp(
        self,
        handler: Callable[..., dict[str, Any]],
        *,
        input_schema: dict[str, Any],
        description: str | None,
    ) -> CommandSpec:
        return replace(
            self,
            handler=handler,
            input_schema=input_schema,
            description=description,
        )


ToolSpec = CommandSpec

_READ_ONLY_NAMES = frozenset((
    'artifacts.describe',
    'artifacts.list',
    'artifacts.read',
    'audit.list',
    'breakpoints.condition.get',
    'breakpoints.hardware.list',
    'breakpoints.memory.list',
    'capabilities.describe',
    'capabilities.search',
    'detect.explain',
    'detect.scan',
    'disassembly.read',
    'doctor',
    'dotnet.enumerate',
    'dotnet.il',
    'dotnet.inspect',
    'dotnet.verify',
    'dotnet.xrefs',
    'dynamic.breakpoints',
    'dynamic.events',
    'dynamic.memory.read',
    'dynamic.modules',
    'dynamic.registers.read',
    'dynamic.state',
    'dynamic.stealth.status',
    'frida.exports',
    'frida.memory.read',
    'frida.modules',
    'ghidra.decompile',
    'ghidra.functions',
    'ghidra.symbols',
    'ghidra.xrefs',
    'imports.read',
    'imports.scan',
    'memory.protect.query',
    'knowledge.query',
    'memory.regions',
    'meta.metrics',
    'modules.list',
    'modules.resolve',
    'packer.classify',
    'patches.list',
    'pe.headers.runtime',
    'r2.disasm',
    'r2.disasm_function',
    'r2.entrypoints',
    'r2.exports',
    'r2.functions',
    'r2.imports',
    'r2.info',
    'r2.read',
    'r2.search',
    'r2.sections',
    'r2.strings',
    'r2.symbols',
    'r2.xrefs',
    'session.get',
    'session.health',
    'session.list',
    'sessions.unclean',
    'stack.read',
    'stack.trace',
    'static.basic_blocks',
    'static.bytes.read',
    'static.callees',
    'static.callers',
    'static.cfg',
    'static.decompile',
    'static.disassemble',
    'static.entrypoints',
    'static.enums',
    'static.exports',
    'static.functions',
    'static.globals',
    'static.imports',
    'static.metadata',
    'static.names',
    'static.search.bytes',
    'static.search.immediate',
    'static.search.text',
    'static.segments',
    'static.strings',
    'static.structs',
    'static.types',
    'static.xrefs_from',
    'static.xrefs_to',
    'symbols.list',
    'symbols.resolve',
    'sync.module_preferred_to_runtime',
    'sync.module_runtime_to_preferred',
    'sync.resolve_runtime_address',
    'sync.runtime_to_static',
    'sync.static_to_runtime',
    'threads.context.read',
    'threads.current',
    'threads.list',
    'timeline.list',
    'trace.status',
    'ui.ocr',
    'ui.process_tree',
    'ui.resolve',
    'ui.tree',
    'ui.virtual_desktop.snapshot',
    'ui.windows.list',
    'unpack.artifacts',
    'unpack.external.probe',
    'unpack.plan',
    'unpack.recommend',
    'unpack.status',
    'unpack.stub_coupling',
    'unpack.upx.test',
    'windbg.disasm',
    'windbg.live_disasm',
    'windbg.live_modules',
    'windbg.live_threads',
    'windbg.modules',
    'windbg.threads',
    'workflow.breakpoint.list',
    'workflow.status',
    # Android / Web / workspace read-only tools.
    'apk.certificates',
    'apk.classes',
    'apk.components',
    'apk.field_xrefs',
    'apk.fields',
    'apk.manifest',
    'apk.method_bytecode',
    'apk.method_refs',
    'apk.methods',
    'apk.native_libs',
    'apk.open',
    'apk.permissions',
    'apk.strings',
    'apk.string_xrefs',
    'apk.xrefs',
    'device.current_activity',
    'device.info',
    'device.list',
    'device.logcat',
    'device.packages',
    'device.properties',
    'frida.applications',
    'frida.devices',
    'frida.java.classes',
    'frida.java.methods',
    'js.beautify',
    'js.deobfuscate',
    'proxy.flow.get',
    'proxy.flows',
    'proxy.status',
    'proxy.ws.frames',
    'wasm.decompile',
    'wasm.info',
    'wasm.summary',
    'wasm.wat',
    'web.console',
    'web.cookies',
    'web.dom.snapshot',
    'web.frames',
    'web.network.get',
    'web.network.list',
    'web.script.source',
    'web.scripts',
    'web.storage',
    'web.wasm.list',
    'web.ws.frames',
    'web.ws.list',
    'workspace.mode.get',
))
_STATE_CHANGE_NAMES = frozenset((
    'breakpoints.condition.set',
    'dynamic.analyze_function',
    'dynamic.trace_api_arguments',
    'knowledge.record',
    'memory.protection',
    'session.recover',
    'breakpoints.hardware.remove',
    'breakpoints.hardware.set',
    'breakpoints.memory.remove',
    'breakpoints.memory.set',
    'dynamic.attach',
    'dynamic.breakpoint.remove',
    'dynamic.breakpoint.set',
    'dynamic.launch',
    'dynamic.memory.write',
    'dynamic.open',
    'dynamic.pause',
    'dynamic.registers.write',
    'dynamic.resume',
    'dynamic.step_into',
    'dynamic.step_over',
    'dynamic.stop',
    'dynamic.wait',
    'frida.attach',
    'frida.hook.template',
    'r2.open',
    'session.close',
    'threads.context.write',
    'ui.click',
    'ui.click_at',
    'ui.drive_to_breakpoint',
    'ui.drive_to_event',
    'ui.invoke',
    'ui.key',
    'ui.text.set',
    'ui.wait',
    'ui.window.close',
    'unpack.score_oep',
    'windbg.attach',
    'windbg.open_dump',
    'workflow.breakpoint.disable',
    'workflow.breakpoint.put',
    'workflow.breakpoint.remove',
    'workflow.cancel',
    'workflow.events.consume',
    'workflow.module.refresh',
    'workflow.module.track',
    'workflow.module.untrack',
    'workflow.navigate_to_breakpoint',
    'workflow.navigate_to_event',
    'workflow.reset',
    # Android / Web / workspace state-changing tools.
    'device.connect',
    'device.force_stop',
    'device.forward',
    'device.install',
    'device.launch',
    'device.push',
    'device.uninstall',
    'frida.device.connect',
    'frida.server.ensure',
    'frida.spawn',
    'proxy.ca.install_android',
    'proxy.replay',
    'proxy.start',
    'proxy.stop',
    'web.close',
    'web.navigate',
    'web.open',
    'workspace.mode.set',
))
_FILE_WRITE_NAMES = frozenset((
    'artifacts.gc',
    'batch.analyze',
    'dotnet.deobfuscate',
    'dotnet.reactor.unpack',
    'dynamic.stealth.set',
    'ghidra.analyze',
    'modules.dump',
    'patches.apply',
    'patches.restore',
    'report.generate',
    'session.create',
    'static.batch',
    'static.bytes.patch',
    'static.comment.set',
    'static.function.create',
    'static.function.delete',
    'static.name.set',
    'static.open',
    'static.type.apply',
    'trace.start',
    'trace.stop',
    'ui.screenshot',
    'ui.virtual_desktop.capture',
    'unpack.auto',
    'unpack.cancel',
    'unpack.confirm_oep',
    'unpack.dump_module',
    'unpack.iat.rebuild',
    'unpack.iat.scan',
    'unpack.iat.validate',
    'unpack.pe.rebuild',
    'unpack.scylla.rebuild',
    'unpack.start',
    'unpack.upx.unpack',
    'unpack.verify',
    'unpack.vmp.dump',
    'unpack.xvlkc.unpack',
    # Android / Web file-writing tools.
    'apk.decode',
    'apk.decompile',
    'apk.export_sources',
    'apk.extract_native_lib',
    'apk.repack',
    'apk.sign',
    'device.pull',
    'device.screenshot',
    'js.unpack_bundle',
    'proxy.export_har',
    'web.har.export',
    'web.screenshot',
))
_ALL_TOOL_NAMES = _READ_ONLY_NAMES | _STATE_CHANGE_NAMES | _FILE_WRITE_NAMES
if len(_ALL_TOOL_NAMES) != 285:
    raise RuntimeError("tool effect policy contains duplicates or omissions")

_WEB_NAMES = frozenset(['artifacts.describe', 'artifacts.gc', 'artifacts.list', 'audit.list', 'dynamic.breakpoints', 'dynamic.modules', 'dynamic.registers.read', 'dynamic.state', 'session.close', 'session.get', 'session.list', 'static.decompile', 'static.functions', 'static.strings', 'timeline.list', 'unpack.artifacts', 'unpack.cancel', 'unpack.status', 'workflow.cancel', 'workflow.status'])
_SERVICE_OVERRIDES = {
    "session.create": "create_session",
    "session.get": "get_session",
    "session.list": "list_sessions",
    "session.close": "close_session",
    "static.open": "open_static",
    "dynamic.open": "open_dynamic",
    "dynamic.registers.write": "dynamic_register_write",
    "modules.list": "module_catalog",
    "modules.resolve": "module_resolve",
    "ui.virtual_desktop.snapshot": "virtual_desktop_snapshot",
    "ui.virtual_desktop.capture": "virtual_desktop_capture",
    "sync.resolve_runtime_address": "resolve_runtime_address",
    "dynamic.analyze_function": "analyze_function_dynamic",
    "dynamic.trace_api_arguments": "trace_api_arguments",
    "meta.metrics": "tool_metrics",
}

# Agent tool_timeout is a ceiling; most tools stay at the 60s default.
# First IDA/x64dbg/Ghidra/APK open of a large sample routinely exceeds that.
_TOOL_TIMEOUTS: dict[str, float] = {
    "apk.open": 180.0,
    "dynamic.open": 180.0,
    "ghidra.analyze": 180.0,
    "static.open": 1800.0,
}


def _declared_spec(name: str) -> CommandSpec:
    if name in _READ_ONLY_NAMES:
        effects = frozenset({ToolEffect.READ_ONLY})
    elif name in _STATE_CHANGE_NAMES:
        effects = frozenset({ToolEffect.STATE_CHANGE})
    elif name in _FILE_WRITE_NAMES:
        effects = frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE})
    else:
        raise KeyError(f"tool has no explicit effects policy: {name}")
    transports = {CommandTransport.MCP, CommandTransport.AGENT}
    if name in _WEB_NAMES:
        transports.add(CommandTransport.WEB)
    timeout = _TOOL_TIMEOUTS.get(name)
    policy = ResourcePolicy(timeout_seconds=timeout) if timeout is not None else ResourcePolicy()
    return CommandSpec(
        name=name,
        service_method=_SERVICE_OVERRIDES.get(name, name.replace(".", "_")),
        transports=frozenset(transports),
        effects=effects,
        resource_policy=policy,
    )


class CommandCatalog:
    """Single catalog definition consumed by MCP, legacy Web and Agent."""

    def __init__(self, specs: Iterable[CommandSpec] | None = None) -> None:
        materialized = tuple(specs) if specs is not None else tuple(
            _declared_spec(name) for name in sorted(_ALL_TOOL_NAMES)
        )
        indexed = {spec.name: spec for spec in materialized}
        if len(indexed) != len(materialized):
            raise ValueError("tool names must be unique")
        if any(not spec.effects for spec in materialized):
            raise ValueError("every tool requires explicit effects")
        self._specs = indexed
        # Read at call time rather than at registration, so a deployment can be
        # put in read-only mode without rebuilding the tool surface, and so tools
        # keep being discoverable instead of silently vanishing.
        self.write_allowed = True

    def get(self, name: str) -> CommandSpec | None:
        return self._specs.get(name)

    def register(self, spec: CommandSpec) -> None:
        if not spec.effects:
            raise ValueError(f"tool effects missing: {spec.name}")
        existing = self._specs.get(spec.name)
        if existing is not None:
            if existing.service_method != spec.service_method:
                raise ValueError(f"tool service method changed: {spec.name}")
            if existing.effects != spec.effects or existing.transports != spec.transports:
                raise ValueError(f"tool policy changed: {spec.name}")
        self._specs[spec.name] = spec

    def bind_mcp(
        self,
        name: str,
        handler: Callable[..., dict[str, Any]],
        *,
        input_schema: dict[str, Any],
        description: str | None,
    ) -> CommandSpec:
        base = self.require(name)
        # Guarding here rather than in one transport's adapter: every binding
        # path arrives at this method, so the MCP server, the agent route and the
        # OpenAI bridge cannot end up with different write policies.
        guarded = self.guard_write(handler, name=name) if base.write else handler
        bound = base.bind_mcp(guarded, input_schema=input_schema, description=description)
        self.register(bound)
        return bound

    def guard_write(
        self,
        handler: Callable[..., dict[str, Any]],
        *,
        name: str,
    ) -> Callable[..., dict[str, Any]]:
        """Refuse a state-changing call while the deployment is read-only.

        The refusal is an ordinary error envelope: a caller that cannot write
        should learn why rather than watch the tool disappear. The flag is read
        per call so a running server is not stuck with the startup config.
        """

        @wraps(handler)
        def guarded(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if self.write_allowed:
                return handler(*args, **kwargs)
            return self.write_refusal(name)

        return guarded

    def write_refusal(self, name: str) -> dict[str, Any]:
        """The envelope every transport returns for a refused write."""
        return {
            "ok": False,
            "data": None,
            "error": {
                "code": "write_disabled",
                "message": f"{name} changes state and this deployment is read-only",
                "details": {"tool": name, "setting": "local_full_access"},
                "retryable": False,
            },
            "meta": {},
        }

    def bind_handler(
        self,
        name: str,
        handler: Callable[..., dict[str, Any]],
        *,
        input_schema: dict[str, Any],
        description: str | None,
    ) -> CommandSpec:
        """Bind protocol-independent handler metadata to one declared tool."""

        return self.bind_mcp(
            name,
            handler,
            input_schema=input_schema,
            description=description,
        )

    def require(self, name: str) -> CommandSpec:
        spec = self.get(name)
        if spec is None:
            raise KeyError(f"tool is unclassified and unavailable: {name}")
        return spec

    def for_transport(self, transport: CommandTransport) -> tuple[CommandSpec, ...]:
        return tuple(spec for spec in self._specs.values() if transport in spec.transports)

    def write_names(self, transport: CommandTransport) -> frozenset[str]:
        return frozenset(spec.name for spec in self.for_transport(transport) if spec.confirm_required)

    def uncategorized_names(self) -> tuple[str, ...]:
        return tuple(sorted(spec.name for spec in self._specs.values() if not spec.effects))

    def schemas(self, transport: CommandTransport = CommandTransport.MCP) -> dict[str, dict[str, Any]]:
        return {
            spec.name: dict(spec.input_schema or {})
            for spec in self.for_transport(transport)
        }

    def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        spec = self.require(name)
        if spec.handler is None:
            raise RuntimeError(f"tool handler is not bound: {name}")
        from headless_re_mcp.error_boundary import exception_envelope

        try:
            return spec.handler(**arguments)
        except BaseException as exc:  # noqa: BLE001 - Agent transport must stay alive
            return exception_envelope(exc, context=f"agent-tool:{name}")


COMMAND_CATALOG = CommandCatalog()
ToolCatalog = CommandCatalog
TOOL_CATALOG = COMMAND_CATALOG
