from __future__ import annotations

import asyncio
import ntpath
import os
import sys
import time
from hashlib import sha256
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ADDRESS_TOOLS = frozenset(
    {
        "modules.list",
        "modules.resolve",
        "sync.static_to_runtime",
        "sync.runtime_to_static",
        "sync.module_preferred_to_runtime",
        "sync.module_runtime_to_preferred",
    }
)
_CASES = [
    ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86),
    ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64),
]


def _configured_fixture(variable: str, architecture: Architecture) -> Path:
    if not os.environ.get(variable):
        pytest.skip(f"{variable} is not configured")
    if Settings.load().ida_home is None:
        pytest.skip("IDA home is not configured")
    fixture = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "headless_fixture.exe"
    )
    if not fixture.is_file():
        pytest.skip(f"fixture is not built: {fixture}")
    return fixture.resolve()


def _entry_rva(binary: Path) -> int:
    image = binary.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    result = int.from_bytes(image[optional_header + 16 : optional_header + 20], "little")
    assert result > 0
    return result


def _preferred_image_layout(binary: Path) -> tuple[int, int]:
    image = binary.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    magic = int.from_bytes(image[optional_header : optional_header + 2], "little")
    if magic == 0x10B:
        base_offset, base_size = optional_header + 28, 4
    else:
        assert magic == 0x20B
        base_offset, base_size = optional_header + 24, 8
    preferred_base = int.from_bytes(
        image[base_offset : base_offset + base_size],
        "little",
    )
    image_size = int.from_bytes(
        image[optional_header + 56 : optional_header + 60],
        "little",
    )
    assert preferred_base > 0 and image_size > 0
    return preferred_base, image_size


def _object(value: object) -> JsonObject:
    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


def _matching_module(module_result: JsonObject, binary: Path) -> JsonObject | None:
    raw_modules = module_result.get("modules")
    assert isinstance(raw_modules, list)
    expected_name = binary.name.casefold()
    expected_path = ntpath.normcase(ntpath.normpath(str(binary.resolve())))
    for raw_module in raw_modules:
        module = _object(raw_module)
        name = str(module.get("name", ""))
        path = str(module.get("path", ""))
        if (
            ntpath.normcase(ntpath.normpath(path)) == expected_path
            or name.casefold() == expected_name
            or ntpath.basename(path).casefold() == expected_name
        ):
            return module
    return None


def _main_module(module_result: JsonObject, binary: Path) -> JsonObject:
    module = _matching_module(module_result, binary)
    if module is not None:
        return module
    raise AssertionError(f"main module missing from {module_result!r}")


def _service_data(result: Result[JsonObject]) -> JsonObject:
    assert result.ok, result.model_dump(mode="json")
    assert result.data is not None
    return result.data


def _session_id(data: JsonObject) -> str:
    return str(_object(data["session"])["id"])


def _structured(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict)
    return {str(key): item for key, item in content.items()}


async def _mcp_call(
    client: ClientSession,
    tool: str,
    arguments: JsonObject,
) -> JsonObject:
    envelope = _structured(await client.call_tool(tool, arguments))
    assert envelope["ok"] is True, envelope
    return _object(envelope["data"])


async def _mcp_failure(
    client: ClientSession,
    tool: str,
    arguments: JsonObject,
) -> JsonObject:
    envelope = _structured(await client.call_tool(tool, arguments))
    assert envelope["ok"] is False, envelope
    return _object(envelope["error"])


def _module_event_seen(
    batch: JsonObject,
    *,
    kind: str,
    module_path: Path,
    runtime_base: int | None,
) -> bool:
    raw_events = batch.get("events")
    assert isinstance(raw_events, list)
    expected_name = module_path.name.casefold()
    for raw_event in raw_events:
        event = _object(raw_event)
        if event.get("kind") != kind:
            continue
        data = _object(event["data"])
        if kind == "module.loaded":
            name = ntpath.basename(str(data.get("name", ""))).casefold()
            if name == expected_name:
                return True
        elif runtime_base is not None and int(data.get("base", -1)) == runtime_base:
            return True
    return False


def _service_pause_after_module_event(
    service: AnalysisService,
    session_id: str,
    module_path: Path,
    *,
    kind: str,
    runtime_base: int | None = None,
) -> JsonObject:
    resumed = _service_data(service.dynamic_resume(session_id))
    assert resumed["state"] in {"running", "paused"}
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        batch = _service_data(service.dynamic_events(session_id, limit=256))
        if _module_event_seen(
            batch,
            kind=kind,
            module_path=module_path,
            runtime_base=runtime_base,
        ):
            paused = _service_data(service.dynamic_pause(session_id, timeout=30.0))
            assert _object(paused["state"])["state"] == "paused"
            return _service_data(service.module_catalog(session_id))
        state = _service_data(service.dynamic_state(session_id))
        if state["state"] == "idle":
            break
        if state["state"] == "paused":
            resumed = _service_data(service.dynamic_resume(session_id))
            assert resumed["state"] in {"running", "paused"}
        time.sleep(0.05)
    raise AssertionError(f"{kind} was not observed for {module_path.name} within 20 seconds")


async def _mcp_pause_after_module_event(
    client: ClientSession,
    session_id: str,
    module_path: Path,
    *,
    kind: str,
    runtime_base: int | None = None,
) -> JsonObject:
    resumed = await _mcp_call(
        client,
        "dynamic.resume",
        {"session_id": session_id},
    )
    assert resumed["state"] in {"running", "paused"}
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        batch = await _mcp_call(
            client,
            "dynamic.events",
            {"session_id": session_id, "limit": 256},
        )
        if _module_event_seen(
            batch,
            kind=kind,
            module_path=module_path,
            runtime_base=runtime_base,
        ):
            paused = await _mcp_call(
                client,
                "dynamic.pause",
                {"session_id": session_id, "timeout": 30.0},
            )
            assert _object(paused["state"])["state"] == "paused"
            return await _mcp_call(
                client,
                "modules.list",
                {"session_id": session_id},
            )
        state = await _mcp_call(
            client,
            "dynamic.state",
            {"session_id": session_id},
        )
        if state["state"] == "idle":
            break
        if state["state"] == "paused":
            resumed = await _mcp_call(
                client,
                "dynamic.resume",
                {"session_id": session_id},
            )
            assert resumed["state"] in {"running", "paused"}
        await asyncio.sleep(0.05)
    raise AssertionError(f"{kind} was not observed for {module_path.name} within 20 seconds")


def _service_resume_until_idle(
    service: AnalysisService,
    session_id: str,
    *,
    timeout: float = 30.0,
) -> JsonObject:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("debuggee did not reach idle within the lifecycle bound")
        result = _service_data(
            service.dynamic_resume(
                session_id,
                wait_for_pause=True,
                timeout=remaining,
            )
        )
        state = _object(result["state"])
        if state["state"] == "idle":
            return result
        assert state["state"] == "paused"


async def _mcp_resume_until_idle(
    client: ClientSession,
    session_id: str,
    *,
    timeout: float = 30.0,
) -> JsonObject:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("debuggee did not reach idle within the lifecycle bound")
        result = await _mcp_call(
            client,
            "dynamic.resume",
            {
                "session_id": session_id,
                "wait_for_pause": True,
                "timeout": remaining,
            },
        )
        state = _object(result["state"])
        if state["state"] == "idle":
            return result
        assert state["state"] == "paused"


def _assert_resolved_module(
    resolved: JsonObject,
    *,
    architecture: Architecture,
    module_path: Path,
    runtime_module: JsonObject,
    preferred_base: int,
    image_size: int,
    expected_sha256: str,
    match_basis: str,
) -> None:
    identity = _object(resolved["module"])
    preferred = _object(resolved["preferred"])
    runtime = _object(resolved["runtime"])
    runtime_base = int(runtime_module["base"])
    assert identity["architecture"] == architecture.value
    assert identity["sha256"] == expected_sha256
    assert ntpath.normcase(str(identity["path"])) == ntpath.normcase(str(module_path.resolve()))
    assert resolved["match_basis"] == match_basis
    assert resolved["rebase_delta"] == runtime_base - preferred_base
    assert preferred["base"] == preferred_base
    assert preferred["size"] == image_size
    assert runtime["base"] == runtime_base
    assert runtime["size"] == image_size


def _assert_rebased_round_trip(
    to_runtime: JsonObject,
    to_preferred: JsonObject,
    *,
    preferred_base: int,
    runtime_base: int,
    rva: int,
) -> None:
    preferred_address = preferred_base + rva
    runtime_address = runtime_base + rva
    assert to_runtime["source"] == "preferred"
    assert to_runtime["target"] == "runtime"
    assert to_runtime["rva"] == rva
    assert _object(to_runtime["preferred"])["address"] == preferred_address
    assert _object(to_runtime["runtime"])["address"] == runtime_address
    assert to_preferred["source"] == "runtime"
    assert to_preferred["target"] == "preferred"
    assert to_preferred["rva"] == rva
    assert _object(to_preferred["preferred"])["address"] == preferred_address
    assert _object(to_preferred["runtime"])["address"] == runtime_address


def _assert_round_trip(
    mapping: JsonObject,
    *,
    architecture: Architecture,
    static_address: int,
    runtime_address: int,
    rva: int,
) -> None:
    module = _object(mapping["module"])
    static = _object(mapping["static"])
    runtime = _object(mapping["runtime"])
    assert module["architecture"] == architecture.value
    assert mapping["rva"] == rva
    assert mapping["match_basis"] in {"path", "name"}
    assert static["address"] == static_address
    assert runtime["address"] == runtime_address


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(("variable", "architecture"), _CASES)
def test_service_real_static_runtime_address_sync(
    variable: str,
    architecture: Architecture,
) -> None:
    fixture = _configured_fixture(variable, architecture)
    service = AnalysisService(Settings.load())
    session_id = _session_id(_service_data(service.create_session(str(fixture))))

    try:
        static_open = _service_data(service.open_static(session_id))
        dynamic_open = _service_data(service.open_dynamic(session_id))
        static_backend = _object(static_open["backend"])
        dynamic_backend = _object(dynamic_open["backend"])
        assert dynamic_backend["architecture"] == architecture.value

        launched = _service_data(
            service.dynamic_launch(session_id, arguments="--debug-wait", timeout=30.0)
        )
        assert _object(launched["state"])["state"] == "paused"

        module_result = _service_data(service.dynamic_modules(session_id))
        runtime_module = _main_module(module_result, fixture)
        static_base = int(static_backend["image_base"])
        runtime_base = int(runtime_module["base"])
        module_size = int(runtime_module["size"])
        entry_rva = _entry_rva(fixture)
        assert entry_rva < module_size
        assert runtime_base != static_base, "fixture was not relocated by ASLR"

        static_address = static_base + entry_rva
        runtime_address = runtime_base + entry_rva
        to_runtime = _service_data(
            service.sync_static_to_runtime(session_id, static_address)
        )
        _assert_round_trip(
            to_runtime,
            architecture=architecture,
            static_address=static_address,
            runtime_address=runtime_address,
            rva=entry_rva,
        )
        assert to_runtime["source"] == "static"
        assert to_runtime["target"] == "runtime"

        to_static = _service_data(
            service.sync_runtime_to_static(session_id, runtime_address)
        )
        _assert_round_trip(
            to_static,
            architecture=architecture,
            static_address=static_address,
            runtime_address=runtime_address,
            rva=entry_rva,
        )
        assert to_static["source"] == "runtime"
        assert to_static["target"] == "static"

        out_of_range = service.sync_runtime_to_static(
            session_id,
            runtime_base + module_size,
        )
        assert not out_of_range.ok and out_of_range.error is not None
        assert out_of_range.error.code == "address_out_of_range"
        assert out_of_range.error.details["backend"] == "x64dbg"

        stopped = _service_data(service.dynamic_stop(session_id, timeout=30.0))
        assert _object(stopped["state"])["state"] == "idle"

        event_fixture = fixture.with_name("event_fixture.dll")
        assert event_fixture.is_file()
        preferred_base, image_size = _preferred_image_layout(event_fixture)
        expected_sha256 = sha256(event_fixture.read_bytes()).hexdigest()
        lifecycle_launch = _service_data(
            service.dynamic_launch(
                session_id,
                arguments="--module-lifecycle-windows",
                timeout=30.0,
            )
        )
        assert _object(lifecycle_launch["state"])["state"] == "paused"
        initial_catalog = _service_data(service.module_catalog(session_id))
        assert _matching_module(initial_catalog, event_fixture) is None

        loaded_catalog = _service_pause_after_module_event(
            service,
            session_id,
            event_fixture,
            kind="module.loaded",
        )
        loaded_module = _matching_module(loaded_catalog, event_fixture)
        assert loaded_module is not None
        runtime_base = int(loaded_module["base"])
        assert int(loaded_module["size"]) == image_size
        assert runtime_base != preferred_base, "event fixture was not relocated by ASLR"

        selector_cases = (
            (
                ModuleSelector(
                    name=event_fixture.name.upper(),
                    sha256=expected_sha256.upper(),
                ),
                "name",
            ),
            (ModuleSelector(path=str(event_fixture.resolve())), "path"),
            (ModuleSelector(base=runtime_base), "base"),
        )
        for selector, match_basis in selector_cases:
            resolved = _service_data(service.module_resolve(session_id, selector))
            _assert_resolved_module(
                resolved,
                architecture=architecture,
                module_path=event_fixture,
                runtime_module=loaded_module,
                preferred_base=preferred_base,
                image_size=image_size,
                expected_sha256=expected_sha256,
                match_basis=match_basis,
            )

        module_rva = _entry_rva(event_fixture)
        assert module_rva < image_size
        module_to_runtime = _service_data(
            service.sync_module_preferred_to_runtime(
                session_id,
                ModuleSelector(path=str(event_fixture.resolve())),
                preferred_base + module_rva,
            )
        )
        module_to_preferred = _service_data(
            service.sync_module_runtime_to_preferred(
                session_id,
                ModuleSelector(name=event_fixture.name),
                runtime_base + module_rva,
            )
        )
        _assert_rebased_round_trip(
            module_to_runtime,
            module_to_preferred,
            preferred_base=preferred_base,
            runtime_base=runtime_base,
            rva=module_rva,
        )

        wrong_hash = service.module_resolve(
            session_id,
            ModuleSelector(name=event_fixture.name, sha256="0" * 64),
        )
        assert not wrong_hash.ok and wrong_hash.error is not None
        assert wrong_hash.error.code == "module_identity_mismatch"
        assert wrong_hash.error.details["actual"] == expected_sha256
        out_of_range_module = service.sync_module_preferred_to_runtime(
            session_id,
            ModuleSelector(base=runtime_base),
            preferred_base + image_size,
        )
        assert not out_of_range_module.ok and out_of_range_module.error is not None
        assert out_of_range_module.error.code == "address_out_of_range"

        unloaded_catalog = _service_pause_after_module_event(
            service,
            session_id,
            event_fixture,
            kind="module.unloaded",
            runtime_base=runtime_base,
        )
        assert _matching_module(unloaded_catalog, event_fixture) is None
        for selector, _ in selector_cases:
            stale = service.module_resolve(session_id, selector)
            assert not stale.ok and stale.error is not None
            assert stale.error.code == "module_not_found"

        lifecycle_exit = _service_resume_until_idle(service, session_id)
        assert _object(lifecycle_exit["state"])["state"] == "idle"
    finally:
        closed = service.close_session(session_id)
        assert closed.ok, closed.model_dump(mode="json")


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
@pytest.mark.parametrize(("variable", "architecture"), _CASES)
async def test_mcp_stdio_real_static_runtime_address_sync(
    variable: str,
    architecture: Architecture,
) -> None:
    fixture = _configured_fixture(variable, architecture)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=os.environ.copy(),
        cwd=_PROJECT_ROOT,
    )

    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        tools = await client.list_tools()
        tool_names = {tool.name for tool in tools.tools}
        assert tool_names >= _ADDRESS_TOOLS
        assert "dynamic.command" not in tool_names

        missing_backend_session = _session_id(
            await _mcp_call(client, "session.create", {"binary": str(fixture)})
        )
        try:
            missing_backend = _structured(
                await client.call_tool(
                    "sync.static_to_runtime",
                    {"session_id": missing_backend_session, "address": 0},
                )
            )
            assert missing_backend["ok"] is False
            missing_error = _object(missing_backend["error"])
            assert missing_error["code"] == "backend_unavailable"
            assert _object(missing_error["details"])["backend"] == "ida"
        finally:
            await _mcp_call(
                client,
                "session.close",
                {"session_id": missing_backend_session},
            )

        session_id = _session_id(
            await _mcp_call(client, "session.create", {"binary": str(fixture)})
        )
        try:
            static_open = await _mcp_call(
                client,
                "static.open",
                {"session_id": session_id},
            )
            await _mcp_call(client, "dynamic.open", {"session_id": session_id})
            await _mcp_call(
                client,
                "dynamic.launch",
                {
                    "session_id": session_id,
                    "arguments": "--debug-wait",
                    "timeout": 30.0,
                },
            )
            module_result = await _mcp_call(
                client,
                "dynamic.modules",
                {"session_id": session_id},
            )

            static_base = int(_object(static_open["backend"])["image_base"])
            runtime_module = _main_module(module_result, fixture)
            runtime_base = int(runtime_module["base"])
            module_size = int(runtime_module["size"])
            entry_rva = _entry_rva(fixture)
            static_address = static_base + entry_rva
            runtime_address = runtime_base + entry_rva

            to_runtime = await _mcp_call(
                client,
                "sync.static_to_runtime",
                {"session_id": session_id, "address": static_address},
            )
            _assert_round_trip(
                to_runtime,
                architecture=architecture,
                static_address=static_address,
                runtime_address=runtime_address,
                rva=entry_rva,
            )
            to_static = await _mcp_call(
                client,
                "sync.runtime_to_static",
                {"session_id": session_id, "address": runtime_address},
            )
            _assert_round_trip(
                to_static,
                architecture=architecture,
                static_address=static_address,
                runtime_address=runtime_address,
                rva=entry_rva,
            )

            out_of_range = _structured(
                await client.call_tool(
                    "sync.runtime_to_static",
                    {
                        "session_id": session_id,
                        "address": runtime_base + module_size,
                    },
                )
            )
            assert out_of_range["ok"] is False
            assert _object(out_of_range["error"])["code"] == "address_out_of_range"

            stopped = await _mcp_call(
                client,
                "dynamic.stop",
                {"session_id": session_id, "timeout": 30.0},
            )
            assert _object(stopped["state"])["state"] == "idle"

            event_fixture = fixture.with_name("event_fixture.dll")
            assert event_fixture.is_file()
            preferred_base, image_size = _preferred_image_layout(event_fixture)
            expected_sha256 = sha256(event_fixture.read_bytes()).hexdigest()
            lifecycle_launch = await _mcp_call(
                client,
                "dynamic.launch",
                {
                    "session_id": session_id,
                    "arguments": "--module-lifecycle-windows",
                    "timeout": 30.0,
                },
            )
            assert _object(lifecycle_launch["state"])["state"] == "paused"
            initial_catalog = await _mcp_call(
                client,
                "modules.list",
                {"session_id": session_id},
            )
            assert _matching_module(initial_catalog, event_fixture) is None

            loaded_catalog = await _mcp_pause_after_module_event(
                client,
                session_id,
                event_fixture,
                kind="module.loaded",
            )
            loaded_module = _matching_module(loaded_catalog, event_fixture)
            assert loaded_module is not None
            assert set(loaded_module) == {"base", "size", "name", "path"}
            runtime_base = int(loaded_module["base"])
            assert int(loaded_module["size"]) == image_size
            assert runtime_base != preferred_base, "event fixture was not relocated by ASLR"

            selector_cases: tuple[tuple[JsonObject, str], ...] = (
                (
                    {
                        "name": event_fixture.name.upper(),
                        "sha256": expected_sha256.upper(),
                    },
                    "name",
                ),
                ({"path": str(event_fixture.resolve())}, "path"),
                ({"base": runtime_base}, "base"),
            )
            for selector, match_basis in selector_cases:
                resolved = await _mcp_call(
                    client,
                    "modules.resolve",
                    {"session_id": session_id, "selector": selector},
                )
                _assert_resolved_module(
                    resolved,
                    architecture=architecture,
                    module_path=event_fixture,
                    runtime_module=loaded_module,
                    preferred_base=preferred_base,
                    image_size=image_size,
                    expected_sha256=expected_sha256,
                    match_basis=match_basis,
                )

            module_rva = _entry_rva(event_fixture)
            module_to_runtime = await _mcp_call(
                client,
                "sync.module_preferred_to_runtime",
                {
                    "session_id": session_id,
                    "selector": {"path": str(event_fixture.resolve())},
                    "address": preferred_base + module_rva,
                },
            )
            module_to_preferred = await _mcp_call(
                client,
                "sync.module_runtime_to_preferred",
                {
                    "session_id": session_id,
                    "selector": {"name": event_fixture.name},
                    "address": runtime_base + module_rva,
                },
            )
            _assert_rebased_round_trip(
                module_to_runtime,
                module_to_preferred,
                preferred_base=preferred_base,
                runtime_base=runtime_base,
                rva=module_rva,
            )

            wrong_hash = await _mcp_failure(
                client,
                "modules.resolve",
                {
                    "session_id": session_id,
                    "selector": {
                        "name": event_fixture.name,
                        "sha256": "0" * 64,
                    },
                },
            )
            assert wrong_hash["code"] == "module_identity_mismatch"
            assert _object(wrong_hash["details"])["actual"] == expected_sha256
            out_of_range_module = await _mcp_failure(
                client,
                "sync.module_runtime_to_preferred",
                {
                    "session_id": session_id,
                    "selector": {"base": runtime_base},
                    "address": runtime_base + image_size,
                },
            )
            assert out_of_range_module["code"] == "address_out_of_range"

            unloaded_catalog = await _mcp_pause_after_module_event(
                client,
                session_id,
                event_fixture,
                kind="module.unloaded",
                runtime_base=runtime_base,
            )
            assert _matching_module(unloaded_catalog, event_fixture) is None
            for selector, _ in selector_cases:
                stale = await _mcp_failure(
                    client,
                    "modules.resolve",
                    {"session_id": session_id, "selector": selector},
                )
                assert stale["code"] == "module_not_found"

            lifecycle_exit = await _mcp_resume_until_idle(client, session_id)
            assert _object(lifecycle_exit["state"])["state"] == "idle"
        finally:
            closed = await _mcp_call(
                client,
                "session.close",
                {"session_id": session_id},
            )
            assert _object(closed["session"])["state"] == "closed"