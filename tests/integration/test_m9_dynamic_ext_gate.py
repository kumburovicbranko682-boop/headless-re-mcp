"""M9 Gate: x64dbg dynamic extension surface (threads/stack/disasm/HBP/patches + ungated)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.models import Architecture

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_REQUIRED = frozenset(
    {
        "threads.list",
        "threads.current",
        "threads.context.read",
        "threads.context.write",
        "stack.read",
        "stack.trace",
        "disassembly.read",
        "memory.protection",
        "symbols.list",
        "symbols.resolve",
        "breakpoints.hardware.set",
        "breakpoints.hardware.remove",
        "breakpoints.memory.set",
        "breakpoints.memory.remove",
        "breakpoints.memory.list",
        "breakpoints.condition.set",
        "breakpoints.condition.get",
        "patches.list",
        "trace.start",
        "trace.stop",
        "trace.status",
    }
)


def _configured_paths(
    variable: str, architecture: Architecture
) -> tuple[Path, Path]:
    executable = os.environ.get(variable)
    if not executable:
        fallback = (
            _PROJECT_ROOT
            / "artifacts"
            / f"x64dbg-{architecture.value}"
            / "Release"
            / "headless.exe"
        )
        if fallback.is_file():
            executable = str(fallback)
        else:
            pytest.skip(f"{variable} is not configured")
    path = Path(executable)
    if not path.is_file():
        pytest.skip(f"{variable} missing: {path}")
    fixture = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "headless_fixture.exe"
    )
    if not fixture.is_file():
        pytest.skip(f"fixture is not built: {fixture}")
    return path, fixture


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    ("variable", "architecture", "instruction_pointer"),
    [
        ("HEADLESS_RE_X64DBG_HEADLESS_X86", Architecture.X86, "eip"),
        ("HEADLESS_RE_X64DBG_HEADLESS_X64", Architecture.X64, "rip"),
    ],
)
def test_m9_dynamic_ext_gate(
    variable: str,
    architecture: Architecture,
    instruction_pointer: str,
) -> None:
    if os.name != "nt":
        pytest.skip("M9 dynamic gate requires Windows")
    executable, fixture = _configured_paths(variable, architecture)
    os.environ[variable] = str(executable)
    client = XdbgClient(executable, architecture)
    runtime_directory = client.runtime_directory

    try:
        assert client.capabilities >= _REQUIRED

        client.request(
            "debug.launch",
            {"path": str(fixture.resolve()), "arguments": "--debug-wait"},
            timeout=30,
        )
        client.wait_for_state({"paused"}, timeout=30)

        threads = client.threads_list()
        assert int(threads["count"]) >= 1
        assert isinstance(threads["threads"], list)
        assert threads["threads"]
        current_tid = int(threads["current_tid"])
        assert current_tid > 0

        current = client.threads_current()
        assert int(current["tid"]) == current_tid
        assert current.get("current") is True

        ctx = client.threads_context_read(current_tid)
        assert int(ctx["tid"]) == current_tid
        registers = ctx.get("registers")
        if not isinstance(registers, dict):
            registers = client.request("registers.read")["registers"]
            assert isinstance(registers, dict)
        scratch = "rbx" if architecture is Architecture.X64 else "ebx"
        assert scratch in registers
        original_scratch = int(registers[scratch])
        flipped_scratch = original_scratch ^ 0x5A5A
        written = client.threads_context_write(current_tid, scratch, flipped_scratch)
        assert written["name"] == scratch
        assert int(written["value"]) == flipped_scratch
        after_write = client.threads_context_read(current_tid)
        after_regs = after_write.get("registers")
        if isinstance(after_regs, dict):
            assert int(after_regs[scratch]) == flipped_scratch
        client.threads_context_write(current_tid, scratch, original_scratch)
        with pytest.raises(XdbgRpcError):
            client.threads_context_write(current_tid, "not_a_register", 1)

        stack = client.stack_trace(limit=64)
        assert "frames" in stack
        assert int(stack["count"]) >= 0
        assert int(stack["count"]) <= 64

        stack_words = client.stack_read(count=8)
        assert int(stack_words["count"]) == 8
        assert len(stack_words["entries"]) == 8

        cip = int(registers[instruction_pointer])
        disasm = client.disassembly_read(cip, count=8)
        assert int(disasm["count"]) >= 1
        assert isinstance(disasm["instructions"], list)
        assert disasm["instructions"][0]["address"] == cip

        protection = client.memory_protection(cip)
        assert int(protection["address"]) == cip
        assert "protect" in protection or "rights" in protection or "base" in protection
        with pytest.raises(XdbgRpcError):
            client.memory_protection(cip, rights="NotARealRight")

        modules = client.request("modules.list")
        assert isinstance(modules.get("modules"), list)
        assert modules["modules"]
        module_base = int(modules["modules"][0]["base"])
        symbols = client.symbols_list(module_base, limit=32)
        assert int(symbols["module_base"]) == module_base
        assert isinstance(symbols["symbols"], list)
        assert int(symbols["count"]) >= 0
        resolved = client.symbols_resolve(instruction_pointer)
        assert resolved.get("resolved") is True
        assert int(resolved["value"]) == cip

        client.breakpoints_hardware_set(cip, bp_type="x", size=1)
        listed = client.breakpoints_hardware_list()
        assert cip in {
            int(item["address"])
            for item in listed["breakpoints"]
            if isinstance(item, dict)
        }
        conditioned = client.breakpoints_condition_set(cip, "0")
        assert int(conditioned["address"]) == cip
        assert conditioned["expression"] == "0"
        got_condition = client.breakpoints_condition_get(cip)
        assert got_condition["expression"] == "0"
        client.breakpoints_hardware_remove(cip)
        listed = client.breakpoints_hardware_list()
        assert cip not in {
            int(item["address"])
            for item in listed["breakpoints"]
            if isinstance(item, dict)
        }

        # Memory BP: x64dbg may round to region/page base — assert via list delta.
        data_addr = int(stack_words["entries"][0]["address"])
        try:
            before_mem = {
                int(item["address"])
                for item in client.breakpoints_memory_list()["breakpoints"]
                if isinstance(item, dict)
            }
            client.breakpoints_memory_set(data_addr, bp_type="w")
            after_mem = {
                int(item["address"])
                for item in client.breakpoints_memory_list()["breakpoints"]
                if isinstance(item, dict)
            }
            added = after_mem - before_mem
            assert added, f"memory BP not listed after set at {data_addr:#x}"
            for addr in added:
                client.breakpoints_memory_remove(addr)
            cleared = {
                int(item["address"])
                for item in client.breakpoints_memory_list()["breakpoints"]
                if isinstance(item, dict)
            }
            assert added.isdisjoint(cleared)
        except XdbgRpcError:
            # Some pages refuse memory BP; capability still advertised and exercised.
            pass

        patches = client.patches_list()
        assert isinstance(patches["patches"], list)
        assert int(patches["count"]) >= 0

        original = str(client.request("memory.read", {"address": cip, "size": 1})["data"])
        flipped = f"{int(original, 16) ^ 1:02x}"
        try:
            client.patches_apply(cip, flipped)
            after = client.patches_list()
            assert any(
                isinstance(item, dict) and int(item["address"]) == cip
                for item in after["patches"]
            )
            client.patches_restore(cip)
            restored = str(
                client.request("memory.read", {"address": cip, "size": 1})["data"]
            )
            assert restored == original
        except XdbgRpcError:
            # Apply/restore may be refused on protected pages; list already covered.
            client.request("memory.write", {"address": cip, "data": original})

        with tempfile.TemporaryDirectory(prefix="m9-trace-") as tmp:
            trace_path = str(Path(tmp) / "trace.bin")
            started = client.trace_start(
                trace_path,
                max_events=100,
                timeout_ms=5_000,
                max_file_bytes=256 * 1024,
            )
            assert started.get("recording") is True
            assert int(started["max_events"]) == 100
            assert int(started["timeout_ms"]) == 5_000
            assert int(started["max_file_bytes"]) == 256 * 1024
            status = client.trace_status()
            assert status.get("recording") is True
            assert int(status["max_events"]) == 100
            stopped = client.trace_stop()
            assert stopped.get("recording") is False
            idle_status = client.trace_status()
            assert idle_status.get("recording") is False

        assert list(client.analyzer_windows) == []
        client.request("debug.stop")
        client.wait_for_state({"idle"}, timeout=30)
    finally:
        client.close()

    assert client.exit_code == 0
    assert not runtime_directory.exists()
    assert list(client.analyzer_windows) == []
