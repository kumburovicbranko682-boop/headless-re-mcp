"""wasm.wat must disassemble post-MVP modules, not just the MVP subset.

wasm2wat gates every proposal after the MVP off by default, so a module using
tail calls / SIMD / reference types / bulk memory / exceptions / threads / GC
dies with "unexpected opcode" and the whole conversion is reported failed --
even though the module is valid and a modern toolchain routinely emits those
features. The fix passes ``--enable-all``.

Two checks: a mock guard that the flag is on the wasm2wat argv (runs anywhere,
so a regression that drops it is caught even without wabt), and a live gate
that runs the real wasm2wat on an embedded tail-call module. The live gate only
asserts when this wabt actually gates the feature -- if the installed wasm2wat
enables tail calls by default it proves nothing, so it skips with a reason
(skip != pass).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre.client import WasmClient

# A 33-byte module with two functions where the second does `return_call 0`
# (tail call, opcode 0x12). Built with `wat2wasm --enable-all`; wasm2wat rejects
# it by default with "unexpected opcode: 0x12".
_TAIL_CALL_WASM = bytes.fromhex(
    "0061736d010000000105016000017f03030200000a0b02040041010b040012000b"
)


def test_wat_passes_enable_all_to_wasm2wat(tmp_path: Path) -> None:
    """The wasm2wat argv must carry --enable-all before the module path."""
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        seen.append(list(cmd))
        return Completed(0, b"(module)", b"")

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        WasmClient(tool).wat(module)

    assert seen, "wasm2wat was never launched"
    argv = seen[0]
    assert "--enable-all" in argv
    # Flag precedes the positional module path, the form wabt documents.
    assert argv.index("--enable-all") < argv.index(str(module))


def test_wat_disassembles_a_real_tail_call_module(tmp_path: Path) -> None:
    """Live: the real wasm2wat converts a tail-call module through wat()."""
    wasm2wat = shutil.which("wasm2wat")
    if wasm2wat is None:
        pytest.skip("wasm2wat (wabt) not installed; cannot run the live gate")

    module = tmp_path / "tailcall.wasm"
    module.write_bytes(_TAIL_CALL_WASM)

    # Only meaningful if this wabt actually gates the feature. If the default
    # already accepts it, the module cannot demonstrate that --enable-all is
    # what unblocks post-MVP input, so there is nothing to prove here.
    default = subprocess.run(
        [wasm2wat, str(module), "-o", "-"],
        capture_output=True,
        timeout=30,
    )
    if default.returncode == 0:
        pytest.skip("this wasm2wat enables tail calls by default; feature gate not observable")

    payload = WasmClient(Path(wasm2wat)).wat(module)
    assert "return_call" in payload["wat"]
    assert payload.get("tool_failed") is not True
