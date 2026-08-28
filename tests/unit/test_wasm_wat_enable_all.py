"""wasm.wat must ask wasm2wat to accept every WebAssembly feature.

wasm2wat parses MVP plus a few on-by-default proposals and rejects anything
using an off-by-default feature (tail-call, threads/atomics, exception
handling, GC, memory64, ...) with a non-zero exit and no output — which the
backend turned into ``backend_error``. Real modern modules use these
constantly (emscripten pthreads ships shared memory; C++ exceptions compile to
the EH proposal), so a disassembler that refuses them is failing at its one
job. The fix passes ``--enable-all`` to wasm2wat. wasm-objdump has no such
flag and already tolerates these features, so ``info`` must NOT carry it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre.client import WasmClient

_WASM = b"\x00asm\x01\x00\x00\x00"


def _capture_cmd(tmp_path: Path, method: str) -> list[str]:
    module = tmp_path / "m.wasm"
    module.write_bytes(_WASM)
    tool = tmp_path / ("wasm2wat.exe" if method == "wat" else "wasm-objdump.exe")
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    seen: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        seen["cmd"] = list(cmd)
        return Completed(stdout=b"(module)", stderr=b"", returncode=0)

    with patch("headless_re_mcp.backends.jsre.client.run_bounded", fake_run):
        client = WasmClient(tool)
        getattr(client, method)(module)
    return seen["cmd"]


def test_wat_enables_all_features(tmp_path: Path) -> None:
    cmd = _capture_cmd(tmp_path, "wat")
    assert "--enable-all" in cmd, cmd


def test_info_does_not_pass_enable_all(tmp_path: Path) -> None:
    """wasm-objdump rejects --enable-all outright, so info must never send it."""
    cmd = _capture_cmd(tmp_path, "info")
    assert "--enable-all" not in cmd, cmd
