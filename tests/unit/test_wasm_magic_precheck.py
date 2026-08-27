"""wasm.wat / wasm.info must refuse a non-module before launching wabt.

The tool docstrings promise that a file without the ``\\0asm`` magic is
refused as invalid_params "rather than handed to wabt", and the apktool zip
precheck names this magic check as the model it copies -- yet only the
too_large half of _require_input was ever exercised behaviorally. A regression
that dropped _looks_like_wasm would hand garbage to wasm2wat / wasm-objdump
and surface as a backend_error after paying the subprocess cost, breaking the
documented contract with no test noticing. These pin the behaviour with
run_bounded stubbed, so "the subprocess launched" is observable and no wabt
install is needed: a non-module is invalid_params with the tool never
launched, an oversized non-module is still too_large (the ordering the
_require_input comment documents), and a real module passes through.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient


def _recording_run(launched: list[list[str]]) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        launched.append(list(cmd))
        return Completed(0, b"(module)", b"")

    return fake_run


@pytest.mark.parametrize(
    "raw",
    [
        b"",  # empty file: passes the size cap, must still fail the magic
        b"\x00as",  # truncated magic
        b"asm\x01\x00\x00\x00",  # right bytes, wrong order
        b"MZ\x90\x00\x03\x00\x00\x00",  # a PE handed to the wrong tool
        b"var x = 1;\n",  # a JS source mistaken for its compiled module
    ],
)
def test_wat_refuses_a_non_module_before_wasm2wat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    launched: list[list[str]] = []
    monkeypatch.setattr(jsre_client, "run_bounded", _recording_run(launched))

    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(raw)

    with pytest.raises(JsReError) as caught:
        WasmClient(tool).wat(module)
    assert caught.value.code == "invalid_params"
    assert "WebAssembly" in caught.value.message
    assert caught.value.details.get("path") == str(module)
    assert launched == [], "wasm2wat must never see a file that failed the magic check"


def test_info_takes_the_same_magic_precheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """info resolves a different tool (wasm-objdump) but shares _require_input;
    exercising it separately catches a refactor that inlines the check into wat
    only."""
    launched: list[list[str]] = []
    monkeypatch.setattr(jsre_client, "run_bounded", _recording_run(launched))

    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"not wasm at all")

    with pytest.raises(JsReError) as caught:
        WasmClient(tool).info(module)
    assert caught.value.code == "invalid_params"
    assert launched == []


def test_an_oversized_non_module_is_too_large_not_bad_magic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_require_input documents that the size cap runs before the magic check,
    so an oversized garbage file reads as "too big" rather than "bad magic" --
    the actionable half of that diagnosis (truncate or split the input) comes
    first. A reorder would silently flip the reported code."""
    monkeypatch.setattr(jsre_client, "_MAX_INPUT_BYTES", 1024)
    launched: list[list[str]] = []
    monkeypatch.setattr(jsre_client, "run_bounded", _recording_run(launched))

    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = tmp_path / "m.wasm"
    module.write_bytes(b"x" * 2048)

    with pytest.raises(JsReError) as caught:
        WasmClient(tool).wat(module)
    assert caught.value.code == "too_large"
    assert launched == []


def test_a_real_module_passes_the_precheck_and_reaches_wabt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the precheck pattern: a well-formed module must not be
    refused. Both tools get the resolved file path on their command line."""
    launched: list[list[str]] = []
    monkeypatch.setattr(jsre_client, "run_bounded", _recording_run(launched))

    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    wat_tool = tmp_path / "wasm2wat.exe"
    wat_tool.write_bytes(b"")
    payload = WasmClient(wat_tool).wat(module)
    assert payload["wat"] == "(module)"

    info_tool = tmp_path / "wasm-objdump.exe"
    info_tool.write_bytes(b"")
    WasmClient(info_tool).info(module)

    assert len(launched) == 2
    for cmd in launched:
        assert str(module) in cmd
