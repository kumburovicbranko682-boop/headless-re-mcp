"""The jsre subprocess wrapper and its failure mapping, pinned tool-free.

``JsClient``/``WasmClient`` shell out to webcrack and wabt. The input guard and
the unpack listing/paging are pinned elsewhere; these tests close the rest of
the wrapper without either CLI installed: the shared ``_run`` maps a deadline to
``timeout`` and a launch failure to ``backend_error`` (never a raw OSError), a
non-zero exit with no usable output becomes ``backend_error`` for each of
deobfuscate/unpack/wat/info, the capped file listing tolerates a non-directory
and skips sub-directories, and wabt discovery finds a tool under ``bin/``.

Every launch is mocked, so these run everywhere the integration gates skip.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.backends.jsre.client as jsre
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    _capped_file_listing,
    _resolve_wabt_tool,
)

# --- _run: deadline, launch failure, and stream decoding --------------------


def test_run_maps_a_deadline_to_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TimedOut from the launcher carries the deadline and the killed pids.

    webcrack runs node as a child, so the killed tree is worth surfacing: an
    unattended pass can see exactly what the deadline had to stop.
    """

    def _timeout(cmd: list[str], *, timeout: float, creationflags: int = 0) -> object:
        raise jsre.TimedOut(timeout, [4321])

    monkeypatch.setattr(jsre, "run_bounded", _timeout)
    with pytest.raises(JsReError) as caught:
        jsre._run(["webcrack", "app.js"], timeout=5.0)
    assert caught.value.code == "timeout"
    assert caught.value.details["timeout"] == 5.0
    assert caught.value.details["killed_pids"] == [4321]


def test_run_maps_a_launch_failure_to_backend_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing/unexecutable binary is backend_error, not a raw OSError."""

    def _oserror(cmd: list[str], *, timeout: float, creationflags: int = 0) -> object:
        raise OSError("no such file")

    monkeypatch.setattr(jsre, "run_bounded", _oserror)
    with pytest.raises(JsReError) as caught:
        jsre._run(["webcrack", "app.js"], timeout=5.0)
    assert caught.value.code == "backend_error"
    assert "failed to launch webcrack" in caught.value.message


def test_run_decodes_streams_and_replaces_bad_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """stdout/stderr are decoded as UTF-8 with replacement, never raising."""
    completed = SimpleNamespace(stdout=b"out\xff", stderr=b"warn", returncode=3)

    def _ok(cmd: list[str], *, timeout: float, creationflags: int = 0) -> object:
        return completed

    monkeypatch.setattr(jsre, "run_bounded", _ok)
    stdout, stderr, code = jsre._run(["webcrack"], timeout=5.0)
    assert stdout == "out\ufffd"
    assert stderr == "warn"
    assert code == 3


# --- non-zero exit with no usable output -> backend_error -------------------


def _fake_run(monkeypatch: pytest.MonkeyPatch, stdout: str, stderr: str, code: int) -> None:
    def _run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        del cmd, timeout
        return stdout, stderr, code

    monkeypatch.setattr(jsre, "_run", _run)


def test_deobfuscate_raises_on_a_failed_exit_with_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_run(monkeypatch, "", "SyntaxError: boom", 1)
    src = tmp_path / "app.js"
    src.write_text("nope", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError) as caught:
        client.deobfuscate(src)
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1
    assert "SyntaxError" in caught.value.details["stderr"]


def test_deobfuscate_returns_output_even_when_the_exit_is_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """webcrack can warn (non-zero) yet still emit usable code; keep it."""
    _fake_run(monkeypatch, "var x = 1;", "a warning", 1)
    src = tmp_path / "app.js"
    src.write_text("nope", encoding="utf-8")
    result = JsClient(executable=Path("/bin/true")).deobfuscate(src)
    assert result["code"] == "var x = 1;"
    assert result["truncated"] is False
    assert result["bytes"] == len(b"var x = 1;")


def test_unpack_bundle_raises_when_it_fails_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_run(monkeypatch, "", "cannot parse", 2)
    src = tmp_path / "app.js"
    src.write_text("nope", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError) as caught:
        client.unpack_bundle(src, tmp_path / "out")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2


def _wasm_client(tmp_path: Path) -> WasmClient:
    client = WasmClient()
    client._wasm2wat = tmp_path / "wasm2wat"
    client._objdump = tmp_path / "wasm-objdump"
    return client


def test_wat_raises_on_a_failed_exit_with_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_run(monkeypatch, "", "not a wasm file", 1)
    wasm = tmp_path / "mod.wasm"
    wasm.write_bytes(b"\x00asm")
    with pytest.raises(JsReError) as caught:
        _wasm_client(tmp_path).wat(wasm)
    assert caught.value.code == "backend_error"
    assert "wasm2wat failed" in caught.value.message


def test_info_raises_on_a_failed_exit_with_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_run(monkeypatch, "", "bad magic", 1)
    wasm = tmp_path / "mod.wasm"
    wasm.write_bytes(b"\x00asm")
    with pytest.raises(JsReError) as caught:
        _wasm_client(tmp_path).info(wasm)
    assert caught.value.code == "backend_error"
    assert "wasm-objdump failed" in caught.value.message


# --- capability degradation and availability --------------------------------


def test_jsclient_without_webcrack_is_unavailable_and_degrades(tmp_path: Path) -> None:
    client = JsClient(executable=None)
    assert client.available is False
    with pytest.raises(JsReError) as caught:
        client.deobfuscate(tmp_path / "app.js")
    assert caught.value.code == "capability_unavailable"


def test_wasmclient_without_wabt_is_unavailable_and_degrades(tmp_path: Path) -> None:
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    assert client.available is False
    with pytest.raises(JsReError) as caught:
        client.wat(tmp_path / "mod.wasm")
    assert caught.value.code == "capability_unavailable"


# --- _capped_file_listing edges ---------------------------------------------


def test_capped_listing_of_a_missing_root_is_empty(tmp_path: Path) -> None:
    assert _capped_file_listing(tmp_path / "gone", cap=10) == ([], 0, False)


def test_capped_listing_skips_subdirectories_and_marks_overflow(tmp_path: Path) -> None:
    """Only files are named; a cap smaller than the count reports has_more."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.js").write_text("x", encoding="utf-8")
    for index in range(5):
        (tmp_path / f"mod-{index}.js").write_text("x", encoding="utf-8")

    names, total, has_more = _capped_file_listing(tmp_path, cap=2)
    assert len(names) == 2
    assert total == 6  # five top-level + one nested file, directories excluded
    assert has_more is True
    assert not any(name == "sub" for name in names)


# --- wabt discovery ---------------------------------------------------------


def test_resolve_wabt_tool_finds_a_tool_under_bin(tmp_path: Path) -> None:
    """A wabt install dir resolves its tools from the bin/ subdirectory."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / ("wasm2wat" + (".exe" if os.name == "nt" else ""))
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    assert _resolve_wabt_tool(tmp_path, "wasm2wat") == exe


def test_resolve_wabt_tool_accepts_a_direct_tool_path(tmp_path: Path) -> None:
    """Pointing wabt straight at the tool binary is honoured as-is."""
    exe = tmp_path / ("wasm2wat" + (".exe" if os.name == "nt" else ""))
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    assert _resolve_wabt_tool(exe, "wasm2wat") == exe
