"""jsre paths the nonzero-exit and unpack-dir suites do not reach.

Those suites pin the "return what we got" surfacing and the unpack listing; here
the focus is the shared input guard (missing/unreadable/size), the wasm magic
read guard, ``_run``'s invalid-timeout/timeout/launch mapping, the
capability_unavailable and backend_error branches on each command, and webcrack
/ wabt discovery. ``run_bounded`` and ``shutil.which`` are faked so no Node or
wabt install is needed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    _capped_file_listing,
    _discover_webcrack,
    _looks_like_wasm,
    _require_existing_file,
    _resolve_wabt_tool,
    _run,
)

_RUN = "headless_re_mcp.backends.jsre.client.run_bounded"


def _wasm(path: Path) -> Path:
    path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return path


# ---------------------------------------------------------------------------
# _capped_file_listing
# ---------------------------------------------------------------------------
def test_capped_file_listing_handles_a_missing_root(tmp_path: Path) -> None:
    assert _capped_file_listing(tmp_path / "nope", cap=10) == ([], 0, False)


def test_capped_file_listing_skips_dirs_and_flags_has_more(tmp_path: Path) -> None:
    for i in range(3):
        (tmp_path / f"f{i}.js").write_text("x", encoding="utf-8")
    (tmp_path / "subdir").mkdir()  # a directory is not a file -> skipped
    names, total, has_more = _capped_file_listing(tmp_path, cap=1)
    assert total == 3
    assert len(names) == 1
    assert has_more is True


# ---------------------------------------------------------------------------
# _require_existing_file
# ---------------------------------------------------------------------------
def test_require_existing_file_missing_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        _require_existing_file(tmp_path / "ghost", missing="input file not found")
    assert caught.value.code == "not_found"


def test_require_existing_file_unreadable_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.js"
    target.write_text("x", encoding="utf-8")
    monkeypatch.setattr(Path, "is_file", lambda self: True)

    def _boom(self: Path, *a: Any, **k: Any) -> Any:
        raise OSError("stat failed")

    monkeypatch.setattr(Path, "stat", _boom)
    with pytest.raises(JsReError) as caught:
        _require_existing_file(target, missing="input file not found")
    assert caught.value.code == "backend_error"


def test_require_existing_file_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_INPUT_BYTES", 4)
    target = tmp_path / "big.js"
    target.write_bytes(b"abcdefgh")
    with pytest.raises(JsReError) as caught:
        _require_existing_file(target, missing="input file not found")
    assert caught.value.code == "too_large"
    assert caught.value.details["size"] == 8


# ---------------------------------------------------------------------------
# _looks_like_wasm
# ---------------------------------------------------------------------------
def test_looks_like_wasm_tolerates_a_read_error(tmp_path: Path) -> None:
    # A path that cannot be opened (a directory) reads as "not wasm", not a crash.
    assert _looks_like_wasm(tmp_path) is False


def test_looks_like_wasm_matches_the_magic(tmp_path: Path) -> None:
    assert _looks_like_wasm(_wasm(tmp_path / "m.wasm")) is True
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not wasm")
    assert _looks_like_wasm(plain) is False


# ---------------------------------------------------------------------------
# _run
# ---------------------------------------------------------------------------
def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(JsReError) as caught:
        _run(["webcrack"], timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_maps_timeout_with_killed_pids() -> None:
    def _boom(*_a: Any, **_k: Any) -> Completed:
        raise TimedOut(7.0, [99])

    with patch(_RUN, _boom), pytest.raises(JsReError) as caught:
        _run(["webcrack"], timeout=10)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [99]


def test_run_maps_oserror_to_backend_error() -> None:
    def _boom(*_a: Any, **_k: Any) -> Completed:
        raise OSError("ENOENT")

    with patch(_RUN, _boom), pytest.raises(JsReError) as caught:
        _run(["webcrack"], timeout=10)
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# JsClient capability + backend_error
# ---------------------------------------------------------------------------
def test_js_client_unconfigured_is_capability_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_discover_webcrack", lambda: None)
    client = JsClient(None)
    assert client.available is False
    with pytest.raises(JsReError) as caught:
        client.deobfuscate(tmp_path / "app.js")
    assert caught.value.code == "capability_unavailable"


def test_unpack_bundle_backend_error_when_nothing_written(tmp_path: Path) -> None:
    tool = tmp_path / "webcrack.exe"
    tool.write_bytes(b"")
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(2, b"", b"unpack failed before writing anything")

    with patch(_RUN, fake_run), pytest.raises(JsReError) as caught:
        JsClient(tool).unpack_bundle(src, out)
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2


# ---------------------------------------------------------------------------
# WasmClient capability + backend_error
# ---------------------------------------------------------------------------
def test_wasm_client_unconfigured_is_capability_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client.shutil, "which", lambda name: None)
    client = WasmClient(None)
    assert client.available is False
    module = _wasm(tmp_path / "m.wasm")
    with pytest.raises(JsReError) as wat_caught:
        client.wat(module)
    assert wat_caught.value.code == "capability_unavailable"
    with pytest.raises(JsReError) as info_caught:
        client.info(module)
    assert info_caught.value.code == "capability_unavailable"


def test_wasm_wat_backend_error_when_no_output(tmp_path: Path) -> None:
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    module = _wasm(tmp_path / "m.wasm")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"error: bad module")

    with patch(_RUN, fake_run), pytest.raises(JsReError) as caught:
        WasmClient(tool).wat(module)
    assert caught.value.code == "backend_error"


def test_wasm_info_backend_error_when_no_output(tmp_path: Path) -> None:
    tool = tmp_path / "wasm-objdump.exe"
    tool.write_bytes(b"")
    module = _wasm(tmp_path / "m.wasm")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"error: bad module")

    with patch(_RUN, fake_run), pytest.raises(JsReError) as caught:
        WasmClient(tool).info(module)
    assert caught.value.code == "backend_error"


def test_wasm_input_rejects_a_non_module(tmp_path: Path) -> None:
    tool = tmp_path / "wasm2wat.exe"
    tool.write_bytes(b"")
    plain = tmp_path / "not.wasm"
    plain.write_bytes(b"MZ not a module")
    with pytest.raises(JsReError) as caught:
        WasmClient(tool).wat(plain)
    assert caught.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
def test_discover_webcrack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client.shutil, "which", lambda name: "/usr/bin/webcrack")
    assert _discover_webcrack() == Path("/usr/bin/webcrack")
    monkeypatch.setattr(jsre_client.shutil, "which", lambda name: None)
    assert _discover_webcrack() is None


def test_resolve_wabt_tool_direct_file(tmp_path: Path) -> None:
    direct = tmp_path / "wasm2wat"
    direct.write_text("x", encoding="utf-8")
    assert _resolve_wabt_tool(direct, "wasm2wat") == direct


def test_resolve_wabt_tool_bin_directory(tmp_path: Path) -> None:
    wabt = tmp_path / "wabt"
    (wabt / "bin").mkdir(parents=True)
    exe = "wasm2wat" + (".exe" if os.name == "nt" else "")
    tool = wabt / "bin" / exe
    tool.write_text("x", encoding="utf-8")
    assert _resolve_wabt_tool(wabt, "wasm2wat") == tool


def test_resolve_wabt_tool_path_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client.shutil, "which", lambda name: "/opt/wabt/wasm2wat")
    assert _resolve_wabt_tool(None, "wasm2wat") == Path("/opt/wabt/wasm2wat")
    monkeypatch.setattr(jsre_client.shutil, "which", lambda name: None)
    assert _resolve_wabt_tool(None, "wasm2wat") is None
