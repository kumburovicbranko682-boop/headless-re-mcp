"""Listing, input-guard, and failure arms of the webcrack/wabt (JS+WASM) client.

The non-zero-exit surfacing already lives in ``test_jsre_nonzero_exit.py`` and
the unpack pagination in ``test_jsre_unpack_dirs.py``. This file covers what
they skip: the ``_capped_file_listing`` edges, the missing-input and wasm-magic
guards, the ``_run`` timeout/launch mapping, the backend_error arms of
unpack/wat/info, and wabt tool discovery via a ``bin/`` subdirectory. A stubbed
``run_bounded`` stands in for node/wabt so no real tool runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jsre import client as jsre_mod
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    _capped_file_listing,
    _looks_like_wasm,
    _require_existing_file,
    _resolve_wabt_tool,
)


def _executable(path: Path) -> Path:
    path.write_bytes(b"")
    return path


# ---------------------------------------------------------------------------
# _capped_file_listing
# ---------------------------------------------------------------------------


def test_capped_listing_returns_empty_for_a_missing_root(tmp_path: Path) -> None:
    assert _capped_file_listing(tmp_path / "nope", cap=10) == ([], 0, False)


def test_capped_listing_skips_subdirectories(tmp_path: Path) -> None:
    root = tmp_path / "out"
    root.mkdir()
    (root / "sub").mkdir()
    (root / "f.txt").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(root, cap=10)
    assert names == ["f.txt"]
    assert total == 1
    assert has_more is False


def test_capped_listing_flags_more_over_the_display_cap(tmp_path: Path) -> None:
    root = tmp_path / "out"
    root.mkdir()
    for index in range(3):
        (root / f"f{index}.js").write_text("x", encoding="utf-8")
    names, total, has_more = _capped_file_listing(root, cap=2)
    assert len(names) == 2
    assert total == 3
    assert has_more is True


# ---------------------------------------------------------------------------
# _require_existing_file / _looks_like_wasm
# ---------------------------------------------------------------------------


def test_require_existing_file_reports_a_missing_input(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as raised:
        _require_existing_file(tmp_path / "missing.js", missing="input file not found")
    assert raised.value.code == "not_found"


def test_require_existing_file_refuses_an_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(jsre_mod, "_MAX_INPUT_BYTES", 4)
    big = tmp_path / "big.js"
    big.write_bytes(b"0123456789")
    with pytest.raises(JsReError) as raised:
        _require_existing_file(big, missing="input file not found")
    assert raised.value.code == "too_large"
    assert raised.value.details["max_file_size"] == 4


def test_looks_like_wasm_is_false_when_the_path_cannot_be_read(tmp_path: Path) -> None:
    # A directory raises on open("rb"); that is "not wasm", not a crash.
    assert _looks_like_wasm(tmp_path) is False


def test_looks_like_wasm_matches_the_magic(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert _looks_like_wasm(module) is True


# ---------------------------------------------------------------------------
# _run
# ---------------------------------------------------------------------------


def test_run_maps_a_timeout(monkeypatch: Any) -> None:
    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [321])

    monkeypatch.setattr(jsre_mod, "run_bounded", boom)
    with pytest.raises(JsReError) as raised:
        jsre_mod._run(["/opt/webcrack", "x"], timeout=5.0)
    assert raised.value.code == "timeout"
    assert raised.value.details["killed_pids"] == [321]


def test_run_maps_a_launch_failure(monkeypatch: Any) -> None:
    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("node missing")

    monkeypatch.setattr(jsre_mod, "run_bounded", boom)
    with pytest.raises(JsReError) as raised:
        jsre_mod._run(["/opt/webcrack", "x"], timeout=5.0)
    assert raised.value.code == "backend_error"


def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(JsReError) as raised:
        jsre_mod._run(["/opt/webcrack"], timeout=-1)
    assert raised.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# unpack_bundle / wat / info backend_error arms
# ---------------------------------------------------------------------------


def test_unpack_bundle_raises_when_nothing_was_written(
    tmp_path: Path, monkeypatch: Any
) -> None:
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    out = tmp_path / "out"

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(2, b"", b"unpack aborted")

    monkeypatch.setattr(jsre_mod, "run_bounded", fake_run)
    client = JsClient(_executable(tmp_path / "webcrack.exe"))
    with pytest.raises(JsReError) as raised:
        client.unpack_bundle(src, out)
    assert raised.value.code == "backend_error"
    assert raised.value.details["exit_code"] == 2


def test_wat_raises_when_nonzero_and_nothing_printed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"error: bad module")

    monkeypatch.setattr(jsre_mod, "run_bounded", fake_run)
    client = WasmClient(_executable(tmp_path / "wasm2wat.exe"))
    with pytest.raises(JsReError) as raised:
        client.wat(module)
    assert raised.value.code == "backend_error"


def test_info_raises_when_nonzero_and_nothing_printed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"error: bad section")

    monkeypatch.setattr(jsre_mod, "run_bounded", fake_run)
    client = WasmClient(_executable(tmp_path / "wasm-objdump.exe"))
    with pytest.raises(JsReError) as raised:
        client.info(module)
    assert raised.value.code == "backend_error"


# ---------------------------------------------------------------------------
# _resolve_wabt_tool
# ---------------------------------------------------------------------------


def test_resolve_wabt_tool_finds_the_binary_in_a_bin_subdir(tmp_path: Path) -> None:
    wabt = tmp_path / "wabt"
    (wabt / "bin").mkdir(parents=True)
    exe = wabt / "bin" / "wasm2wat"
    exe.write_bytes(b"")
    assert _resolve_wabt_tool(wabt, "wasm2wat") == exe


def test_resolve_wabt_tool_accepts_a_direct_tool_path(tmp_path: Path) -> None:
    direct = tmp_path / "wasm2wat"
    direct.write_bytes(b"")
    assert _resolve_wabt_tool(direct, "wasm2wat") == direct


# ---------------------------------------------------------------------------
# JsReError
# ---------------------------------------------------------------------------


def test_jsre_error_is_a_runtime_error_carrying_code_and_details() -> None:
    err = JsReError("too_large", "big", size=99)
    assert isinstance(err, RuntimeError)
    assert err.code == "too_large"
    assert err.details["size"] == 99
