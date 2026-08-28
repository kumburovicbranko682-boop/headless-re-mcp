"""js/wasm client guard paths refuse bad inputs and dead tools precisely.

The webcrack and wabt adapters promise specific error codes before and after
the subprocess runs: a missing input is ``not_found``, an unstatable one is
``backend_error`` (not silently accepted), a timed-out child maps to
``timeout`` with the killed PIDs, a launch failure to ``backend_error``, and
a tool that exited non-zero without producing anything raises rather than
returning an empty success. These lock in those contracts plus the bounded
directory listing's edges (missing root, non-file entries, the name cap) and
wabt tool resolution through a ``bin/`` directory.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    _capped_file_listing,
    _looks_like_wasm,
    _require_existing_file,
    _resolve_wabt_tool,
)

_RUN_BOUNDED = "headless_re_mcp.backends.jsre.client.run_bounded"

# _resolve_wabt_tool looks for "<tool>.exe" on Windows, so the fake wabt
# binaries must carry the platform suffix or resolution returns None there.
_EXE = ".exe" if os.name == "nt" else ""


def _js_client(tmp_path: Path) -> tuple[JsClient, Path]:
    tool = tmp_path / "webcrack"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    script = tmp_path / "input.js"
    script.write_text("var a = 1;", encoding="utf-8")
    return JsClient(tool), script


def _wasm_client(tmp_path: Path) -> tuple[WasmClient, Path]:
    wabt = tmp_path / "wabt"
    wabt.mkdir()
    (wabt / f"wasm2wat{_EXE}").write_text("#!/bin/sh\n", encoding="utf-8")
    (wabt / f"wasm-objdump{_EXE}").write_text("#!/bin/sh\n", encoding="utf-8")
    module = tmp_path / "module.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return WasmClient(wabt), module


def test_listing_a_missing_root_is_empty(tmp_path: Path) -> None:
    names, total, has_more = _capped_file_listing(tmp_path / "absent", cap=10)

    assert names == []
    assert total == 0
    assert has_more is False


def test_listing_counts_files_but_not_directories(tmp_path: Path) -> None:
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "module.js").write_text("x", encoding="utf-8")

    names, total, has_more = _capped_file_listing(tmp_path, cap=10)

    assert names == [str(Path("sub", "module.js"))]
    assert total == 1
    assert has_more is False


def test_listing_keeps_counting_past_the_name_cap(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"chunk{index}.js").write_text("x", encoding="utf-8")

    names, total, has_more = _capped_file_listing(tmp_path, cap=2)

    assert len(names) == 2
    assert total == 3
    assert has_more is True


def test_a_missing_input_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        _require_existing_file(tmp_path / "ghost.js", missing="input file not found")

    assert caught.value.code == "not_found"
    assert caught.value.details["path"] == str(tmp_path / "ghost.js")


def test_an_unresolvable_user_path_is_invalid_params(tmp_path: Path) -> None:
    # "~unknownuser" has no home to expand to, so Path.expanduser() raises a
    # bare RuntimeError. The chokepoint must report that as a parameter mistake
    # rather than let it escape as an unexpected internal error, the same way
    # the missing/oversized cases below answer with a JsReError.
    with pytest.raises(JsReError) as caught:
        _require_existing_file(
            Path("~nosuchuser_xyz/app.js"), missing="input file not found"
        )

    assert caught.value.code == "invalid_params"
    assert caught.value.details["path"] == "~nosuchuser_xyz/app.js"


def test_an_unstatable_input_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # is_file says yes but stat then fails: the file must be refused loudly,
    # not passed to the child with an unknown size.
    monkeypatch.setattr(Path, "is_file", lambda self, **kwargs: True)

    with pytest.raises(JsReError) as caught:
        _require_existing_file(tmp_path / "ghost.js", missing="input file not found")

    assert caught.value.code == "backend_error"
    assert "input unreadable" in caught.value.message


def test_an_unreadable_file_does_not_look_like_wasm(tmp_path: Path) -> None:
    assert _looks_like_wasm(tmp_path / "ghost.wasm") is False


def test_a_timed_out_tool_maps_to_timeout_with_killed_pids(tmp_path: Path) -> None:
    client, script = _js_client(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(9.0, killed=[321])

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JsReError) as caught:
        client.deobfuscate(script, timeout=9.0)

    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [321]


def test_a_launch_failure_maps_to_backend_error(tmp_path: Path) -> None:
    client, script = _js_client(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("exec format error")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JsReError) as caught:
        client.deobfuscate(script)

    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


def test_unpack_that_failed_and_wrote_nothing_raises(tmp_path: Path) -> None:
    client, script = _js_client(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(3, b"", b"unpack fell over")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JsReError) as caught:
        client.unpack_bundle(script, tmp_path / "out")

    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 3
    assert caught.value.details["stderr"] == "unpack fell over"


def test_wat_that_failed_with_no_output_raises(tmp_path: Path) -> None:
    client, module = _wasm_client(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"", b"bad section")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JsReError) as caught:
        client.wat(module)

    assert caught.value.code == "backend_error"
    assert "wasm2wat failed" in caught.value.message


def test_info_that_failed_with_no_output_raises(tmp_path: Path) -> None:
    client, module = _wasm_client(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(2, b"", b"objdump broke")

    with patch(_RUN_BOUNDED, fake_run), pytest.raises(JsReError) as caught:
        client.info(module)

    assert caught.value.code == "backend_error"
    assert "wasm-objdump failed" in caught.value.message


def test_wabt_tool_resolves_through_a_bin_directory(tmp_path: Path) -> None:
    wabt = tmp_path / "wabt"
    (wabt / "bin").mkdir(parents=True)
    tool = wabt / "bin" / f"wasm2wat{_EXE}"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")

    assert _resolve_wabt_tool(wabt, "wasm2wat") == tool


def test_wabt_pointing_at_the_binary_itself_is_accepted(tmp_path: Path) -> None:
    tool = tmp_path / "wasm2wat"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")

    assert _resolve_wabt_tool(tool, "wasm2wat") == tool


def test_wabt_resolution_falls_back_to_path_and_may_find_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)

    assert _resolve_wabt_tool(tmp_path / "empty", "wasm2wat") is None
