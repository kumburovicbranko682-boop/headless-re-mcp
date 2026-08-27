"""Branch coverage for the webcrack (JS) and wabt (WASM) subprocess backends.

Both are optional user-provided CLIs: a missing tool degrades to
capability_unavailable, oversized or unreadable input is refused before the
child launches, a non-module is rejected on the \\0asm magic, and a tool that
exits non-zero yet still emits output is flagged rather than silently trusted.
These fakes drive the guard, listing, and degradation branches without Node or
wabt; the live gate (tests/integration/test_web_re_gate.py) pins the real
tools.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    WasmClient,
    _capped_file_listing,
    _looks_like_wasm,
    _require_existing_file,
    _resolve_wabt_tool,
    _run,
)

MP = pytest.MonkeyPatch
_EXE = Path(sys.executable)
_WASM = b"\x00asm\x01\x00\x00\x00"


def _install(monkeypatch: MP, handler: Any) -> list[list[str]]:
    calls: list[list[str]] = []

    def _fake(cmd: list[str], *, timeout: float, creationflags: int = 0) -> Completed:
        calls.append(list(cmd))
        return handler(list(cmd))

    monkeypatch.setattr(jsre_client, "run_bounded", _fake)
    return calls


class TestHelpers:
    def test_listing_missing_root(self, tmp_path: Path) -> None:
        assert _capped_file_listing(tmp_path / "nope", cap=10) == ([], 0, False)

    def test_listing_skips_directories(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.js").write_text("x")
        names, total, has_more = _capped_file_listing(tmp_path, cap=10)
        assert names == ["a.js"]
        assert total == 1
        assert has_more is False

    def test_listing_cap_flags_has_more(self, tmp_path: Path) -> None:
        for i in range(4):
            (tmp_path / f"f{i}.js").write_text("x")
        names, total, has_more = _capped_file_listing(tmp_path, cap=2)
        assert len(names) == 2
        assert total == 4
        assert has_more is True

    def test_listing_counted_cap_stops_the_walk(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(jsre_client, "_MAX_COUNTED_FILES", 1)
        (tmp_path / "a.js").write_text("x")
        (tmp_path / "b.js").write_text("x")
        names, total, has_more = _capped_file_listing(tmp_path, cap=10)
        assert total == 1
        assert has_more is True

    def test_require_existing_file_reports_missing(self, tmp_path: Path) -> None:
        with pytest.raises(JsReError) as excinfo:
            _require_existing_file(tmp_path / "gone.js", missing="input file not found")
        assert excinfo.value.code == "not_found"

    def test_require_existing_file_rejects_oversized(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(jsre_client, "_MAX_INPUT_BYTES", 4)
        big = tmp_path / "big.js"
        big.write_bytes(b"x" * 32)
        with pytest.raises(JsReError) as excinfo:
            _require_existing_file(big, missing="input file not found")
        assert excinfo.value.code == "too_large"

    def test_require_existing_file_wraps_a_stat_error(
        self, tmp_path: Path, monkeypatch: MP
    ) -> None:
        target = tmp_path / "weird.js"
        target.write_text("x")
        real_stat = Path.stat

        def _fake_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
            # is_file() stats too and must still succeed; only the explicit size
            # read inside _require_existing_file blows up, so key off the caller.
            caller = sys._getframe(1).f_code.co_name
            if self == target and caller == "_require_existing_file":
                raise OSError("stat blew up")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _fake_stat)
        with pytest.raises(JsReError) as excinfo:
            _require_existing_file(target, missing="input file not found")
        assert excinfo.value.code == "backend_error"

    def test_looks_like_wasm_true_and_false(self, tmp_path: Path) -> None:
        good = tmp_path / "m.wasm"
        good.write_bytes(_WASM)
        bad = tmp_path / "n.wasm"
        bad.write_bytes(b"not wasm")
        assert _looks_like_wasm(good) is True
        assert _looks_like_wasm(bad) is False

    def test_looks_like_wasm_swallows_oserror(self, tmp_path: Path) -> None:
        # A directory cannot be opened as a file; treat it as "not wasm".
        (tmp_path / "dir").mkdir()
        assert _looks_like_wasm(tmp_path / "dir") is False

    def test_run_maps_a_timeout(self, monkeypatch: MP) -> None:
        def _boom(_cmd: list[str]) -> Completed:
            raise TimedOut(3.0, killed=[11])

        _install(monkeypatch, _boom)
        with pytest.raises(JsReError) as excinfo:
            _run(["webcrack", "x.js"], timeout=30)
        assert excinfo.value.code == "timeout"
        assert excinfo.value.details.get("killed_pids") == [11]

    def test_run_maps_a_launch_oserror(self, monkeypatch: MP) -> None:
        def _boom(_cmd: list[str]) -> Completed:
            raise FileNotFoundError("missing node")

        _install(monkeypatch, _boom)
        with pytest.raises(JsReError) as excinfo:
            _run(["webcrack", "x.js"], timeout=30)
        assert excinfo.value.code == "backend_error"

    def test_run_rejects_a_bad_timeout(self, monkeypatch: MP) -> None:
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"", stderr=b""))
        with pytest.raises(JsReError) as excinfo:
            _run(["webcrack", "x.js"], timeout=-1)
        assert excinfo.value.code == "invalid_params"


class TestAvailability:
    def test_js_available_reflects_executable(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(jsre_client, "_discover_webcrack", lambda: None)
        assert JsClient(executable=None).available is False
        assert JsClient(executable=_EXE).available is True

    def test_wasm_available_reflects_wasm2wat(self) -> None:
        client = WasmClient()
        client._wasm2wat = None
        assert client.available is False
        client._wasm2wat = _EXE
        assert client.available is True


class TestJsClient:
    def test_deobfuscate_needs_webcrack(self, tmp_path: Path) -> None:
        src = tmp_path / "a.js"
        src.write_text("var a=1")
        with pytest.raises(JsReError) as excinfo:
            JsClient(executable=None).deobfuscate(src)
        assert excinfo.value.code == "capability_unavailable"

    def test_deobfuscate_returns_bounded_code(self, tmp_path: Path, monkeypatch: MP) -> None:
        src = tmp_path / "a.js"
        src.write_text("var a=1")
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"clean();", stderr=b""))
        out = JsClient(executable=_EXE).deobfuscate(src)
        assert out["code"] == "clean();"
        assert out["truncated"] is False
        assert out["bytes"] == len(b"clean();")

    def test_deobfuscate_fails_hard_with_no_output(self, tmp_path: Path, monkeypatch: MP) -> None:
        src = tmp_path / "a.js"
        src.write_text("var a=1")
        _install(monkeypatch, lambda cmd: Completed(returncode=2, stdout=b"", stderr=b"boom"))
        with pytest.raises(JsReError) as excinfo:
            JsClient(executable=_EXE).deobfuscate(src)
        assert excinfo.value.code == "backend_error"

    def test_deobfuscate_flags_a_partial_run(self, tmp_path: Path, monkeypatch: MP) -> None:
        src = tmp_path / "a.js"
        src.write_text("var a=1")
        _install(
            monkeypatch,
            lambda cmd: Completed(returncode=1, stdout=b"partial();", stderr=b"one class failed"),
        )
        out = JsClient(executable=_EXE).beautify(src)  # beautify routes to deobfuscate
        assert out["code"] == "partial();"
        assert out["tool_failed"] is True
        assert out["exit_code"] == 1

    def test_unpack_bundle_lists_and_paginates(self, tmp_path: Path, monkeypatch: MP) -> None:
        src = tmp_path / "bundle.js"
        src.write_text("var a=1")
        out_dir = tmp_path / "unpacked"

        def _handler(cmd: list[str]) -> Completed:
            out_dir.mkdir(parents=True, exist_ok=True)
            for i in range(3):
                (out_dir / f"mod{i}.js").write_text("x")
            return Completed(returncode=0, stdout=b"", stderr=b"")

        _install(monkeypatch, _handler)
        out = JsClient(executable=_EXE).unpack_bundle(src, out_dir, offset=1, limit=1)
        assert out["file_count"] == 3
        assert out["count"] == 1
        assert out["offset"] == 1
        assert out["has_more"] is True

    def test_unpack_bundle_fails_hard_when_empty(self, tmp_path: Path, monkeypatch: MP) -> None:
        src = tmp_path / "bundle.js"
        src.write_text("var a=1")
        out_dir = tmp_path / "unpacked"
        _install(monkeypatch, lambda cmd: Completed(returncode=1, stdout=b"", stderr=b"nope"))
        with pytest.raises(JsReError) as excinfo:
            JsClient(executable=_EXE).unpack_bundle(src, out_dir)
        assert excinfo.value.code == "backend_error"


def _wasm_client(monkeypatch: MP) -> WasmClient:
    client = WasmClient()
    client._wasm2wat = _EXE
    client._objdump = _EXE
    return client


class TestWasmClient:
    def test_wat_needs_the_tool(self, tmp_path: Path) -> None:
        wasm = tmp_path / "m.wasm"
        wasm.write_bytes(_WASM)
        client = WasmClient()
        client._wasm2wat = None
        with pytest.raises(JsReError) as excinfo:
            client.wat(wasm)
        assert excinfo.value.code == "capability_unavailable"

    def test_wat_rejects_a_non_module(self, tmp_path: Path, monkeypatch: MP) -> None:
        notwasm = tmp_path / "x.wasm"
        notwasm.write_bytes(b"MZ not a module")
        client = _wasm_client(monkeypatch)
        with pytest.raises(JsReError) as excinfo:
            client.wat(notwasm)
        assert excinfo.value.code == "invalid_params"

    def test_wat_returns_bounded_text(self, tmp_path: Path, monkeypatch: MP) -> None:
        wasm = tmp_path / "m.wasm"
        wasm.write_bytes(_WASM)
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"(module)", stderr=b""))
        out = _wasm_client(monkeypatch).wat(wasm)
        assert out["wat"] == "(module)"
        assert out["bytes"] == len(b"(module)")

    def test_wat_fails_hard_with_no_output(self, tmp_path: Path, monkeypatch: MP) -> None:
        wasm = tmp_path / "m.wasm"
        wasm.write_bytes(_WASM)
        _install(monkeypatch, lambda cmd: Completed(returncode=1, stdout=b"", stderr=b"bad"))
        with pytest.raises(JsReError) as excinfo:
            _wasm_client(monkeypatch).wat(wasm)
        assert excinfo.value.code == "backend_error"

    def test_info_returns_objdump_text(self, tmp_path: Path, monkeypatch: MP) -> None:
        wasm = tmp_path / "m.wasm"
        wasm.write_bytes(_WASM)
        _install(monkeypatch, lambda cmd: Completed(returncode=0, stdout=b"Sections:", stderr=b""))
        out = _wasm_client(monkeypatch).info(wasm)
        assert out["objdump"] == "Sections:"
        assert "bytes" not in out  # info omits the byte count

    def test_info_fails_hard_with_no_output(self, tmp_path: Path, monkeypatch: MP) -> None:
        wasm = tmp_path / "m.wasm"
        wasm.write_bytes(_WASM)
        _install(monkeypatch, lambda cmd: Completed(returncode=3, stdout=b"", stderr=b"broken"))
        with pytest.raises(JsReError) as excinfo:
            _wasm_client(monkeypatch).info(wasm)
        assert excinfo.value.code == "backend_error"


class TestResolveWabtTool:
    def test_direct_tool_path(self, tmp_path: Path) -> None:
        tool = tmp_path / "wasm2wat"
        tool.write_text("#!/bin/sh")
        assert _resolve_wabt_tool(tool, "wasm2wat") == tool

    def test_bin_subdir_path(self, tmp_path: Path) -> None:
        (tmp_path / "bin").mkdir()
        tool = tmp_path / "bin" / "wasm2wat"
        tool.write_text("#!/bin/sh")
        assert _resolve_wabt_tool(tmp_path, "wasm2wat") == tool

    def test_falls_back_to_path(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(
            jsre_client.shutil,
            "which",
            lambda name: "/usr/bin/wasm-objdump" if name == "wasm-objdump" else None,
        )
        assert _resolve_wabt_tool(None, "wasm-objdump") == Path("/usr/bin/wasm-objdump")

    def test_dir_without_the_tool_falls_through(self, tmp_path: Path, monkeypatch: MP) -> None:
        # wabt points at a dir with neither <tool> nor bin/<tool>; the lookup
        # must fall through to PATH rather than returning a non-file.
        monkeypatch.setattr(jsre_client.shutil, "which", lambda name: None)
        assert _resolve_wabt_tool(tmp_path, "wasm2wat") is None

    def test_returns_none_when_absent(self, monkeypatch: MP) -> None:
        monkeypatch.setattr(jsre_client.shutil, "which", lambda name: None)
        assert _resolve_wabt_tool(None, "wasm2wat") is None
