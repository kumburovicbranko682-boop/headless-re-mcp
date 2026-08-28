"""Residual paths of the JS/WASM service mixin and the jsre client.

Covers the prune helpers' OSError arcs, each mixin method's success and
unexpected-exception envelopes, the client's input guards, the _run error
mapping, tool-failure raises, and the wabt bin/ fallback.
"""

from __future__ import annotations

import os
from pathlib import Path, PosixPath
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

import headless_re_mcp.backends.jsre.client as jsre_client
import headless_re_mcp.core.service_jsre as service_jsre
from headless_re_mcp.backends.common.bounded_run import TimedOut
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
from headless_re_mcp.core.service_jsre import JsReAnalysisMixin, prune_jsre_unpack_dirs


class _Harness(JsReAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, webcrack=None, wabt=None)


class _SecondStatFails(PosixPath):
    """stat succeeds once (the is_dir/is_file probe) then fails; a file that
    vanished between the listing and the sort takes exactly this shape."""

    _calls: ClassVar[dict[str, int]] = {}

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        if "poison" in self.name:
            count = self._calls.get(str(self), 0) + 1
            self._calls[str(self)] = count
            if count > 1:
                raise OSError("stat lost a race")
        return super().stat(follow_symlinks=follow_symlinks)


# ------------------------------------------------- prune_jsre_unpack_dirs


def test_prune_survives_an_unlistable_root(tmp_path: Path) -> None:
    prune_jsre_unpack_dirs(tmp_path / "never-created", keep=1)


def test_prune_treats_an_unstatable_tree_as_oldest(tmp_path: Path) -> None:
    root = tmp_path / "jsre"
    root.mkdir()
    (root / "unpack-poison").mkdir()
    survivor = root / "unpack-survivor"
    survivor.mkdir()
    os.utime(survivor, (2_000_000_000, 2_000_000_000))
    _SecondStatFails._calls.clear()

    prune_jsre_unpack_dirs(_SecondStatFails(root), keep=1)

    assert not (root / "unpack-poison").exists()
    assert survivor.is_dir()


# ------------------------------------------------------ mixin envelopes


def _stub_client(method: str, outcome: Any) -> type:
    class _Stub:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    def call(self: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    setattr(_Stub, method, call)
    return _Stub


_MIXIN_CASES = [
    ("js_deobfuscate", "JsClient", "deobfuscate", {"code": "clean"}),
    ("js_beautify", "JsClient", "beautify", {"code": "pretty"}),
    ("wasm_wat", "WasmClient", "wat", {"wat": "(module)"}),
    ("wasm_info", "WasmClient", "info", {"objdump": "sections"}),
]


@pytest.mark.parametrize(("service_method", "client_name", "client_method", "data"), _MIXIN_CASES)
def test_each_mixin_method_wraps_client_data_in_a_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service_method: str,
    client_name: str,
    client_method: str,
    data: dict[str, Any],
) -> None:
    monkeypatch.setattr(service_jsre, client_name, _stub_client(client_method, data))
    harness = _Harness(tmp_path)

    result = getattr(harness, service_method)(str(tmp_path / "input.bin"))

    assert result.ok is True and result.data is not None
    for key, value in data.items():
        assert result.data[key] == value


@pytest.mark.parametrize(("service_method", "client_name", "client_method", "data"), _MIXIN_CASES)
def test_each_mixin_method_wraps_an_unexpected_error_in_a_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service_method: str,
    client_name: str,
    client_method: str,
    data: dict[str, Any],
) -> None:
    del data
    monkeypatch.setattr(service_jsre, client_name, _stub_client(client_method, ValueError("boom")))
    harness = _Harness(tmp_path)

    result = getattr(harness, service_method)(str(tmp_path / "input.bin"))

    assert result.ok is False and result.error is not None


@pytest.mark.parametrize(("service_method", "client_name", "client_method", "data"), _MIXIN_CASES)
def test_each_mixin_method_keeps_a_jsre_error_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    service_method: str,
    client_name: str,
    client_method: str,
    data: dict[str, Any],
) -> None:
    del data
    error = JsReError("capability_unavailable", "tool is not configured")
    monkeypatch.setattr(service_jsre, client_name, _stub_client(client_method, error))
    harness = _Harness(tmp_path)

    result = getattr(harness, service_method)(str(tmp_path / "input.bin"))

    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_unpack_bundle_keeps_a_jsre_error_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = JsReError("too_large", "input exceeds the tool limit")
    monkeypatch.setattr(service_jsre, "JsClient", _stub_client("unpack_bundle", error))
    harness = _Harness(tmp_path)

    result = harness.js_unpack_bundle(str(tmp_path / "bundle.js"))

    assert result.ok is False and result.error is not None
    assert result.error.code == "too_large"


def test_unpack_bundle_wraps_an_unexpected_error_and_still_prunes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_jsre, "JsClient", _stub_client("unpack_bundle", ValueError("boom")))
    harness = _Harness(tmp_path)

    result = harness.js_unpack_bundle(str(tmp_path / "bundle.js"))

    assert result.ok is False and result.error is not None
    assert (tmp_path / "jsre").is_dir()


# ------------------------------------------------------- client helpers


def test_capped_listing_of_a_missing_root_is_empty(tmp_path: Path) -> None:
    assert _capped_file_listing(tmp_path / "absent", cap=10) == ([], 0, False)


def test_capped_listing_skips_directories_and_flags_the_cut(tmp_path: Path) -> None:
    root = tmp_path / "out"
    (root / "nested").mkdir(parents=True)
    (root / "a.js").write_text("x", encoding="utf-8")
    (root / "nested" / "b.js").write_text("x", encoding="utf-8")

    names, total, has_more = _capped_file_listing(root, cap=1)

    assert len(names) == 1
    assert total == 2
    assert has_more is True


def test_require_existing_file_rejects_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as exc:
        _require_existing_file(tmp_path / "absent.js", missing="input file not found")

    assert exc.value.code == "not_found"


def test_require_existing_file_maps_a_stat_race_to_backend_error(tmp_path: Path) -> None:
    target = tmp_path / "poison.js"
    target.write_text("x", encoding="utf-8")
    _SecondStatFails._calls.clear()

    with pytest.raises(JsReError) as exc:
        _require_existing_file(_SecondStatFails(target), missing="input file not found")

    assert exc.value.code == "backend_error"
    assert "unreadable" in exc.value.message


def test_an_unreadable_file_does_not_look_like_wasm(tmp_path: Path) -> None:
    class _UnopenablePath(PosixPath):
        def open(self, *args: Any, **kwargs: Any) -> Any:
            raise OSError("permission denied")

    target = tmp_path / "module.wasm"
    target.write_bytes(b"\x00asm\x01\x00\x00\x00")

    assert _looks_like_wasm(_UnopenablePath(target)) is False


def test_run_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(JsReError) as exc:
        _run(["tool"], timeout=0)

    assert exc.value.code == "invalid_params"


def test_run_maps_a_timeout_to_a_structured_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timing_out(cmd: list[str], **_kwargs: Any) -> Any:
        raise TimedOut(1.0, [123])

    monkeypatch.setattr(jsre_client, "run_bounded", timing_out)

    with pytest.raises(JsReError) as exc:
        _run(["tool"], timeout=1.0)

    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [123]


def test_run_maps_a_launch_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unlaunchable(cmd: list[str], **_kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(jsre_client, "run_bounded", unlaunchable)

    with pytest.raises(JsReError) as exc:
        _run(["tool"], timeout=1.0)

    assert exc.value.code == "backend_error"
    assert "failed to launch" in exc.value.message


# ----------------------------------------------------- tool-failed raises


def test_unpack_that_fails_without_files_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_run", lambda cmd, **kwargs: ("", "webcrack blew up", 1))
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")

    with pytest.raises(JsReError) as exc:
        JsClient(executable=Path("/bin/true")).unpack_bundle(bundle, tmp_path / "out")

    assert exc.value.code == "backend_error"
    assert "unpack failed" in exc.value.message


def _wabt_dir(tmp_path: Path) -> Path:
    wabt = tmp_path / "wabt"
    wabt.mkdir()
    (wabt / "wasm2wat").write_text("#!/bin/sh\n", encoding="utf-8")
    (wabt / "wasm-objdump").write_text("#!/bin/sh\n", encoding="utf-8")
    return wabt


def _wasm_module(tmp_path: Path) -> Path:
    module = tmp_path / "module.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return module


def test_wat_that_fails_without_output_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_run", lambda cmd, **kwargs: ("", "bad module", 1))
    client = WasmClient(_wabt_dir(tmp_path))

    with pytest.raises(JsReError) as exc:
        client.wat(_wasm_module(tmp_path))

    assert exc.value.code == "backend_error"
    assert "wasm2wat failed" in exc.value.message


def test_info_that_fails_without_output_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_run", lambda cmd, **kwargs: ("", "bad module", 1))
    client = WasmClient(_wabt_dir(tmp_path))

    with pytest.raises(JsReError) as exc:
        client.info(_wasm_module(tmp_path))

    assert exc.value.code == "backend_error"
    assert "wasm-objdump failed" in exc.value.message


# -------------------------------------------------------- wabt discovery


def test_wabt_root_falls_back_to_its_bin_directory(tmp_path: Path) -> None:
    wabt = tmp_path / "wabt"
    (wabt / "bin").mkdir(parents=True)
    tool = wabt / "bin" / "wasm2wat"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")

    assert _resolve_wabt_tool(wabt, "wasm2wat") == tool
