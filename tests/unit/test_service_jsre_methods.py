"""JS/WASM static-analysis service methods and unpack-dir retention.

Each method forwards one JsClient/WasmClient call and maps JsReError -> failure;
``js.unpack_bundle`` also caps the on-disk unpack area. The tests drive that
surface with fake clients plus direct exercises of ``prune_jsre_unpack_dirs``,
so success, error mapping, and the retention sweeps run without the Node/wabt
toolchain.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_jsre
from headless_re_mcp.core.service_jsre import (
    JsReAnalysisMixin,
    prune_jsre_unpack_dirs,
)

JsonObject = dict[str, Any]


class _FakeJs:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def deobfuscate(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return {"op": "deobfuscate", "path": str(path)}

    def beautify(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return {"op": "beautify", "path": str(path)}

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "chunk.js").write_text("//chunk", encoding="utf-8")
        return {"files": ["chunk.js"], "out": str(out_dir), "offset": offset, "limit": limit}


class _FakeWasm:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def wat(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return {"wat": "(module)", "path": str(path)}

    def info(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return {"sections": [], "path": str(path)}


class _Host(JsReAnalysisMixin):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings


@pytest.fixture
def host(tmp_path: Path) -> _Host:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return _Host(settings)


def _patch_js(monkeypatch: pytest.MonkeyPatch, client: type) -> None:
    monkeypatch.setattr(service_jsre, "JsClient", client)


def _patch_wasm(monkeypatch: pytest.MonkeyPatch, client: type) -> None:
    monkeypatch.setattr(service_jsre, "WasmClient", client)


def _raiser(exc: BaseException) -> Any:
    def _method(*_a: Any, **_k: Any) -> JsonObject:
        raise exc

    return _method


# --- js.deobfuscate / js.beautify -----------------------------------------


def test_js_deobfuscate_success(host: _Host, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_js(monkeypatch, _FakeJs)
    result = host.js_deobfuscate("/tmp/bundle.js")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["op"] == "deobfuscate"


def test_js_deobfuscate_maps_jsre_error(host: _Host, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeJs):
        deobfuscate = _raiser(JsReError("webcrack_failed", "parse error"))

    _patch_js(monkeypatch, _Boom)
    result = host.js_deobfuscate("/tmp/bundle.js")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "webcrack_failed"


def test_js_deobfuscate_maps_unexpected_error(host: _Host, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeJs):
        deobfuscate = _raiser(RuntimeError("node crashed"))

    _patch_js(monkeypatch, _Boom)
    result = host.js_deobfuscate("/tmp/bundle.js")
    assert result.ok is False
    assert result.error is not None


def test_js_beautify_success_and_both_error_kinds(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_js(monkeypatch, _FakeJs)
    ok = host.js_beautify("/tmp/min.js")
    assert ok.ok and ok.data is not None
    assert ok.data["op"] == "beautify"

    class _JsErr(_FakeJs):
        beautify = _raiser(JsReError("beautify_failed", "syntax error"))

    _patch_js(monkeypatch, _JsErr)
    mapped = host.js_beautify("/tmp/min.js")
    assert mapped.ok is False
    assert mapped.error is not None
    assert mapped.error.code == "beautify_failed"

    class _Boom(_FakeJs):
        beautify = _raiser(RuntimeError("node crashed"))

    _patch_js(monkeypatch, _Boom)
    bad = host.js_beautify("/tmp/min.js")
    assert bad.ok is False
    assert bad.error is not None


# --- js.unpack_bundle ------------------------------------------------------


def test_js_unpack_bundle_success_writes_and_prunes(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_js(monkeypatch, _FakeJs)
    result = host.js_unpack_bundle("/tmp/app.js", limit=5)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["files"] == ["chunk.js"]
    jsre_root = host.settings.artifact_root.expanduser().resolve() / "jsre"
    assert jsre_root.is_dir()


def test_js_unpack_bundle_maps_jsre_error(host: _Host, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeJs):
        unpack_bundle = _raiser(JsReError("unpack_failed", "not a bundle"))

    _patch_js(monkeypatch, _Boom)
    result = host.js_unpack_bundle("/tmp/app.js")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_failed"


def test_js_unpack_bundle_maps_unexpected_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeJs):
        unpack_bundle = _raiser(RuntimeError("disk full"))

    _patch_js(monkeypatch, _Boom)
    result = host.js_unpack_bundle("/tmp/app.js")
    assert result.ok is False
    assert result.error is not None


# --- wasm.wat / wasm.info --------------------------------------------------


def test_wasm_wat_success_and_both_error_kinds(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_wasm(monkeypatch, _FakeWasm)
    ok = host.wasm_wat("/tmp/mod.wasm")
    assert ok.ok and ok.data is not None
    assert ok.data["wat"] == "(module)"

    class _JsErr(_FakeWasm):
        wat = _raiser(JsReError("wabt_failed", "bad magic"))

    _patch_wasm(monkeypatch, _JsErr)
    mapped = host.wasm_wat("/tmp/mod.wasm")
    assert mapped.ok is False
    assert mapped.error is not None
    assert mapped.error.code == "wabt_failed"

    class _Boom(_FakeWasm):
        wat = _raiser(RuntimeError("wabt segfault"))

    _patch_wasm(monkeypatch, _Boom)
    bad = host.wasm_wat("/tmp/mod.wasm")
    assert bad.ok is False
    assert bad.error is not None


def test_wasm_info_success_and_both_error_kinds(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_wasm(monkeypatch, _FakeWasm)
    ok = host.wasm_info("/tmp/mod.wasm")
    assert ok.ok and ok.data is not None
    assert ok.data["sections"] == []

    class _JsErr(_FakeWasm):
        info = _raiser(JsReError("wabt_info_failed", "truncated"))

    _patch_wasm(monkeypatch, _JsErr)
    mapped = host.wasm_info("/tmp/mod.wasm")
    assert mapped.ok is False
    assert mapped.error is not None
    assert mapped.error.code == "wabt_info_failed"

    class _Boom(_FakeWasm):
        info = _raiser(RuntimeError("wabt segfault"))

    _patch_wasm(monkeypatch, _Boom)
    bad = host.wasm_info("/tmp/mod.wasm")
    assert bad.ok is False
    assert bad.error is not None


# --- prune_jsre_unpack_dirs -----------------------------------------------


def test_prune_ignores_unlistable_root(tmp_path: Path) -> None:
    # A path that does not exist raises OSError from iterdir; the sweep swallows it.
    prune_jsre_unpack_dirs(tmp_path / "missing")


def test_prune_keeps_when_under_the_cap(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"unpack-{index}").mkdir()
    (tmp_path / "not-an-unpack-dir").mkdir()
    (tmp_path / "unpack-file").write_text("x", encoding="utf-8")

    prune_jsre_unpack_dirs(tmp_path, keep=8)

    assert sum(1 for p in tmp_path.iterdir() if p.name.startswith("unpack-") and p.is_dir()) == 3


def test_prune_drops_oldest_over_the_cap(tmp_path: Path) -> None:
    made: list[Path] = []
    for index in range(5):
        directory = tmp_path / f"unpack-{index}"
        directory.mkdir()
        # Space mtimes apart so the sort order is deterministic.
        stamp = 1_000_000 + index * 1_000_000
        os.utime(directory, ns=(stamp, stamp))
        made.append(directory)

    prune_jsre_unpack_dirs(tmp_path, keep=2)

    survivors = {p.name for p in tmp_path.iterdir() if p.is_dir()}
    assert survivors == {"unpack-3", "unpack-4"}


def test_prune_treats_unstattable_dir_as_oldest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doomed = tmp_path / "unpack-doomed"
    doomed.mkdir()
    for index in range(2):
        keeper = tmp_path / f"unpack-keep-{index}"
        keeper.mkdir()
        stamp = 5_000_000 + index * 1_000_000
        os.utime(keeper, ns=(stamp, stamp))

    real_stat = Path.stat
    doomed_calls = {"n": 0}

    def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        # is_dir() stats the entry first (call 1, allowed); _mtime stats it
        # again (call 2, refused) so the mtime sort treats it as oldest.
        if self.name == "unpack-doomed":
            doomed_calls["n"] += 1
            if doomed_calls["n"] >= 2:
                raise OSError("stat refused")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    prune_jsre_unpack_dirs(tmp_path, keep=2)
    monkeypatch.undo()

    survivors = {p.name for p in tmp_path.iterdir() if p.is_dir()}
    assert "unpack-doomed" not in survivors
    assert survivors == {"unpack-keep-0", "unpack-keep-1"}
