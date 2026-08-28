"""JS/WASM static-analysis service paths (JsReAnalysisMixin).

The webcrack/wabt backends are exercised directly elsewhere; here the service
orchestration is pinned: the deobfuscate/beautify/unpack/wat/info happy paths and
their JsReError/unexpected -> structured-envelope mapping, plus the unpack-tree
pruning helper (including its OSError guards). Clients are constructed inline by
the mixin, so each is monkeypatched at the module boundary.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_jsre
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_jsre import prune_jsre_unpack_dirs


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


class _FakeJs:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc

    def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(path), "deobfuscated": True}

    def beautify(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(path), "beautified": True}

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "module-0.js").write_text("var a=1;", encoding="utf-8")
        return {"out_dir": str(out_dir), "modules": ["module-0.js"], "count": 1, "has_more": False}


class _FakeWasm:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc

    def wat(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(path), "wat": "(module)", "truncated": False}

    def info(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(path), "sections": [], "count": 0}


def _use_js(monkeypatch: pytest.MonkeyPatch, fake: _FakeJs) -> None:
    monkeypatch.setattr(service_jsre, "JsClient", lambda *a, **k: fake)


def _use_wasm(monkeypatch: pytest.MonkeyPatch, fake: _FakeWasm) -> None:
    monkeypatch.setattr(service_jsre, "WasmClient", lambda *a, **k: fake)


# ---------------------------------------------------------------------------
# js.deobfuscate / js.beautify
# ---------------------------------------------------------------------------
def test_js_deobfuscate_and_beautify_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_js(monkeypatch, _FakeJs())
    src = tmp_path / "bundle.js"
    src.write_text("var a=1;", encoding="utf-8")
    try:
        deob = service.js_deobfuscate(str(src))
        assert deob.ok, deob.error
        assert deob.meta["backend"] == "webcrack"
        assert service.js_beautify(str(src)).ok
    finally:
        service.close_all()


def test_js_deobfuscate_maps_jsre_error_and_unexpected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    src = tmp_path / "bundle.js"
    src.write_text("var a=1;", encoding="utf-8")
    try:
        _use_js(monkeypatch, _FakeJs(JsReError("capability_unavailable", "webcrack missing")))
        mapped = service.js_deobfuscate(str(src))
        assert mapped.ok is False
        assert mapped.error is not None and mapped.error.code == "capability_unavailable"

        _use_js(monkeypatch, _FakeJs(RuntimeError("node segfault")))
        unexpected = service.js_beautify(str(src))
        assert unexpected.ok is False
        assert unexpected.error is not None and unexpected.error.code == "internal_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# js.unpack_bundle (writes + prunes; error + unexpected still prune in finally)
# ---------------------------------------------------------------------------
def test_js_unpack_bundle_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_js(monkeypatch, _FakeJs())
    src = tmp_path / "app.js"
    src.write_text("var a=1;", encoding="utf-8")
    try:
        result = service.js_unpack_bundle(str(src), offset=0, limit=10)
        assert result.ok, result.error
        assert result.data is not None and result.data["count"] == 1
    finally:
        service.close_all()


def test_js_unpack_bundle_maps_error_and_still_prunes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_js(monkeypatch, _FakeJs(JsReError("too_large", "bundle over cap")))
    src = tmp_path / "app.js"
    src.write_text("var a=1;", encoding="utf-8")
    try:
        result = service.js_unpack_bundle(str(src))
        assert result.ok is False
        assert result.error is not None and result.error.code == "too_large"

        _use_js(monkeypatch, _FakeJs(RuntimeError("unexpected")))
        boom = service.js_unpack_bundle(str(src))
        assert boom.ok is False
        assert boom.error is not None and boom.error.code == "internal_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# wasm.wat / wasm.info
# ---------------------------------------------------------------------------
def test_wasm_wat_and_info_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_wasm(monkeypatch, _FakeWasm())
    mod = tmp_path / "mod.wasm"
    mod.write_bytes(b"\x00asm\x01\x00\x00\x00")
    try:
        assert service.wasm_wat(str(mod)).ok
        assert service.wasm_info(str(mod)).ok
    finally:
        service.close_all()


def test_wasm_wat_and_info_map_jsre_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    mod = tmp_path / "mod.wasm"
    mod.write_bytes(b"\x00asm\x01\x00\x00\x00")
    try:
        _use_wasm(monkeypatch, _FakeWasm(JsReError("backend_error", "wat2wasm failed")))
        wat = service.wasm_wat(str(mod))
        assert wat.ok is False and wat.error is not None
        assert wat.error.code == "backend_error"

        _use_wasm(monkeypatch, _FakeWasm(JsReError("invalid_params", "not a wasm module")))
        info = service.wasm_info(str(mod))
        assert info.ok is False and info.error is not None
        assert info.error.code == "invalid_params"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# prune_jsre_unpack_dirs helper (including OSError guards)
# ---------------------------------------------------------------------------
def test_prune_jsre_unpack_dirs_drops_the_oldest(tmp_path: Path) -> None:
    import os

    for i in range(4):
        d = tmp_path / f"unpack-{i}"
        d.mkdir()
        os.utime(d, ns=(1000 + i, 1000 + i))
    (tmp_path / "keepme").mkdir()  # a non-unpack dir is ignored
    prune_jsre_unpack_dirs(tmp_path, keep=2)
    remaining = sorted(p.name for p in tmp_path.iterdir())
    assert remaining == ["keepme", "unpack-2", "unpack-3"]


def test_prune_jsre_unpack_dirs_tolerates_a_missing_root(tmp_path: Path) -> None:
    prune_jsre_unpack_dirs(tmp_path / "not-there", keep=2)  # no raise
