"""Branch coverage for the JS/WASM static-analysis service mixin.

These wrap the webcrack/wabt backends into Result envelopes: a backend
JsReError becomes a structured failure, an unexpected exception is still
captured (never escapes as a crash), and the unregistered unpack tree is pruned
so a path-keyed tool cannot leak disk the artifact table never sees.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_jsre
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_jsre import prune_jsre_unpack_dirs

MP = pytest.MonkeyPatch


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


class _OkJs:
    def __init__(self, _exe: Any = None) -> None:
        pass

    def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        return {"code": "clean();", "truncated": False}

    def beautify(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        return {"code": "pretty();"}

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "mod.js").write_text("x")
        return {"output_dir": str(out_dir), "file_count": 1, "files": ["mod.js"]}


class _OkWasm:
    def __init__(self, _exe: Any = None) -> None:
        pass

    def wat(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        return {"wat": "(module)"}

    def info(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
        return {"objdump": "Sections:"}


class _BoomJs:
    def __init__(self, _exe: Any = None) -> None:
        pass

    def deobfuscate(self, *a: Any, **k: Any) -> dict[str, Any]:
        raise RuntimeError("unexpected")

    beautify = deobfuscate

    def unpack_bundle(self, *a: Any, **k: Any) -> dict[str, Any]:
        raise RuntimeError("unexpected")


class _BoomWasm:
    def __init__(self, _exe: Any = None) -> None:
        pass

    def wat(self, *a: Any, **k: Any) -> dict[str, Any]:
        raise RuntimeError("unexpected")

    info = wat


class TestSuccessPaths:
    def test_js_deobfuscate_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_jsre, "JsClient", _OkJs)
        result = service.js_deobfuscate("/tmp/a.js")
        assert result.ok is True
        assert result.data is not None and result.data["code"] == "clean();"

    def test_js_beautify_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_jsre, "JsClient", _OkJs)
        result = service.js_beautify("/tmp/a.js")
        assert result.ok is True and result.data is not None
        assert result.data["code"] == "pretty();"

    def test_js_unpack_bundle_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_jsre, "JsClient", _OkJs)
        result = service.js_unpack_bundle("/tmp/bundle.js")
        assert result.ok is True and result.data is not None
        assert result.data["file_count"] == 1

    def test_wasm_wat_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_jsre, "WasmClient", _OkWasm)
        result = service.wasm_wat("/tmp/m.wasm")
        assert result.ok is True and result.data is not None
        assert result.data["wat"] == "(module)"

    def test_wasm_info_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_jsre, "WasmClient", _OkWasm)
        result = service.wasm_info("/tmp/m.wasm")
        assert result.ok is True and result.data is not None
        assert result.data["objdump"] == "Sections:"


class TestErrorMapping:
    def test_js_deobfuscate_maps_backend_error(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Err(_OkJs):
            def deobfuscate(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JsReError("capability_unavailable", "no webcrack")

        monkeypatch.setattr(service_jsre, "JsClient", _Err)
        result = service.js_deobfuscate("/tmp/a.js")
        assert result.ok is False
        assert result.error is not None and result.error.code == "capability_unavailable"

    def test_other_methods_map_backend_error(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _ErrJs(_OkJs):
            def beautify(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JsReError("not_found", "missing")

            def unpack_bundle(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JsReError("too_large", "big")

        class _ErrWasm(_OkWasm):
            def wat(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JsReError("invalid_params", "bad magic")

            def info(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JsReError("backend_error", "objdump died")

        monkeypatch.setattr(service_jsre, "JsClient", _ErrJs)
        monkeypatch.setattr(service_jsre, "WasmClient", _ErrWasm)
        assert service.js_beautify("/tmp/a.js").error.code == "not_found"  # type: ignore[union-attr]
        assert service.js_unpack_bundle("/tmp/a.js").error.code == "too_large"  # type: ignore[union-attr]
        assert service.wasm_wat("/tmp/m.wasm").error.code == "invalid_params"  # type: ignore[union-attr]
        assert service.wasm_info("/tmp/m.wasm").error.code == "backend_error"  # type: ignore[union-attr]

    def test_js_deobfuscate_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_jsre, "JsClient", _BoomJs)
        result = service.js_deobfuscate("/tmp/a.js")
        assert result.ok is False and result.error is not None

    def test_js_beautify_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_jsre, "JsClient", _BoomJs)
        assert service.js_beautify("/tmp/a.js").ok is False

    def test_js_unpack_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_jsre, "JsClient", _BoomJs)
        assert service.js_unpack_bundle("/tmp/a.js").ok is False

    def test_wasm_wat_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_jsre, "WasmClient", _BoomWasm)
        assert service.wasm_wat("/tmp/m.wasm").ok is False

    def test_wasm_info_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_jsre, "WasmClient", _BoomWasm)
        assert service.wasm_info("/tmp/m.wasm").ok is False


class TestPruneUnpackDirs:
    def test_prune_ignores_a_missing_root(self, tmp_path: Path) -> None:
        prune_jsre_unpack_dirs(tmp_path / "nope")  # no raise

    def test_prune_survives_stat_errors(self, tmp_path: Path, monkeypatch: MP) -> None:
        for i in range(3):
            (tmp_path / f"unpack-{i}").mkdir()
        (tmp_path / "keep-me").mkdir()  # not an unpack- dir, must be untouched
        real_stat = Path.stat

        def _fake_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
            if sys._getframe(1).f_code.co_name == "_mtime":
                raise OSError("stat blew up")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _fake_stat)
        prune_jsre_unpack_dirs(tmp_path, keep=1)
        remaining = sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("unpack-"))
        assert len(remaining) == 1  # two oldest dropped despite the stat errors
        assert (tmp_path / "keep-me").is_dir()
