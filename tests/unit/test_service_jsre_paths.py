"""JsReAnalysisMixin error mapping plus the unpack-dir retention helper.

The webcrack/wabt CLIs are not installed in CI, so the JsClient/WasmClient
classes are monkeypatched with fakes. That lets every method's success and
error contract run, and lets the retention helper's guard branches be driven
directly with real directories.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_jsre import prune_jsre_unpack_dirs


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _install_js(
    monkeypatch: pytest.MonkeyPatch,
    cls_name: str,
    *,
    payload: dict[str, Any] | None = None,
    error: BaseException | None = None,
) -> None:
    class _Fake:
        def __init__(self, executable: Any = None) -> None:
            self.executable = executable

        def _out(self, path: Path) -> dict[str, Any]:
            if error is not None:
                raise error
            return dict(payload or {"path": str(path)})

        def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
            return self._out(path)

        def beautify(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
            return self._out(path)

        def unpack_bundle(
            self,
            path: Path,
            out_dir: Path,
            *,
            timeout: float = 300.0,
            offset: int = 0,
            limit: int = 100,
        ) -> dict[str, Any]:
            if error is not None:
                raise error
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "index.js").write_text("x", encoding="utf-8")
            return dict(payload or {"out_dir": str(out_dir), "entries": []})

        def wat(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
            return self._out(path)

        def info(self, path: Path, *, timeout: float = 120.0) -> dict[str, Any]:
            return self._out(path)

    monkeypatch.setattr(f"headless_re_mcp.core.service_jsre.{cls_name}", _Fake)


def test_js_deobfuscate_beautify_success_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        _install_js(monkeypatch, "JsClient", payload={"code": "clean"})
        ok = service.js_deobfuscate(str(tmp_path / "a.js"))
        assert ok.ok and ok.data == {"code": "clean"}
        assert service.js_beautify(str(tmp_path / "a.js")).ok

        _install_js(monkeypatch, "JsClient", error=JsReError("tool_not_found", "no webcrack"))
        mapped = service.js_deobfuscate(str(tmp_path / "a.js"))
        assert mapped.ok is False and mapped.error is not None
        assert mapped.error.code == "tool_not_found"
        assert service.js_beautify(str(tmp_path / "a.js")).ok is False

        _install_js(monkeypatch, "JsClient", error=RuntimeError("boom"))
        assert service.js_deobfuscate(str(tmp_path / "a.js")).ok is False
        assert service.js_beautify(str(tmp_path / "a.js")).ok is False
    finally:
        service.close_all()


def test_js_unpack_bundle_success_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        _install_js(monkeypatch, "JsClient", payload={"entries": ["index.js"]})
        ok = service.js_unpack_bundle(str(tmp_path / "bundle.js"))
        assert ok.ok and ok.data == {"entries": ["index.js"]}

        _install_js(monkeypatch, "JsClient", error=JsReError("invalid_params", "bad bundle"))
        mapped = service.js_unpack_bundle(str(tmp_path / "bundle.js"))
        assert mapped.ok is False and mapped.error is not None
        assert mapped.error.code == "invalid_params"

        _install_js(monkeypatch, "JsClient", error=RuntimeError("boom"))
        assert service.js_unpack_bundle(str(tmp_path / "bundle.js")).ok is False
    finally:
        service.close_all()


def test_wasm_wat_and_info_success_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        _install_js(monkeypatch, "WasmClient", payload={"wat": "(module)"})
        ok = service.wasm_wat(str(tmp_path / "m.wasm"))
        assert ok.ok and ok.data == {"wat": "(module)"}
        _install_js(monkeypatch, "WasmClient", payload={"sections": []})
        assert service.wasm_info(str(tmp_path / "m.wasm")).ok

        _install_js(monkeypatch, "WasmClient", error=JsReError("tool_not_found", "no wabt"))
        mapped = service.wasm_wat(str(tmp_path / "m.wasm"))
        assert mapped.ok is False and mapped.error is not None
        assert mapped.error.code == "tool_not_found"
        assert service.wasm_info(str(tmp_path / "m.wasm")).ok is False

        _install_js(monkeypatch, "WasmClient", error=RuntimeError("boom"))
        assert service.wasm_wat(str(tmp_path / "m.wasm")).ok is False
        assert service.wasm_info(str(tmp_path / "m.wasm")).ok is False
    finally:
        service.close_all()


def test_prune_jsre_unpack_dirs_evicts_oldest_over_keep(tmp_path: Path) -> None:
    root = tmp_path / "jsre"
    root.mkdir()
    made: list[Path] = []
    for index in range(5):
        d = root / f"unpack-{index}"
        d.mkdir()
        # Stagger mtimes so the sort has a defined oldest-first order.
        import os

        os.utime(d, (1000 + index, 1000 + index))
        made.append(d)
    # A non-unpack sibling must never be swept.
    keeper = root / "keep-me"
    keeper.mkdir()

    prune_jsre_unpack_dirs(root, keep=2)

    survivors = sorted(p.name for p in root.iterdir())
    assert "keep-me" in survivors
    assert made[0].name not in survivors and made[1].name not in survivors
    assert made[3].name in survivors and made[4].name in survivors


def test_prune_jsre_unpack_dirs_noop_when_under_keep(tmp_path: Path) -> None:
    root = tmp_path / "jsre"
    root.mkdir()
    (root / "unpack-a").mkdir()
    prune_jsre_unpack_dirs(root, keep=8)
    assert (root / "unpack-a").exists()


def test_prune_jsre_unpack_dirs_survives_an_unlistable_root(tmp_path: Path) -> None:
    # iterdir on a file raises NotADirectoryError (an OSError); the helper must
    # swallow it rather than let retention bookkeeping raise.
    not_a_dir = tmp_path / "jsre-file"
    not_a_dir.write_text("", encoding="utf-8")
    prune_jsre_unpack_dirs(not_a_dir)
