"""Guard, retention and error-mapping paths of the jsre service mixin.

The webcrack/wabt backends have their own suite; this file covers the thin
service layer -- the ``JsReError`` -> envelope mapping on every method, the
unexpected-error arm, and the unpack-directory retention helper. The backend
classes are faked in the module namespace so neither webcrack nor wabt needs to
be installed.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_jsre as service_jsre
from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.core.service_jsre import JsReAnalysisMixin, prune_jsre_unpack_dirs


class _Host(JsReAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, webcrack=None, wabt=None)


@pytest.fixture
def host(tmp_path: Path) -> _Host:
    return _Host(tmp_path)


def _returns(value: dict[str, Any]) -> Any:
    def _fn(_self: Any, *_a: Any, **_k: Any) -> dict[str, Any]:
        return value

    return _fn


def _raises(exc: BaseException) -> Any:
    def _fn(_self: Any, *_a: Any, **_k: Any) -> dict[str, Any]:
        raise exc

    return _fn


def _install_js(monkeypatch: pytest.MonkeyPatch, **methods: Any) -> None:
    fake = type("_FakeJsClient", (), {"__init__": lambda self, _cfg=None: None, **methods})
    monkeypatch.setattr(service_jsre, "JsClient", fake)


def _install_wasm(monkeypatch: pytest.MonkeyPatch, **methods: Any) -> None:
    fake = type("_FakeWasmClient", (), {"__init__": lambda self, _cfg=None: None, **methods})
    monkeypatch.setattr(service_jsre, "WasmClient", fake)


# ---------------------------------------------------------------------------
# js.deobfuscate


def test_js_deobfuscate_returns_the_backend_payload(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, deobfuscate=_returns({"transformed": True}))

    result = host.js_deobfuscate("/tmp/app.js")

    assert result.ok, result.error
    assert result.data == {"transformed": True}
    assert result.meta.get("backend") == "webcrack"


def test_js_deobfuscate_maps_a_jsre_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, deobfuscate=_raises(JsReError("invalid_input", "not javascript")))

    result = host.js_deobfuscate("/tmp/app.js")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_input"


def test_js_deobfuscate_maps_an_unexpected_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, deobfuscate=_raises(ValueError("boom")))

    result = host.js_deobfuscate("/tmp/app.js")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# js.beautify


def test_js_beautify_returns_the_backend_payload(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, beautify=_returns({"code": "pretty"}))

    result = host.js_beautify("/tmp/app.js")

    assert result.ok, result.error
    assert result.meta.get("backend") == "webcrack"


def test_js_beautify_maps_a_jsre_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, beautify=_raises(JsReError("timeout", "webcrack timed out")))

    result = host.js_beautify("/tmp/app.js")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "timeout"


def test_js_beautify_maps_an_unexpected_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, beautify=_raises(ValueError("boom")))

    result = host.js_beautify("/tmp/app.js")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# js.unpack_bundle


def test_js_unpack_bundle_maps_a_jsre_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, unpack_bundle=_raises(JsReError("backend_error", "webcrack failed")))

    result = host.js_unpack_bundle("/tmp/bundle.js")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_js_unpack_bundle_maps_an_unexpected_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_js(monkeypatch, unpack_bundle=_raises(ValueError("boom")))

    result = host.js_unpack_bundle("/tmp/bundle.js")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# wasm.wat / wasm.info


def test_wasm_wat_returns_the_backend_payload(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_wasm(monkeypatch, wat=_returns({"wat": "(module)"}))

    result = host.wasm_wat("/tmp/mod.wasm")

    assert result.ok, result.error
    assert result.meta.get("backend") == "wabt"


def test_wasm_wat_maps_a_jsre_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_wasm(monkeypatch, wat=_raises(JsReError("invalid_input", "not wasm")))

    result = host.wasm_wat("/tmp/mod.wasm")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_input"


def test_wasm_wat_maps_an_unexpected_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_wasm(monkeypatch, wat=_raises(ValueError("boom")))

    result = host.wasm_wat("/tmp/mod.wasm")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_wasm_info_returns_the_backend_payload(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_wasm(monkeypatch, info=_returns({"sections": []}))

    result = host.wasm_info("/tmp/mod.wasm")

    assert result.ok, result.error
    assert result.meta.get("backend") == "wabt"


def test_wasm_info_maps_a_jsre_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_wasm(monkeypatch, info=_raises(JsReError("not_found", "file missing")))

    result = host.wasm_info("/tmp/mod.wasm")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_wasm_info_maps_an_unexpected_error(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_wasm(monkeypatch, info=_raises(RuntimeError("boom")))

    result = host.wasm_info("/tmp/mod.wasm")

    assert not result.ok
    assert result.error is not None


# ---------------------------------------------------------------------------
# prune_jsre_unpack_dirs


def test_prune_swallows_a_root_that_cannot_be_listed(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("x", encoding="utf-8")

    # A file where a directory was expected must not raise out of retention.
    prune_jsre_unpack_dirs(not_a_dir)


def test_prune_keeps_everything_when_under_the_cap(tmp_path: Path) -> None:
    kept = [tmp_path / f"unpack-{i}" for i in range(3)]
    for path in kept:
        path.mkdir()

    prune_jsre_unpack_dirs(tmp_path, keep=8)

    assert all(path.is_dir() for path in kept)


def test_prune_drops_the_oldest_unpack_trees(tmp_path: Path) -> None:
    dirs = []
    for i in range(10):
        path = tmp_path / f"unpack-{i}"
        path.mkdir()
        # Stagger mtimes so the sort has a deterministic oldest-first order.
        os.utime(path, (1_000 + i, 1_000 + i))
        dirs.append(path)
    # A non-unpack sibling and a stray file must be left alone.
    (tmp_path / "keep-me").mkdir()
    (tmp_path / "note.txt").write_text("x", encoding="utf-8")

    prune_jsre_unpack_dirs(tmp_path, keep=8)

    assert not dirs[0].exists()
    assert not dirs[1].exists()
    assert all(path.is_dir() for path in dirs[2:])
    assert (tmp_path / "keep-me").is_dir()
    assert (tmp_path / "note.txt").is_file()
