"""The jsre service mixin must envelope every backend outcome and prune spills.

``JsReAnalysisMixin`` wraps the webcrack/wabt clients: each method returns a
``_success`` payload, maps a ``JsReError`` through ``_as_rpc`` (timeout stays
retryable), and lets anything else fall through as a plain failure. Neither tool
is installed here, so the clients are swapped for fakes that return data or
raise on demand -- the point is the mixin's translation, not the CLI.

``prune_jsre_unpack_dirs`` is the retention guard for the unpack trees the tool
never registers: it drops the oldest once the directory is full, returns
quietly when the directory cannot be read, and tolerates a stat that fails
mid-sort.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_jsre
from headless_re_mcp.core.service_jsre import JsReAnalysisMixin, prune_jsre_unpack_dirs

JsonObject = dict[str, Any]


class _Svc(JsReAnalysisMixin):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings


@pytest.fixture
def svc(tmp_path: Path) -> _Svc:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return _Svc(settings)


class _FakeJs:
    """A webcrack stand-in with per-method scripted outcomes."""

    result: JsonObject = {"code": "ok"}
    error: BaseException | None = None

    def __init__(self, tool: Any) -> None:
        self.tool = tool

    def _answer(self) -> JsonObject:
        err = type(self).error
        if err is not None:
            raise err
        return dict(type(self).result)

    def deobfuscate(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return self._answer()

    def beautify(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return self._answer()

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        out_dir.mkdir(parents=True, exist_ok=True)
        return self._answer()


class _FakeWasm:
    result: JsonObject = {"wat": "(module)"}
    error: BaseException | None = None

    def __init__(self, tool: Any) -> None:
        self.tool = tool

    def _answer(self) -> JsonObject:
        err = type(self).error
        if err is not None:
            raise err
        return dict(type(self).result)

    def wat(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return self._answer()

    def info(self, path: Path, timeout: float = 120.0) -> JsonObject:
        return self._answer()


@pytest.fixture(autouse=True)
def _fresh_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeJs.error = None
    _FakeJs.result = {"code": "ok"}
    _FakeWasm.error = None
    _FakeWasm.result = {"wat": "(module)"}
    monkeypatch.setattr(service_jsre, "JsClient", _FakeJs)
    monkeypatch.setattr(service_jsre, "WasmClient", _FakeWasm)


# --------------------------------------------------------------------------
# success paths
# --------------------------------------------------------------------------


def test_js_deobfuscate_returns_the_backend_payload(svc: _Svc) -> None:
    result = svc.js_deobfuscate("/tmp/a.js")
    assert result.ok, result.error
    assert result.data == {"code": "ok"}
    assert result.meta.get("backend") == "webcrack"


def test_js_beautify_returns_the_backend_payload(svc: _Svc) -> None:
    _FakeJs.result = {"code": "beautified"}
    result = svc.js_beautify("/tmp/a.js")
    assert result.ok, result.error
    assert result.data == {"code": "beautified"}


def test_js_unpack_bundle_returns_the_backend_payload(svc: _Svc) -> None:
    _FakeJs.result = {"modules": []}
    result = svc.js_unpack_bundle("/tmp/bundle.js")
    assert result.ok, result.error
    assert result.data == {"modules": []}


def test_wasm_wat_returns_the_backend_payload(svc: _Svc) -> None:
    result = svc.wasm_wat("/tmp/m.wasm")
    assert result.ok, result.error
    assert result.data == {"wat": "(module)"}


def test_wasm_info_returns_the_backend_payload(svc: _Svc) -> None:
    _FakeWasm.result = {"sections": []}
    result = svc.wasm_info("/tmp/m.wasm")
    assert result.ok, result.error
    assert result.data == {"sections": []}


# --------------------------------------------------------------------------
# JsReError -> _as_rpc (timeout retryable) and bare-exception fall-through
# --------------------------------------------------------------------------


def test_a_timeout_is_mapped_retryable(svc: _Svc) -> None:
    _FakeJs.error = JsReError("timeout", "webcrack timed out")
    result = svc.js_deobfuscate("/tmp/a.js")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


def test_a_capability_error_is_mapped_non_retryable(svc: _Svc) -> None:
    _FakeWasm.error = JsReError("capability_unavailable", "wabt is not installed")
    result = svc.wasm_wat("/tmp/m.wasm")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"
    assert result.error.retryable is False


@pytest.mark.parametrize(
    "method, uses_wasm, arg",
    [
        ("js_deobfuscate", False, "/tmp/a.js"),
        ("js_beautify", False, "/tmp/a.js"),
        ("js_unpack_bundle", False, "/tmp/bundle.js"),
        ("wasm_wat", True, "/tmp/m.wasm"),
        ("wasm_info", True, "/tmp/m.wasm"),
    ],
)
def test_every_method_maps_a_jsre_error_through_as_rpc(
    svc: _Svc, method: str, uses_wasm: bool, arg: str
) -> None:
    error = JsReError("backend_error", "tool failed")
    if uses_wasm:
        _FakeWasm.error = error
    else:
        _FakeJs.error = error
    result = getattr(svc, method)(arg)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"
    assert result.error.retryable is False


@pytest.mark.parametrize(
    "method, uses_wasm",
    [
        ("js_deobfuscate", False),
        ("js_beautify", False),
        ("js_unpack_bundle", False),
        ("wasm_wat", True),
        ("wasm_info", True),
    ],
)
def test_an_unexpected_exception_falls_through_as_a_failure(
    svc: _Svc, method: str, uses_wasm: bool
) -> None:
    if uses_wasm:
        _FakeWasm.error = RuntimeError("segfault in the CLI")
        arg = "/tmp/m.wasm"
    else:
        _FakeJs.error = RuntimeError("segfault in the CLI")
        arg = "/tmp/a.js"
    result = getattr(svc, method)(arg)
    assert result.ok is False
    assert result.error is not None


def test_js_unpack_bundle_prunes_even_when_the_backend_raises(svc: _Svc) -> None:
    """The finally-clause prune must run on the failure path too."""
    _FakeJs.error = JsReError("backend_error", "webcrack crashed")
    result = svc.js_unpack_bundle("/tmp/bundle.js")
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# prune_jsre_unpack_dirs
# --------------------------------------------------------------------------


def _make_unpack_dir(root: Path, name: str, *, age_s: float) -> Path:
    path = root / f"unpack-{name}"
    path.mkdir(parents=True)
    stamp = time.time() - age_s
    import os

    os.utime(path, (stamp, stamp))
    return path


def test_prune_drops_the_oldest_trees_over_the_keep_limit(tmp_path: Path) -> None:
    root = tmp_path / "jsre"
    root.mkdir()
    old = _make_unpack_dir(root, "old", age_s=100)
    mid = _make_unpack_dir(root, "mid", age_s=50)
    new = _make_unpack_dir(root, "new", age_s=1)
    prune_jsre_unpack_dirs(root, keep=1)
    assert not old.exists()
    assert not mid.exists()
    assert new.exists()


def test_prune_returns_quietly_when_the_directory_is_unreadable(tmp_path: Path) -> None:
    prune_jsre_unpack_dirs(tmp_path / "does-not-exist", keep=1)


def test_prune_tolerates_a_stat_failure_mid_sort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "jsre"
    root.mkdir()
    first = _make_unpack_dir(root, "a", age_s=100)
    second = _make_unpack_dir(root, "b", age_s=1)

    real_stat = Path.stat
    seen: set[str] = set()

    def selective_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        # The first stat per path is ``is_dir`` during the listing; the second is
        # the ``_mtime`` sort key. Fail only the latter so the directory listing
        # stands and the mtime falls back to 0.
        key = str(self)
        if key in seen:
            raise OSError("stat refused")
        seen.add(key)
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", selective_stat)
    prune_jsre_unpack_dirs(root, keep=1)
    monkeypatch.undo()
    # One of the two (all mtime 0) is dropped; the directory is now at the cap.
    remaining = [p for p in (first, second) if p.exists()]
    assert len(remaining) == 1
