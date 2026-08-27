"""service_jsre's four one-shot wrappers: success, backend error, and the
unexpected-exception catch-all -- plus the unpack pruner's OSError guards.

js.deobfuscate / js.beautify / wasm.wat / wasm.info each hand a file to a
JsClient/WasmClient and wrap the reply. The backend tests drive those clients
directly (run_bounded patched), so the *service* wrappers were never exercised:
webcrack and wabt are simply not installed on the test host, so only the
capability_unavailable JsReError path ever ran through the service. That left
three real contracts unpinned per method -- the success envelope that stamps the
backend name, the JsReError->code mapping, and the `except BaseException` that
turns an unexpected fault into a structured internal_error rather than letting
it escape the RPC. These pin all three at the service layer for every one-shot
method, the same catch-all on js.unpack_bundle, and the two OSError guards in
prune_jsre_unpack_dirs (a non-directory root, and a stat that fails mid-sort).
"""

from __future__ import annotations

import os
import pathlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.core.service_jsre import JsReAnalysisMixin, prune_jsre_unpack_dirs

JsonObject = dict[str, Any]


class _FakeClient:
    """Stands in for JsClient/WasmClient: each entry point returns data or raises."""

    def __init__(
        self, *, data: JsonObject | None = None, raises: BaseException | None = None
    ) -> None:
        self._data = data
        self._raises = raises

    def _answer(self) -> JsonObject:
        if self._raises is not None:
            raise self._raises
        assert self._data is not None
        return dict(self._data)

    def deobfuscate(self, path: Path, timeout: float = 120.0) -> JsonObject:
        del path, timeout
        return self._answer()

    def beautify(self, path: Path, timeout: float = 120.0) -> JsonObject:
        del path, timeout
        return self._answer()

    def wat(self, path: Path, timeout: float = 120.0) -> JsonObject:
        del path, timeout
        return self._answer()

    def info(self, path: Path, timeout: float = 120.0) -> JsonObject:
        del path, timeout
        return self._answer()

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        del path, out_dir, timeout, offset, limit
        return self._answer()


class _Harness(JsReAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, webcrack=None, wabt=None)


def _install(monkeypatch: pytest.MonkeyPatch, attr: str, client: _FakeClient) -> None:
    monkeypatch.setattr(
        f"headless_re_mcp.core.service_jsre.{attr}", lambda *a, **k: client
    )


# (service method, factory attr the method instantiates, backend name it stamps,
#  a plausible payload the backend would return)
_METHODS = [
    ("js_deobfuscate", "JsClient", "webcrack", {"code": "z", "bytes": 1, "truncated": False}),
    ("js_beautify", "JsClient", "webcrack", {"code": "z", "bytes": 1, "truncated": False}),
    ("wasm_wat", "WasmClient", "wabt", {"wat": "(module)", "bytes": 8}),
    ("wasm_info", "WasmClient", "wabt", {"objdump": "x", "bytes": 1, "truncated": False}),
]


@pytest.mark.parametrize(("method", "attr", "backend", "payload"), _METHODS)
def test_success_wraps_the_backend_payload_and_stamps_the_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    attr: str,
    backend: str,
    payload: JsonObject,
) -> None:
    _install(monkeypatch, attr, _FakeClient(data=payload))
    harness = _Harness(tmp_path)

    result = getattr(harness, method)("/tmp/app.bin")

    assert result.ok is True, result.error
    assert result.data == payload
    assert result.meta.get("backend") == backend


@pytest.mark.parametrize(("method", "attr", "backend", "payload"), _METHODS)
def test_a_backend_JsReError_surfaces_its_own_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    attr: str,
    backend: str,
    payload: JsonObject,
) -> None:
    del backend, payload
    _install(
        monkeypatch,
        attr,
        _FakeClient(raises=JsReError("capability_unavailable", "tool not installed")),
    )
    harness = _Harness(tmp_path)

    result = getattr(harness, method)("/tmp/app.bin")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


@pytest.mark.parametrize(("method", "attr", "backend", "payload"), _METHODS)
def test_an_unexpected_exception_becomes_internal_error_not_a_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    attr: str,
    backend: str,
    payload: JsonObject,
) -> None:
    """A backend fault that is not a JsReError must still fail closed as a
    structured envelope, never propagate out of the service into the RPC loop."""
    del backend, payload
    _install(monkeypatch, attr, _FakeClient(raises=RuntimeError("backend blew up")))
    harness = _Harness(tmp_path)

    result = getattr(harness, method)("/tmp/app.bin")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


def test_unpack_maps_an_unexpected_exception_to_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """js.unpack_bundle's own non-JsReError catch-all: a fault after the out dir
    is created still fails closed (and the finally-block prune still runs)."""
    _install(monkeypatch, "JsClient", _FakeClient(raises=RuntimeError("unpack blew up")))
    harness = _Harness(tmp_path)

    result = harness.js_unpack_bundle("/tmp/app.js")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


def test_prune_swallows_a_non_directory_or_missing_root(tmp_path: Path) -> None:
    """iterdir on a file or a missing path raises OSError; the pruner must return
    quietly rather than let a bookkeeping sweep fail the call that triggered it."""
    not_a_dir = tmp_path / "regular-file"
    not_a_dir.write_text("x", encoding="utf-8")

    prune_jsre_unpack_dirs(not_a_dir)
    prune_jsre_unpack_dirs(tmp_path / "does-not-exist")


def test_prune_survives_stat_failures_while_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a dir vanishes between the is_dir filter and the mtime sort, its stat
    raises; _mtime treats that as age 0 so the sweep still completes and trims to
    keep. Forced directly so the guard does not depend on a real TOCTOU race."""
    root = tmp_path / "jsre"
    root.mkdir()
    for index in range(3):
        (root / f"unpack-{index}").mkdir()

    monkeypatch.setattr(
        pathlib.Path, "is_dir", lambda self: self.name.startswith("unpack-")
    )

    def _stat_is_down(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        raise OSError("stat is down")

    monkeypatch.setattr(pathlib.Path, "stat", _stat_is_down)

    prune_jsre_unpack_dirs(root, keep=1)

    assert len(os.listdir(root)) == 1
