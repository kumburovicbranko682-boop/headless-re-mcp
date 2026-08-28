"""Device-free coverage for the JS/WASM static-analysis service contract.

``service_jsre`` is the boundary between the webcrack/wabt subprocess clients
and the RPC envelope: for every one of its five methods it must turn a
``JsReError`` (the client's structured "too_large / not_found /
capability_unavailable / backend_error" signal) into an ``XdbgRpcError`` that
keeps the *code* and *details*, and let any other exception fall through the
canonical ``_failure`` dispatch so a ``FileNotFoundError`` reads as
``file_not_found`` and a ``ValueError`` as ``invalid_request`` rather than a
generic incident.

None of that was exercised device-free: the existing jsre tests either need
webcrack/wabt on PATH (they skip without) or only reach the retention/pruning
logic. So the branch that decides whether a tool-not-installed answer surfaces
with an actionable code -- or as an opaque ``internal_error`` with a logged
incident -- had no guard. These fakes stand in for the clients so the mapping
is pinned without either tool present.
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

# (method name, backend label, kwargs beyond path). js.* -> webcrack, wasm.* -> wabt.
_METHODS: tuple[tuple[str, str], ...] = (
    ("js_deobfuscate", "webcrack"),
    ("js_beautify", "webcrack"),
    ("js_unpack_bundle", "webcrack"),
    ("wasm_wat", "wabt"),
    ("wasm_info", "wabt"),
)


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: Any = None,
    raises: BaseException | None = None,
) -> None:
    """Swap both jsre clients for a fake that returns ``result`` or raises ``raises``.

    A single fake covers both surfaces: each service method calls exactly one of
    its methods, so implementing all of them is harmless and keeps the tests
    from caring which client a given method reaches for.
    """

    class _Fake:
        def __init__(self, tool: object) -> None:
            self.tool = tool

        def _do(self, *args: object, **kwargs: object) -> Any:
            if raises is not None:
                raise raises
            return result

        deobfuscate = _do
        beautify = _do
        unpack_bundle = _do
        wat = _do
        info = _do

    monkeypatch.setattr(service_jsre, "JsClient", _Fake)
    monkeypatch.setattr(service_jsre, "WasmClient", _Fake)


@pytest.mark.parametrize(("method", "backend"), _METHODS)
def test_success_carries_data_and_backend_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, backend: str
) -> None:
    _install(monkeypatch, result={"value": method})
    service = _service(tmp_path)
    try:
        res = getattr(service, method)("bundle.js")
        assert res.ok is True
        assert res.data == {"value": method}
        assert res.meta["backend"] == backend
        assert res.error is None
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "backend"), _METHODS)
def test_jsre_error_maps_to_its_code_and_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, backend: str
) -> None:
    del backend
    err = JsReError("too_large", "input exceeds the cap", path="/tmp/big.js", limit=5)
    _install(monkeypatch, raises=err)
    service = _service(tmp_path)
    try:
        res = getattr(service, method)("bundle.js")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "too_large"
        assert res.error.details["path"] == "/tmp/big.js"
        assert res.error.details["limit"] == 5
        # JsReError carries no retryable flag, so the mapping must not invent one.
        assert res.error.retryable is False
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "backend"), _METHODS)
def test_capability_unavailable_reaches_the_caller_verbatim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, backend: str
) -> None:
    del backend
    # The tool-not-installed answer is the whole reason this line degrades
    # instead of blocking readiness; it must arrive as an actionable code.
    _install(monkeypatch, raises=JsReError("capability_unavailable", "webcrack is not installed"))
    service = _service(tmp_path)
    try:
        res = getattr(service, method)("bundle.js")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "capability_unavailable"
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "backend"), _METHODS)
def test_a_missing_file_maps_to_file_not_found_not_an_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, backend: str
) -> None:
    del backend
    # A non-JsReError still routes through the canonical dispatch, so a
    # FileNotFoundError becomes file_not_found rather than internal_error.
    _install(monkeypatch, raises=FileNotFoundError("no such file: bundle.js"))
    service = _service(tmp_path)
    try:
        res = getattr(service, method)("bundle.js")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "file_not_found"
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "backend"), _METHODS)
def test_a_value_error_maps_to_invalid_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, backend: str
) -> None:
    del backend
    _install(monkeypatch, raises=ValueError("offset must be >= 0"))
    service = _service(tmp_path)
    try:
        res = getattr(service, method)("bundle.js")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "backend"), _METHODS)
def test_an_unexpected_error_becomes_an_internal_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, backend: str
) -> None:
    del backend
    _install(monkeypatch, raises=RuntimeError("segfault in the child"))
    service = _service(tmp_path)
    try:
        res = getattr(service, method)("bundle.js")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "internal_error"
    finally:
        service.close_all()


def test_unpack_bundle_prunes_its_tree_even_when_the_client_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The finally-block pruner must run on the failure path too; here it simply
    # has to not crash when the out dir's parent exists but the unpack raised.
    _install(monkeypatch, raises=JsReError("timeout", "webcrack timed out"))
    service = _service(tmp_path)
    try:
        res = service.js_unpack_bundle("bundle.js", timeout=1.0)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "timeout"
        # The jsre root is created before the (failing) unpack, so it exists and
        # is empty rather than being left holding a partial tree.
        jsre_root = (service.settings.artifact_root.expanduser().resolve() / "jsre")
        assert jsre_root.is_dir()
    finally:
        service.close_all()


def test_as_rpc_preserves_code_message_and_copies_details() -> None:
    err = JsReError("backend_error", "boom", tool="webcrack", exit_code=2)
    rpc = service_jsre._as_rpc(err)
    assert rpc.code == "backend_error"
    assert str(rpc) == "boom"
    assert rpc.details == {"tool": "webcrack", "exit_code": 2}
    # The mapping must snapshot details, not alias them: mutating the source
    # afterwards cannot rewrite an error already handed to the caller.
    err.details["tool"] = "mutated"
    assert rpc.details["tool"] == "webcrack"
