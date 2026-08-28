"""js.*/wasm.* service methods must wrap the backend payload in the right envelope.

The backend clients are exercised directly (test_js_wasm_fields) and the absent-
backend path is pinned (test_nonpe_degradation_contract), but nothing drove the
JsReAnalysisMixin methods on a *successful* backend. Two service-layer contracts
were therefore unpinned:

* the backend label -- js.deobfuscate / js.beautify report ``webcrack`` and
  wasm.wat / wasm.info report ``wabt`` -- which is how a caller (and the audit
  trail) attributes the reply to a tool, and
* the arm that contains an unexpected backend exception as a failure envelope
  rather than letting it escape as a raised exception to the RPC layer.

These drive the real AnalysisService with dummy tool paths and a stubbed
``run_bounded`` so the whole service -> client path runs without Node or wabt.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_jsre import prune_jsre_unpack_dirs


def _service(tmp_path: Path) -> AnalysisService:
    """A service whose webcrack and wabt paths resolve to (empty) dummy tools.

    The wabt setting names a directory, and _resolve_wabt_tool looks inside it
    for ``wasm2wat``/``wasm-objdump`` with a ``.exe`` suffix on Windows (that is
    how a real wabt install ships). Extensionless stubs therefore resolved on
    Linux but not on the Windows quality runner, where the two wasm.* tests
    failed with capability_unavailable while Linux stayed green -- the same
    optional-tool CI-honesty gap the apk/proxy suites had, only platform-hidden.
    Name the stubs with the platform's executable suffix, the way the sibling
    test_js_wasm_fields helpers already do, so both runners resolve them.
    """
    exe = ".exe" if os.name == "nt" else ""
    webcrack = tmp_path / f"webcrack{exe}"
    webcrack.write_bytes(b"")
    wabt = tmp_path / "wabt"
    wabt.mkdir()
    (wabt / f"wasm2wat{exe}").write_bytes(b"")
    (wabt / f"wasm-objdump{exe}").write_bytes(b"")
    settings = replace(
        Settings.load(),
        webcrack=webcrack,
        wabt=wabt,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _stub_run(stdout: bytes) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, stdout, b"")

    return fake_run


def _wasm_input(tmp_path: Path) -> Path:
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    return module


def test_js_deobfuscate_wraps_the_payload_under_the_webcrack_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "run_bounded", _stub_run(b"var x = 1;"))
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    service = _service(tmp_path)
    try:
        result = service.js_deobfuscate(str(src))
    finally:
        service.close_all()

    assert result.ok, result.error
    assert result.meta.get("backend") == "webcrack"
    assert result.data is not None
    assert result.data["code"] == "var x = 1;"


def test_js_beautify_wraps_the_payload_under_the_webcrack_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "run_bounded", _stub_run(b"const y = 2;"))
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    service = _service(tmp_path)
    try:
        result = service.js_beautify(str(src))
    finally:
        service.close_all()

    assert result.ok, result.error
    assert result.meta.get("backend") == "webcrack"
    assert result.data is not None
    assert result.data["code"] == "const y = 2;"


def test_wasm_wat_wraps_the_payload_under_the_wabt_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "run_bounded", _stub_run(b"(module)"))
    service = _service(tmp_path)
    try:
        result = service.wasm_wat(str(_wasm_input(tmp_path)))
    finally:
        service.close_all()

    assert result.ok, result.error
    assert result.meta.get("backend") == "wabt"
    assert result.data is not None
    assert result.data["wat"] == "(module)"


def test_wasm_info_wraps_the_payload_under_the_wabt_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = b"Contents of section .text:\n"
    monkeypatch.setattr(jsre_client, "run_bounded", _stub_run(dump))
    service = _service(tmp_path)
    try:
        result = service.wasm_info(str(_wasm_input(tmp_path)))
    finally:
        service.close_all()

    assert result.ok, result.error
    assert result.meta.get("backend") == "wabt"
    assert result.data is not None
    assert result.data["objdump"] == dump.decode("utf-8")


def test_an_unexpected_backend_exception_is_contained_as_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-JsReError escaping the client is an envelope, not a raised exception.

    _run only remaps TimedOut/OSError, so a bug that raised anything else would,
    without the service's BaseException arm, propagate to the RPC layer as an
    unhandled crash. It must instead become an internal_error envelope.
    """

    def boom(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        raise RuntimeError("unexpected webcrack crash")

    monkeypatch.setattr(jsre_client, "run_bounded", boom)
    src = tmp_path / "app.js"
    src.write_text("x", encoding="utf-8")
    service = _service(tmp_path)
    try:
        result = service.js_deobfuscate(str(src))
    finally:
        service.close_all()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


def test_prune_jsre_unpack_dirs_is_a_safe_no_op_when_the_root_is_gone(
    tmp_path: Path,
) -> None:
    """Retention runs in js.unpack_bundle's finally; it must never raise.

    If the jsre artifact dir vanished (a concurrent sweep, a wiped tmpfs) the
    prune would iterdir a missing path. Swallowing that OSError is what keeps the
    finally from replacing a good unpack result with a spurious crash.
    """
    prune_jsre_unpack_dirs(tmp_path / "does-not-exist")
