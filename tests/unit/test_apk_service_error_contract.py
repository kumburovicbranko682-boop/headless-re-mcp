"""Service-layer contract for the apk.* static-analysis surface.

The test_apk_*_fields.py files stub ApkClient's _apk/_parsed and pin each tool's
happy-path *shape*; the client's own guards live in test_apk_client.py. What
neither touches is the service methods in service_apk.py that wrap those tools:
resolve the APK-target session, call the backend, and either record a
backend/timeline entry and shape a Result, or map a structured backend error
onto the RPC envelope. Those success-bookkeeping and error-mapping paths were
uncovered.

These pin them device-free. A real APK-target session is created (so the
state/target guards run for real), but the three tool clients are replaced with
fakes -- androguard/jadx/apktool are never invoked -- so the fakes decide
whether a call returns data or raises a structured error, and the test asserts
the service either records the work and returns ok, or fails with the backend's
own code intact (ApkError/JadxError/ApktoolError all flow through _as_rpc). The
pure _refuse_oversized_tree cap-guard is pinned directly.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_apk
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def _service(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, str(created.data["session"]["id"])


# --- _refuse_oversized_tree (pure cap guard) ------------------------------


def test_refuse_oversized_tree_ignores_a_missing_path(tmp_path: Path) -> None:
    # No raise, no crash: nothing to measure.
    service_apk._refuse_oversized_tree(tmp_path / "gone", kind="jadx", error_type=ApkError)


def test_refuse_oversized_tree_degrades_on_a_stat_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If the size cannot be read, the guard yields rather than deleting a tree
    # it could not measure.
    target = tmp_path / "tree"
    target.mkdir()
    monkeypatch.setattr(service_apk, "_dir_size", _raiser(OSError("stat failed")))
    service_apk._refuse_oversized_tree(target, kind="jadx", error_type=ApkError)
    assert target.exists()


def test_refuse_oversized_tree_deletes_and_raises_for_an_over_cap_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "big.bin").write_bytes(b"0123456789")
    with pytest.raises(ApkError) as caught:
        service_apk._refuse_oversized_tree(tree, kind="jadx", error_type=ApkError)
    assert caught.value.code == "too_large"
    assert not tree.exists()  # the over-cap tree was reclaimed


def test_refuse_oversized_tree_deletes_and_raises_for_an_over_cap_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
    blob = tmp_path / "artifact.bin"
    blob.write_bytes(b"0123456789")
    with pytest.raises(ApktoolError) as caught:
        service_apk._refuse_oversized_tree(blob, kind="apktool", error_type=ApktoolError)
    assert caught.value.code == "too_large"
    assert not blob.exists()


def _raiser(exc: BaseException) -> Any:
    def f(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise exc

    return f


# --- fake tool clients ----------------------------------------------------


class _FakeApk:
    """Stands in for ApkClient(): every reader returns data or raises."""

    def __init__(self, error: BaseException | None = None) -> None:
        self._error = error

    def _out(self, data: dict[str, Any]) -> dict[str, Any]:
        if self._error is not None:
            raise self._error
        return data

    def open(self, binary: Path) -> dict[str, Any]:
        del binary
        return self._out({"package": "com.example.app"})

    def classes(self, binary: Path, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        del binary, offset, limit
        return self._out({"classes": ["com.example.Main"], "count": 1})

    def methods(
        self, binary: Path, class_name: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        del binary, offset, limit
        return self._out({"class_name": class_name, "methods": []})

    def strings(self, binary: Path, *, offset: int = 0, limit: int = 200) -> dict[str, Any]:
        del binary, offset, limit
        return self._out({"strings": ["hi"], "count": 1})

    def xrefs(self, binary: Path, method_name: str, *, limit: int = 100) -> dict[str, Any]:
        del binary, limit
        return self._out({"method": method_name, "xrefs": []})

    def manifest(self, binary: Path) -> dict[str, Any]:
        del binary
        return self._out({"package": "com.example.app"})

    def permissions(self, binary: Path) -> dict[str, Any]:
        del binary
        return self._out({"permissions": []})

    def certificates(self, binary: Path) -> dict[str, Any]:
        del binary
        return self._out({"certificates": []})

    def components(self, binary: Path) -> dict[str, Any]:
        del binary
        return self._out({"components": []})

    def native_libs(self, binary: Path) -> dict[str, Any]:
        del binary
        return self._out({"native_libs": []})


def _install_fake_apk(monkeypatch: pytest.MonkeyPatch, error: BaseException | None = None) -> None:
    monkeypatch.setattr(service_apk, "ApkClient", lambda: _FakeApk(error))


class _FakeJadx:
    def __init__(self, settings: Any = None, *, error: BaseException | None = None) -> None:
        del settings
        self._error = error

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> dict[str, Any]:
        del binary, timeout
        if self._error is not None:
            raise self._error
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "C.java").write_text("class C {}", encoding="utf-8")
        return {"class_name": class_name, "path": str(out_dir)}

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
    ) -> dict[str, Any]:
        del binary, timeout, no_imports
        if self._error is not None:
            raise self._error
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"exported": True, "path": str(out_dir)}


class _FakeApktool:
    def __init__(self, *, error: BaseException | None = None) -> None:
        self._error = error

    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float = 600.0, no_resources: bool = False
    ) -> dict[str, Any]:
        del binary, timeout, no_resources
        if self._error is not None:
            raise self._error
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"decoded": str(out_dir)}


# --- apk_open --------------------------------------------------------------


def test_apk_open_records_the_backend_and_returns_the_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_apk(monkeypatch)
    service, session_id = _service(tmp_path)
    try:
        result = service.apk_open(session_id)
        assert result.ok and result.data is not None, result.error
        assert result.data["package"] == "com.example.app"
    finally:
        service.close_all()


def test_apk_open_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_apk(monkeypatch, ApkError("backend_error", "corrupt apk"))
    service, session_id = _service(tmp_path)
    try:
        result = service.apk_open(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# --- reader methods: success and error mapping ----------------------------


@pytest.mark.parametrize(
    ("call", "key"),
    [
        (lambda s, sid: s.apk_classes(sid), "classes"),
        (lambda s, sid: s.apk_methods(sid, "com.example.Main"), "methods"),
        (lambda s, sid: s.apk_strings(sid), "strings"),
        (lambda s, sid: s.apk_xrefs(sid, "onCreate"), "xrefs"),
        (lambda s, sid: s.apk_manifest(sid), "package"),
        (lambda s, sid: s.apk_permissions(sid), "permissions"),
        (lambda s, sid: s.apk_certificates(sid), "certificates"),
        (lambda s, sid: s.apk_components(sid), "components"),
        (lambda s, sid: s.apk_native_libs(sid), "native_libs"),
    ],
)
def test_reader_methods_return_backend_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    call: Any,
    key: str,
) -> None:
    _install_fake_apk(monkeypatch)
    service, session_id = _service(tmp_path)
    try:
        result = call(service, session_id)
        assert result.ok and result.data is not None, result.error
        assert key in result.data
    finally:
        service.close_all()


@pytest.mark.parametrize(
    "call",
    [
        lambda s, sid: s.apk_classes(sid),
        lambda s, sid: s.apk_methods(sid, "com.example.Main"),
        lambda s, sid: s.apk_strings(sid),
        lambda s, sid: s.apk_xrefs(sid, "onCreate"),
        lambda s, sid: s.apk_manifest(sid),
        lambda s, sid: s.apk_permissions(sid),
        lambda s, sid: s.apk_certificates(sid),
        lambda s, sid: s.apk_components(sid),
        lambda s, sid: s.apk_native_libs(sid),
    ],
)
def test_reader_methods_map_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: Any
) -> None:
    _install_fake_apk(monkeypatch, ApkError("backend_error", "parse blew up"))
    service, session_id = _service(tmp_path)
    try:
        result = call(service, session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    "call",
    [
        lambda s, sid: s.apk_classes(sid),
        lambda s, sid: s.apk_methods(sid, "com.example.Main"),
        lambda s, sid: s.apk_strings(sid),
        lambda s, sid: s.apk_xrefs(sid, "onCreate"),
        lambda s, sid: s.apk_manifest(sid),
    ],
)
def test_reader_methods_map_an_unexpected_error_to_internal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: Any
) -> None:
    # A non-structured exception (not ApkError) falls to the generic branch and
    # becomes internal_error with a recorded incident, rather than escaping.
    _install_fake_apk(monkeypatch, RuntimeError("androguard imploded"))
    service, session_id = _service(tmp_path)
    try:
        result = call(service, session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


# --- apk_decompile / apk_export_sources -----------------------------------


def test_apk_decompile_records_the_output_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
    service, session_id = _service(tmp_path)
    try:
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok and result.data is not None, result.error
        assert result.data["class_name"] == "com.example.Main"
    finally:
        service.close_all()


def test_apk_decompile_maps_a_jadx_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        service_apk, "JadxClient", lambda settings: _FakeJadx(error=JadxError("timeout", "slow"))
    )
    service, session_id = _service(tmp_path)
    try:
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None and result.error.code == "timeout"
    finally:
        service.close_all()


def test_apk_export_sources_records_the_output_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
    service, session_id = _service(tmp_path)
    try:
        result = service.apk_export_sources(session_id)
        assert result.ok and result.data is not None, result.error
        assert result.data["exported"] is True
    finally:
        service.close_all()


def test_apk_export_sources_maps_a_jadx_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        service_apk,
        "JadxClient",
        lambda settings: _FakeJadx(error=JadxError("backend_error", "no jre")),
    )
    service, session_id = _service(tmp_path)
    try:
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# --- apk_decode / _apktool_client -----------------------------------------


def test_apktool_client_builds_the_real_wrapper(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        assert isinstance(service._apktool_client(), ApktoolClient)
    finally:
        service.close_all()


def test_apk_decode_records_the_decoded_tree(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    service._apktool_client = lambda: _FakeApktool()  # type: ignore[method-assign]
    try:
        result = service.apk_decode(session_id)
        assert result.ok and result.data is not None, result.error
        assert "decoded" in result.data
    finally:
        service.close_all()


def test_apk_decode_maps_an_apktool_error(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    service._apktool_client = lambda: _FakeApktool(  # type: ignore[method-assign]
        error=ApktoolError("capability_unavailable", "apktool missing")
    )
    try:
        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "capability_unavailable"
    finally:
        service.close_all()
