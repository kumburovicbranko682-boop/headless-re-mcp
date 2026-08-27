"""service_apk's success tails and error taxonomy, driven at the service layer.

The APK line's entry guards and mid-run leak guards are pinned by the
*_closed_session tests, and the artifact-dir `..` guards by
test_web_proxy_artifact_dir_safety. But the *success* half of the line only runs
when androguard/jadx/apktool actually parse something, which the test host has
no tools for -- so the read wrappers (open/manifest/permissions/certificates/
components/native_libs/classes/methods/strings/xrefs), the _apk_call dispatcher,
and the success tails of decompile/export_sources/decode/repack/sign (which
record the backend and a timeline entry) had no unit coverage, and neither did
their ApkError->code / unexpected->internal_error mapping. Fake Apk/Jadx/Apktool
clients stand in so the service wiring is what is exercised, without the tools.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.apktool import ApktoolError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _FakeApk:
    """Stands in for ApkClient (constructed argument-less by the service)."""

    def __init__(self, *args: Any, raises: dict[str, BaseException] | None = None, **kwargs: Any):
        self._raises = raises or {}

    def _maybe_fail(self, op: str) -> None:
        exc = self._raises.get(op)
        if exc is not None:
            raise exc

    def open(self, binary: Path) -> JsonObject:
        self._maybe_fail("open")
        return {"package": "com.example.app", "version_name": "1.0"}

    def manifest(self, binary: Path) -> JsonObject:
        self._maybe_fail("manifest")
        return {"manifest": "<manifest/>"}

    def permissions(self, binary: Path) -> JsonObject:
        self._maybe_fail("permissions")
        return {"permissions": ["INTERNET"]}

    def certificates(self, binary: Path) -> JsonObject:
        self._maybe_fail("certificates")
        return {"certificates": []}

    def components(self, binary: Path) -> JsonObject:
        self._maybe_fail("components")
        return {"activities": []}

    def native_libs(self, binary: Path) -> JsonObject:
        self._maybe_fail("native_libs")
        return {"native_libs": []}

    def classes(self, binary: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        self._maybe_fail("classes")
        return {"classes": [], "offset": offset, "limit": limit}

    def methods(
        self, binary: Path, class_name: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        self._maybe_fail("methods")
        return {"methods": [], "class_name": class_name}

    def strings(self, binary: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        self._maybe_fail("strings")
        return {"strings": [], "offset": offset}

    def xrefs(self, binary: Path, method_name: str, *, limit: int = 100) -> JsonObject:
        self._maybe_fail("xrefs")
        return {"xrefs": [], "method_name": method_name}


class _FakeJadx:
    def __init__(self, *args: Any, raises: dict[str, BaseException] | None = None, **kwargs: Any):
        self._raises = raises or {}

    def _maybe_fail(self, op: str) -> None:
        exc = self._raises.get(op)
        if exc is not None:
            raise exc

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> JsonObject:
        self._maybe_fail("decompile")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "Foo.java").write_text("class Foo {}", encoding="utf-8")
        return {"class_name": class_name, "path": str(out_dir)}

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
    ) -> JsonObject:
        self._maybe_fail("export_sources")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "src.java").write_text("x", encoding="utf-8")
        return {"out_dir": str(out_dir)}


class _FakeApktool:
    def __init__(self, *, raises: dict[str, BaseException] | None = None) -> None:
        self._raises = raises or {}

    def _maybe_fail(self, op: str) -> None:
        exc = self._raises.get(op)
        if exc is not None:
            raise exc

    def decode(
        self, apk: Path, out_dir: Path, *, timeout: float = 600.0, no_resources: bool = False
    ) -> JsonObject:
        self._maybe_fail("decode")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("x", encoding="utf-8")
        return {"decoded_dir": str(out_dir)}

    def build(self, source: Path, out_apk: Path, *, timeout: float = 600.0) -> JsonObject:
        self._maybe_fail("build")
        out_apk.write_bytes(b"PK\x03\x04")
        return {"apk": str(out_apk)}

    def sign(
        self,
        source: Path,
        out_apk: Path,
        *,
        keystore: Path | None = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> JsonObject:
        self._maybe_fail("sign")
        out_apk.write_bytes(b"PK\x03\x04signed")
        return {"signed": str(out_apk)}


def _apk_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk_raises: dict[str, BaseException] | None = None,
    jadx_raises: dict[str, BaseException] | None = None,
    apktool_raises: dict[str, BaseException] | None = None,
) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.ApkClient",
        lambda *a, **k: _FakeApk(raises=apk_raises),
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient",
        lambda *a, **k: _FakeJadx(raises=jadx_raises),
    )
    service._apktool_client = lambda: _FakeApktool(raises=apktool_raises)  # type: ignore[method-assign]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


def _timeline(service: AnalysisService, session_id: str, name: str) -> list[JsonObject]:
    page = service.repository.list_timeline(session_id)
    return [item for item in page["events"] if item.get("event") == name]


# (service method, backend op it drives, extra positional args to the method)
_READS = [
    ("apk_open", "open", ()),
    ("apk_manifest", "manifest", ()),
    ("apk_permissions", "permissions", ()),
    ("apk_certificates", "certificates", ()),
    ("apk_components", "components", ()),
    ("apk_native_libs", "native_libs", ()),
    ("apk_classes", "classes", ()),
    ("apk_methods", "methods", ("Lcom/example/Foo;",)),
    ("apk_strings", "strings", ()),
    ("apk_xrefs", "xrefs", ("onCreate",)),
]


@pytest.mark.parametrize(("method", "op", "extra"), _READS)
def test_read_wraps_with_session_and_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, op: str, extra: tuple
) -> None:
    del op
    service, session_id = _apk_session(tmp_path, monkeypatch)
    try:
        result = getattr(service, method)(session_id, *extra)
        assert result.ok is True, result.error
        assert result.meta.get("session_id") == session_id
        assert result.meta.get("backend") == "apk"
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "op", "extra"), _READS)
def test_read_maps_an_apk_error_to_its_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, op: str, extra: tuple
) -> None:
    service, session_id = _apk_session(
        tmp_path, monkeypatch, apk_raises={op: ApkError("backend_error", f"{op} failed")}
    )
    try:
        result = getattr(service, method)(session_id, *extra)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "op", "extra"), _READS)
def test_read_fails_closed_on_an_unexpected_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, op: str, extra: tuple
) -> None:
    service, session_id = _apk_session(
        tmp_path, monkeypatch, apk_raises={op: RuntimeError(f"{op} crashed")}
    )
    try:
        result = getattr(service, method)(session_id, *extra)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_apk_open_records_backend_and_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(tmp_path, monkeypatch)
    try:
        result = service.apk_open(session_id)
        assert result.ok is True, result.error
        assert result.data is not None and result.data["package"] == "com.example.app"
        assert len(_timeline(service, session_id, "apk.open")) == 1
    finally:
        service.close_all()


def test_apk_decompile_success_records_its_tree_and_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(tmp_path, monkeypatch)
    try:
        result = service.apk_decompile(session_id, "Lcom/example/Foo;")
        assert result.ok is True, result.error
        assert len(_timeline(service, session_id, "apk.decompile")) == 1
    finally:
        service.close_all()


def test_apk_decompile_maps_a_jadx_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(
        tmp_path, monkeypatch, jadx_raises={"decompile": JadxError("backend_error", "jadx blew up")}
    )
    try:
        result = service.apk_decompile(session_id, "Lcom/example/Foo;")
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_export_sources_success_records_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(tmp_path, monkeypatch)
    try:
        result = service.apk_export_sources(session_id)
        assert result.ok is True, result.error
        assert len(_timeline(service, session_id, "apk.export_sources")) == 1
    finally:
        service.close_all()


def test_apk_decode_success_records_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(tmp_path, monkeypatch)
    try:
        result = service.apk_decode(session_id)
        assert result.ok is True, result.error
        assert len(_timeline(service, session_id, "apk.decode")) == 1
    finally:
        service.close_all()


def test_apk_decode_maps_an_apktool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(
        tmp_path, monkeypatch, apktool_raises={"decode": ApktoolError("backend_error", "boom")}
    )
    try:
        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apktool_client_is_constructed_from_the_configured_tool_paths(tmp_path: Path) -> None:
    """The real _apktool_client (every other test stubs it out) wires the
    apktool/apksigner settings into an ApktoolClient without needing the tools."""
    from headless_re_mcp.backends.apktool import ApktoolClient

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        assert isinstance(service._apktool_client(), ApktoolClient)
    finally:
        service.close_all()


def test_apk_repack_and_sign_success_record_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_session(tmp_path, monkeypatch)
    try:
        # A decode first so repack's default decoded_dir exists in the tree.
        assert service.apk_decode(session_id).ok
        repacked = service.apk_repack(session_id)
        assert repacked.ok is True, repacked.error
        assert len(_timeline(service, session_id, "apk.repack")) == 1

        signed = service.apk_sign(session_id)
        assert signed.ok is True, signed.error
        assert len(_timeline(service, session_id, "apk.sign")) == 1
    finally:
        service.close_all()
