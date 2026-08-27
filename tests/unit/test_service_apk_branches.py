"""Branch coverage for the APK static-analysis service mixin.

androguard runs in-process; jadx and apktool are bounded subprocesses into a
per-session artifact tree. Each call wraps its backend into a Result (backend
error -> structured failure, unexpected exception still captured), refuses a
tree that would blow the unregistered-capture cap, and re-checks session state
after a long subprocess so a close arriving mid-run tears the tree down rather
than recording a dead session as owning it. These fakes drive those branches
without the real tools; the live gate pins them.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_apk
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_apk import _refuse_oversized_tree

MP = pytest.MonkeyPatch


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _FakeApk:
    def open(self, binary: Path) -> dict[str, Any]:
        return {"package": "com.example.app", "version_name": "1.0"}

    def classes(self, binary: Path, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        return {"classes": [], "total": 0}

    def methods(
        self, binary: Path, class_name: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        return {"methods": [], "class_name": class_name}

    def strings(self, binary: Path, *, offset: int = 0, limit: int = 200) -> dict[str, Any]:
        return {"strings": []}

    def xrefs(self, binary: Path, method_name: str, *, limit: int = 100) -> dict[str, Any]:
        return {"xrefs": [], "method": method_name}

    def manifest(self, binary: Path) -> dict[str, Any]:
        return {"manifest": "<manifest/>"}

    def permissions(self, binary: Path) -> dict[str, Any]:
        return {"permissions": []}

    def certificates(self, binary: Path) -> dict[str, Any]:
        return {"certificates": []}

    def components(self, binary: Path) -> dict[str, Any]:
        return {"components": []}

    def native_libs(self, binary: Path) -> dict[str, Any]:
        return {"native_libs": []}

    @classmethod
    def release(cls, binary: Path) -> None:
        return None


class _FakeJadx:
    def __init__(self, _exe: Any = None) -> None:
        pass

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> dict[str, Any]:
        (out_dir / "sources").mkdir(parents=True, exist_ok=True)
        (out_dir / "sources" / "Foo.java").write_text("class Foo {}")
        return {"class_name": class_name, "source": "class Foo {}"}

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
    ) -> dict[str, Any]:
        (out_dir / "sources").mkdir(parents=True, exist_ok=True)
        return {"output_dir": str(out_dir), "java_file_count": 0}


class _FakeApktool:
    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float = 600.0, no_resources: bool = False
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("m")
        return {"decoded_dir": str(out_dir), "smali_dirs": ["smali"]}

    def build(self, source: Path, out_apk: Path, *, timeout: float = 600.0) -> dict[str, Any]:
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        _write_apk(out_apk)
        return {"apk": str(out_apk), "signed": False}

    def sign(
        self,
        source: Path,
        out_apk: Path,
        *,
        keystore: Any = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        _write_apk(out_apk)
        return {"apk": str(out_apk), "signed": True}


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    svc._apk_path = _write_apk(tmp_path / "app.apk")  # type: ignore[attr-defined]
    try:
        yield svc
    finally:
        svc.close_all()


def _session(service: AnalysisService) -> str:
    created = service.create_session(str(service._apk_path), target="apk")  # type: ignore[attr-defined]
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _force_state(service: AnalysisService, session_id: str, state: SessionState) -> None:
    service.registry._sessions[session_id].state = state


class TestRefuseOversizedTree:
    def test_ignores_a_missing_path(self, tmp_path: Path) -> None:
        _refuse_oversized_tree(tmp_path / "nope", kind="jadx", error_type=JadxError)  # no raise

    def test_survives_a_sizing_error(self, tmp_path: Path, monkeypatch: MP) -> None:
        target = tmp_path / "tree"
        target.mkdir()
        monkeypatch.setattr(
            service_apk, "_dir_size", lambda p: (_ for _ in ()).throw(OSError("boom"))
        )
        _refuse_oversized_tree(target, kind="jadx", error_type=JadxError)  # no raise

    def test_removes_and_refuses_an_oversized_dir(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 1)
        target = tmp_path / "tree"
        target.mkdir()
        (target / "big.txt").write_text("more than one byte")
        with pytest.raises(JadxError) as excinfo:
            _refuse_oversized_tree(target, kind="jadx", error_type=JadxError)
        assert excinfo.value.code == "too_large"
        assert not target.exists()

    def test_removes_and_refuses_an_oversized_file(self, tmp_path: Path, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 1)
        target = tmp_path / "blob.apk"
        target.write_text("more than one byte")
        with pytest.raises(ApkError) as excinfo:
            _refuse_oversized_tree(target, kind="apktool", error_type=ApkError)
        assert excinfo.value.code == "too_large"
        assert not target.exists()


class TestAndroguardCalls:
    def test_apk_open_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        sid = _session(service)
        result = service.apk_open(sid)
        assert result.ok is True and result.data is not None
        assert result.data["package"] == "com.example.app"

    def test_apk_open_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FakeApk):
            def open(self, binary: Path) -> dict[str, Any]:
                raise ApkError("backend_error", "androguard blew up")

        monkeypatch.setattr(service_apk, "ApkClient", _Err)
        sid = _session(service)
        result = service.apk_open(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_classes_methods_strings_xrefs_success(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        sid = _session(service)
        assert service.apk_classes(sid).ok is True
        assert service.apk_methods(sid, "com.x.Y").ok is True
        assert service.apk_strings(sid).ok is True
        assert service.apk_xrefs(sid, "doThing").ok is True

    def test_classes_methods_strings_xrefs_map_errors(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Err(_FakeApk):
            def classes(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise ApkError("invalid_params", "bad offset")

            def methods(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise ApkError("not_found", "no class")

            def strings(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise ApkError("backend_error", "dex parse")

            def xrefs(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise ApkError("not_found", "no method")

        monkeypatch.setattr(service_apk, "ApkClient", _Err)
        sid = _session(service)
        assert service.apk_classes(sid).error.code == "invalid_params"  # type: ignore[union-attr]
        assert service.apk_methods(sid, "c").error.code == "not_found"  # type: ignore[union-attr]
        assert service.apk_strings(sid).error.code == "backend_error"  # type: ignore[union-attr]
        assert service.apk_xrefs(sid, "m").error.code == "not_found"  # type: ignore[union-attr]

    def test_apk_call_success_and_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        sid = _session(service)
        for method in (
            service.apk_manifest,
            service.apk_permissions,
            service.apk_certificates,
            service.apk_components,
            service.apk_native_libs,
        ):
            assert method(sid).ok is True

        class _Err(_FakeApk):
            def manifest(self, binary: Path) -> dict[str, Any]:
                raise ApkError("backend_error", "axml parse")

        monkeypatch.setattr(service_apk, "ApkClient", _Err)
        assert service.apk_manifest(sid).ok is False


class TestJadx:
    def test_decompile_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
        sid = _session(service)
        result = service.apk_decompile(sid, "com.example.Foo")
        assert result.ok is True and result.data is not None
        assert result.data["class_name"] == "com.example.Foo"

    def test_decompile_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FakeJadx):
            def decompile(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JadxError("not_found", "decompiled class not found")

        monkeypatch.setattr(service_apk, "JadxClient", _Err)
        sid = _session(service)
        result = service.apk_decompile(sid, "com.example.Foo")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"

    def test_decompile_tears_down_on_a_mid_run_close(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _session(service)

        class _CloseMid(_FakeJadx):
            def decompile(self, binary: Path, out_dir: Path, class_name: str, **k: Any):
                (out_dir / "sources").mkdir(parents=True, exist_ok=True)
                (out_dir / "sources" / "Foo.java").write_text("class Foo {}")
                _force_state(service, sid, SessionState.CLOSED)
                return {"class_name": class_name, "source": "x"}

        monkeypatch.setattr(service_apk, "JadxClient", _CloseMid)
        result = service.apk_decompile(sid, "com.example.Foo")
        assert result.ok is False
        out_dir = service.settings.artifact_root.expanduser().resolve() / "jadx" / sid
        assert not out_dir.exists()  # tree removed rather than orphaned

    def test_decompile_mid_run_close_without_a_tree(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _session(service)

        class _CloseNoTree(_FakeJadx):
            def decompile(self, binary: Path, out_dir: Path, class_name: str, **k: Any):
                # No tree written: the mid-run teardown must skip rmtree cleanly.
                _force_state(service, sid, SessionState.CLOSED)
                return {"class_name": class_name, "source": "x"}

        monkeypatch.setattr(service_apk, "JadxClient", _CloseNoTree)
        assert service.apk_decompile(sid, "com.example.Foo").ok is False

    def test_export_sources_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
        sid = _session(service)
        result = service.apk_export_sources(sid)
        assert result.ok is True and result.data is not None
        assert "output_dir" in result.data

    def test_export_sources_tears_down_on_a_mid_run_close(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _session(service)

        class _CloseMid(_FakeJadx):
            def export_sources(self, binary: Path, out_dir: Path, **k: Any):
                (out_dir / "sources").mkdir(parents=True, exist_ok=True)
                _force_state(service, sid, SessionState.CLOSED)
                return {"output_dir": str(out_dir)}

        monkeypatch.setattr(service_apk, "JadxClient", _CloseMid)
        result = service.apk_export_sources(sid)
        assert result.ok is False
        out_dir = service.settings.artifact_root.expanduser().resolve() / "jadx" / sid
        assert not out_dir.exists()

    def test_export_sources_mid_run_close_without_a_tree(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _session(service)

        class _CloseNoTree(_FakeJadx):
            def export_sources(self, binary: Path, out_dir: Path, **k: Any):
                _force_state(service, sid, SessionState.CLOSED)
                return {"output_dir": str(out_dir)}

        monkeypatch.setattr(service_apk, "JadxClient", _CloseNoTree)
        assert service.apk_export_sources(sid).ok is False


class TestGuardsAndUnexpected:
    def test_apk_binary_refuses_a_closed_session(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        sid = _session(service)
        _force_state(service, sid, SessionState.CLOSED)
        # apk_classes goes through _apk_binary, whose own state guard fires.
        assert service.apk_classes(sid).ok is False

    def test_jadx_out_dir_rejects_a_bad_session_id(self, service: AnalysisService) -> None:
        with pytest.raises(ApkError) as excinfo:
            service._jadx_out_dir("../evil")
        assert excinfo.value.code == "invalid_params"

    def test_repack_dir_rejects_a_bad_session_id(self, service: AnalysisService) -> None:
        with pytest.raises(ApkError) as excinfo:
            service._repack_dir("../evil")
        assert excinfo.value.code == "invalid_params"

    def test_require_session_path_refuses_a_foreign_path(self, service: AnalysisService) -> None:
        with pytest.raises(ApkError) as excinfo:
            service._require_session_path("sid", Path("/etc/passwd"), what="apk_path")
        assert excinfo.value.code == "invalid_params"

    def test_apk_open_mid_run_close(self, service: AnalysisService, monkeypatch: MP) -> None:
        sid = _session(service)

        class _CloseMid(_FakeApk):
            def open(self, binary: Path) -> dict[str, Any]:
                _force_state(service, sid, SessionState.CLOSED)
                return {"package": "com.x"}

        monkeypatch.setattr(service_apk, "ApkClient", _CloseMid)
        assert service.apk_open(sid).ok is False

    def test_apk_open_captures_unexpected(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Boom(_FakeApk):
            def open(self, binary: Path) -> dict[str, Any]:
                raise RuntimeError("boom")

        monkeypatch.setattr(service_apk, "ApkClient", _Boom)
        sid = _session(service)
        assert service.apk_open(sid).ok is False

    def test_androguard_calls_capture_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Boom(_FakeApk):
            def classes(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

            def methods(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

            def strings(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

            def xrefs(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

            def manifest(self, binary: Path) -> dict[str, Any]:
                raise RuntimeError("boom")

        monkeypatch.setattr(service_apk, "ApkClient", _Boom)
        sid = _session(service)
        assert service.apk_classes(sid).ok is False
        assert service.apk_methods(sid, "c").ok is False
        assert service.apk_strings(sid).ok is False
        assert service.apk_xrefs(sid, "m").ok is False
        assert service.apk_manifest(sid).ok is False  # via _apk_call

    def test_export_sources_maps_backend_error(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Err(_FakeJadx):
            def export_sources(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise JadxError("backend_error", "jadx produced no sources")

        monkeypatch.setattr(service_apk, "JadxClient", _Err)
        sid = _session(service)
        result = service.apk_export_sources(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"


class TestApktool:
    def test_decode_success(self, service: AnalysisService) -> None:
        service._apktool_client = lambda: _FakeApktool()  # type: ignore[assignment]
        sid = _session(service)
        result = service.apk_decode(sid)
        assert result.ok is True and result.data is not None
        assert result.data["smali_dirs"] == ["smali"]

    def test_decode_maps_backend_error_via_real_client(self, service: AnalysisService) -> None:
        # settings.apktool is unset, so the real client reports it unavailable;
        # this also exercises the _apktool_client() constructor.
        sid = _session(service)
        result = service.apk_decode(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "capability_unavailable"

    def test_repack_success(self, service: AnalysisService) -> None:
        service._apktool_client = lambda: _FakeApktool()  # type: ignore[assignment]
        sid = _session(service)
        # A decoded tree in the session area for the default source path.
        root = service.settings.artifact_root.expanduser().resolve() / "apktool" / sid
        (root / "decoded").mkdir(parents=True, exist_ok=True)
        result = service.apk_repack(sid)
        assert result.ok is True and result.data is not None
        assert result.data["signed"] is False

    def test_sign_success(self, service: AnalysisService) -> None:
        service._apktool_client = lambda: _FakeApktool()  # type: ignore[assignment]
        sid = _session(service)
        result = service.apk_sign(sid)
        assert result.ok is True and result.data is not None
        assert result.data["signed"] is True

    def test_repack_maps_backend_error(self, service: AnalysisService) -> None:
        from headless_re_mcp.backends.apktool import ApktoolError

        class _Err(_FakeApktool):
            def build(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise ApktoolError("backend_error", "apktool build failed")

        service._apktool_client = lambda: _Err()  # type: ignore[assignment]
        sid = _session(service)
        root = service.settings.artifact_root.expanduser().resolve() / "apktool" / sid
        (root / "decoded").mkdir(parents=True, exist_ok=True)
        result = service.apk_repack(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_sign_maps_backend_error(self, service: AnalysisService) -> None:
        from headless_re_mcp.backends.apktool import ApktoolError

        class _Err(_FakeApktool):
            def sign(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise ApktoolError("capability_unavailable", "apksigner is not configured")

        service._apktool_client = lambda: _Err()  # type: ignore[assignment]
        sid = _session(service)
        result = service.apk_sign(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "capability_unavailable"
