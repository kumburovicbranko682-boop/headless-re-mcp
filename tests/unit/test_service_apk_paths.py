"""APK static-analysis service-layer paths (ApkAnalysisMixin).

The apk/jadx/apktool backends are exercised directly elsewhere; here the service
orchestration is pinned: the androguard read ops and their _apk_call fan-out, the
jadx decompile/export with the oversized-tree refusal, the apktool decode/repack/
sign flow, and the ApkError/JadxError/ApktoolError -> structured-envelope mapping.
Clients are constructed inline by the mixin, so each is monkeypatched at the
module boundary.
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
from headless_re_mcp.core import service_apk
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _apk_session(service: AnalysisService, tmp_path: Path) -> str:
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", b"dex\n")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


class _FakeApk:
    def __init__(self) -> None:
        self.raise_on: dict[str, BaseException] = {}

    def _maybe(self, op: str) -> None:
        exc = self.raise_on.get(op)
        if exc is not None:
            raise exc

    def open(self, binary: Path) -> dict[str, Any]:
        self._maybe("open")
        return {"package": "com.example", "min_sdk": 21}

    def manifest(self, binary: Path) -> dict[str, Any]:
        self._maybe("manifest")
        return {"package": "com.example"}

    def permissions(self, binary: Path) -> dict[str, Any]:
        self._maybe("permissions")
        return {"permissions": []}

    def certificates(self, binary: Path) -> dict[str, Any]:
        self._maybe("certificates")
        return {"certificates": []}

    def components(self, binary: Path) -> dict[str, Any]:
        self._maybe("components")
        return {"activities": []}

    def native_libs(self, binary: Path) -> dict[str, Any]:
        self._maybe("native_libs")
        return {"native_libs": []}

    def classes(self, binary: Path, **kw: Any) -> dict[str, Any]:
        self._maybe("classes")
        return {"classes": [], "count": 0, "total": 0, "has_more": False}

    def methods(self, binary: Path, class_name: str, **kw: Any) -> dict[str, Any]:
        self._maybe("methods")
        return {"methods": [], "count": 0, "class_name": class_name}

    def strings(self, binary: Path, **kw: Any) -> dict[str, Any]:
        self._maybe("strings")
        return {"strings": [], "count": 0}

    def xrefs(self, binary: Path, method_name: str, **kw: Any) -> dict[str, Any]:
        self._maybe("xrefs")
        return {"xrefs": [], "count": 0}


class _FakeJadx:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc

    def decompile(self, binary: Path, out_dir: Path, class_name: str, **kw: Any) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"class_name": class_name, "path": str(out_dir), "files": 1}

    def export_sources(self, binary: Path, out_dir: Path, **kw: Any) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(out_dir), "files": 3}


class _FakeApktool:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc

    def decode(self, binary: Path, out_dir: Path, **kw: Any) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(out_dir), "manifest": True}

    def build(self, source: Path, out_apk: Path, **kw: Any) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(out_apk), "built": True}

    def sign(self, source: Path, out_apk: Path, **kw: Any) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"path": str(out_apk), "verified": True}


def _use_apk(monkeypatch: pytest.MonkeyPatch, fake: _FakeApk) -> None:
    monkeypatch.setattr(service_apk, "ApkClient", lambda *a, **k: fake)


def _use_jadx(monkeypatch: pytest.MonkeyPatch, fake: _FakeJadx) -> None:
    monkeypatch.setattr(service_apk, "JadxClient", lambda *a, **k: fake)


def _use_apktool(monkeypatch: pytest.MonkeyPatch, fake: _FakeApktool) -> None:
    monkeypatch.setattr(service_apk, "ApktoolClient", lambda *a, **k: fake)


# ---------------------------------------------------------------------------
# apk_open + androguard read ops (_apk_call fan-out)
# ---------------------------------------------------------------------------
def test_apk_open_records_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    try:
        sid = _apk_session(service, tmp_path)
        result = service.apk_open(sid)
        assert result.ok, result.error
        assert result.data is not None and result.data["package"] == "com.example"
        assert result.meta["backend"] == "apk"
    finally:
        service.close_all()


def test_apk_open_maps_apk_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    fake = _FakeApk()
    fake.raise_on["open"] = ApkError("backend_error", "androguard choked")
    _use_apk(monkeypatch, fake)
    try:
        sid = _apk_session(service, tmp_path)
        result = service.apk_open(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_open_refused_on_closed_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    try:
        sid = _apk_session(service, tmp_path)
        assert service.close_session(sid).ok
        result = service.apk_open(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_apk_read_ops_all_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    try:
        sid = _apk_session(service, tmp_path)
        assert service.apk_manifest(sid).ok
        assert service.apk_permissions(sid).ok
        assert service.apk_certificates(sid).ok
        assert service.apk_components(sid).ok
        assert service.apk_native_libs(sid).ok
        assert service.apk_classes(sid, offset=0, limit=10).ok
        assert service.apk_methods(sid, "com.example.Main", offset=0, limit=10).ok
        assert service.apk_strings(sid, offset=0, limit=20).ok
        assert service.apk_xrefs(sid, "onCreate", limit=10).ok
    finally:
        service.close_all()


def test_apk_call_maps_apk_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    fake = _FakeApk()
    fake.raise_on["manifest"] = ApkError("not_found", "no manifest")
    _use_apk(monkeypatch, fake)
    try:
        sid = _apk_session(service, tmp_path)
        result = service.apk_manifest(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


def test_apk_paged_ops_map_apk_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    fake = _FakeApk()
    fake.raise_on["classes"] = ApkError("invalid_params", "bad offset")
    fake.raise_on["methods"] = ApkError("not_found", "no such class")
    fake.raise_on["strings"] = ApkError("backend_error", "dex broken")
    fake.raise_on["xrefs"] = ApkError("not_found", "no such method")
    _use_apk(monkeypatch, fake)
    try:
        sid = _apk_session(service, tmp_path)
        assert service.apk_classes(sid).error.code == "invalid_params"  # type: ignore[union-attr]
        assert service.apk_methods(sid, "C").error.code == "not_found"  # type: ignore[union-attr]
        assert service.apk_strings(sid).error.code == "backend_error"  # type: ignore[union-attr]
        assert service.apk_xrefs(sid, "m").error.code == "not_found"  # type: ignore[union-attr]
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# jadx decompile / export_sources
# ---------------------------------------------------------------------------
def test_apk_decompile_success_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    _use_jadx(monkeypatch, _FakeJadx())
    try:
        sid = _apk_session(service, tmp_path)
        ok = service.apk_decompile(sid, "com.example.Main")
        assert ok.ok, ok.error
        assert ok.data is not None and ok.data["class_name"] == "com.example.Main"

        _use_jadx(monkeypatch, _FakeJadx(JadxError("timeout", "jadx stalled")))
        failed = service.apk_decompile(sid, "com.example.Main")
        assert failed.ok is False
        assert failed.error is not None and failed.error.code == "timeout"
    finally:
        service.close_all()


def test_apk_export_sources_success_and_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    _use_jadx(monkeypatch, _FakeJadx())
    try:
        sid = _apk_session(service, tmp_path)
        ok = service.apk_export_sources(sid)
        assert ok.ok, ok.error

        _use_jadx(monkeypatch, _FakeJadx(JadxError("backend_error", "jadx crashed")))
        failed = service.apk_export_sources(sid)
        assert failed.ok is False
        assert failed.error is not None and failed.error.code == "backend_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# apktool decode / repack / sign
# ---------------------------------------------------------------------------
def test_apk_decode_success_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    _use_apktool(monkeypatch, _FakeApktool())
    try:
        sid = _apk_session(service, tmp_path)
        ok = service.apk_decode(sid)
        assert ok.ok, ok.error

        _use_apktool(monkeypatch, _FakeApktool(ApktoolError("backend_error", "decode failed")))
        failed = service.apk_decode(sid)
        assert failed.ok is False
        assert failed.error is not None and failed.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_repack_success_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    _use_apktool(monkeypatch, _FakeApktool())
    try:
        sid = _apk_session(service, tmp_path)
        ok = service.apk_repack(sid)
        assert ok.ok, ok.error

        _use_apktool(monkeypatch, _FakeApktool(ApktoolError("invalid_params", "not a decode tree")))
        failed = service.apk_repack(sid)
        assert failed.ok is False
        assert failed.error is not None and failed.error.code == "invalid_params"
    finally:
        service.close_all()


def test_apk_sign_success_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    _use_apktool(monkeypatch, _FakeApktool())
    try:
        sid = _apk_session(service, tmp_path)
        ok = service.apk_sign(sid)
        assert ok.ok, ok.error

        _use_apktool(
            monkeypatch, _FakeApktool(ApktoolError("capability_unavailable", "no apksigner"))
        )
        failed = service.apk_sign(sid)
        assert failed.ok is False
        assert failed.error is not None and failed.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_apk_sign_rejects_a_path_outside_the_session_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_apk(monkeypatch, _FakeApk())
    _use_apktool(monkeypatch, _FakeApktool())
    try:
        sid = _apk_session(service, tmp_path)
        stray = tmp_path / "outside.apk"
        stray.write_bytes(b"PK\x03\x04")
        result = service.apk_sign(sid, apk_path=str(stray))
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
    finally:
        service.close_all()
