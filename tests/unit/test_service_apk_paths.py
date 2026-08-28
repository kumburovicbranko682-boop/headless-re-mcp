"""Path coverage for the APK static-analysis service mixin (``core/service_apk``).

androguard/jadx/apktool are not installed in the quality environment, so the
existing tests only reach the validation and error arcs; the mixin's success
surface was uncovered. These fake the three backend clients and inject an
APK-target session via ``registry.adopt`` so the happy paths, the
_record_backend/_timeline_append bookkeeping, the ApkError/JadxError/ApktoolError
envelopes, and the oversized-tree guard all run without a real toolchain.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_apk as service_apk
from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.apktool import ApktoolError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.service import AnalysisService


class _FakeApk:
    def open(self, binary: Path) -> dict[str, Any]:
        return {"package": "com.example"}

    def classes(self, binary: Path, *, offset: int, limit: int) -> dict[str, Any]:
        return {"classes": [], "offset": offset, "limit": limit}

    def methods(self, binary: Path, class_name: str, *, offset: int, limit: int) -> dict[str, Any]:
        return {"class": class_name, "methods": []}

    def strings(self, binary: Path, *, offset: int, limit: int) -> dict[str, Any]:
        return {"strings": []}

    def xrefs(self, binary: Path, method_name: str, *, limit: int) -> dict[str, Any]:
        return {"method": method_name, "xrefs": []}

    def manifest(self, binary: Path) -> dict[str, Any]:
        return {"manifest": {}}

    def permissions(self, binary: Path) -> dict[str, Any]:
        return {"permissions": []}

    def certificates(self, binary: Path) -> dict[str, Any]:
        return {"certificates": []}

    def components(self, binary: Path) -> dict[str, Any]:
        return {"components": []}

    def native_libs(self, binary: Path) -> dict[str, Any]:
        return {"native_libs": []}


class _BoomApk:
    """Any op raises ApkError, to drive every ApkError envelope uniformly."""

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise ApkError("parse_failed", "unreadable apk")

        return _fn


class _FakeJadx:
    def __init__(self, exe: Any) -> None:
        pass

    def decompile(self, binary: Path, out_dir: Path, class_name: str, *, timeout: float) -> Any:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "X.java").write_text("class X {}", encoding="utf-8")
        return {"class": class_name}

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float, no_imports: bool
    ) -> Any:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "src.java").write_text("//", encoding="utf-8")
        return {"exported": True}


class _FakeApktool:
    def __init__(self, apktool: Any, apksigner: Any) -> None:
        pass

    def decode(self, binary: Path, out_dir: Path, *, timeout: float, no_resources: bool) -> Any:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("<x/>", encoding="utf-8")
        return {"decoded": True}

    def build(self, source: Path, out_apk: Path, *, timeout: float) -> Any:
        out_apk.write_bytes(b"PK\x03\x04")
        return {"built": True}

    def sign(
        self,
        source: Path,
        out_apk: Path,
        *,
        keystore: Any,
        keystore_password: str,
        key_alias: str,
        timeout: float,
    ) -> Any:
        out_apk.write_bytes(b"PK\x03\x04")
        return {"signed": True}


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _apk_session(service: AnalysisService, tmp_path: Path) -> str:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    session = Session(target=TargetKind.APK, binary=apk, locator=str(apk), state=SessionState.READY)
    service.registry.adopt(session)
    return session.id


# --------------------------------------------------------------------------- #
# _refuse_oversized_tree                                                       #
# --------------------------------------------------------------------------- #
def test_refuse_oversized_tree_ignores_a_missing_path(tmp_path: Path) -> None:
    service_apk._refuse_oversized_tree(tmp_path / "gone", kind="jadx", error_type=JadxError)


def test_refuse_oversized_tree_allows_a_small_tree(tmp_path: Path) -> None:
    small = tmp_path / "small"
    small.mkdir()
    (small / "f").write_text("x", encoding="utf-8")
    service_apk._refuse_oversized_tree(small, kind="jadx", error_type=JadxError)
    assert small.is_dir()


def test_refuse_oversized_tree_returns_when_sizing_raises(tmp_path: Path, monkeypatch: Any) -> None:
    a_dir = tmp_path / "d"
    a_dir.mkdir()

    def boom(path: Path) -> int:
        raise OSError("stat failed")

    monkeypatch.setattr(service_apk, "_dir_size", boom)
    service_apk._refuse_oversized_tree(a_dir, kind="jadx", error_type=JadxError)
    assert a_dir.is_dir()


def test_refuse_oversized_tree_deletes_and_raises_for_a_big_dir(
    tmp_path: Path, monkeypatch: Any
) -> None:
    big = tmp_path / "big"
    big.mkdir()
    (big / "f").write_text("payload", encoding="utf-8")
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)
    with pytest.raises(JadxError) as excinfo:
        service_apk._refuse_oversized_tree(big, kind="jadx", error_type=JadxError)
    assert excinfo.value.code == "too_large"
    assert not big.exists()


def test_refuse_oversized_tree_deletes_and_raises_for_a_big_file(
    tmp_path: Path, monkeypatch: Any
) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"payload")
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)
    with pytest.raises(ApktoolError):
        service_apk._refuse_oversized_tree(big, kind="apktool", error_type=ApktoolError)
    assert not big.exists()


# --------------------------------------------------------------------------- #
# androguard-backed methods                                                    #
# --------------------------------------------------------------------------- #
def test_apk_open_records_backend_and_timeline(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        result = service.apk_open(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["package"] == "com.example"
    finally:
        service.close_all()


def test_apk_open_maps_an_apk_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApkClient", _BoomApk)
        result = service.apk_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "parse_failed"
    finally:
        service.close_all()


def test_apk_listing_methods_succeed(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        assert service.apk_classes(session_id).ok
        assert service.apk_methods(session_id, "com.X").ok
        assert service.apk_strings(session_id).ok
        assert service.apk_xrefs(session_id, "m()").ok
    finally:
        service.close_all()


def test_apk_listing_methods_map_errors(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApkClient", _BoomApk)
        for result in (
            service.apk_classes(session_id),
            service.apk_methods(session_id, "com.X"),
            service.apk_strings(session_id),
            service.apk_xrefs(session_id, "m()"),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "parse_failed"
    finally:
        service.close_all()


def test_apk_call_backed_methods_succeed_and_map_errors(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
        assert service.apk_manifest(session_id).ok
        assert service.apk_permissions(session_id).ok
        assert service.apk_certificates(session_id).ok
        assert service.apk_components(session_id).ok
        assert service.apk_native_libs(session_id).ok

        monkeypatch.setattr(service_apk, "ApkClient", _BoomApk)
        failed = service.apk_manifest(session_id)
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "parse_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# jadx-backed methods                                                          #
# --------------------------------------------------------------------------- #
def test_apk_decompile_succeeds(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["class"] == "com.example.Main"
    finally:
        service.close_all()


def test_apk_decompile_rolls_back_when_the_session_closes(tmp_path: Path, monkeypatch: Any) -> None:
    """A session closing after jadx runs but before the re-check is refused."""
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        class _ClosingJadx:
            def __init__(self, exe: Any) -> None:
                pass

            def decompile(
                self, binary: Path, out_dir: Path, class_name: str, *, timeout: float
            ) -> Any:
                service.registry.transition(session_id, SessionState.FAILED)
                return {"class": class_name}

        monkeypatch.setattr(service_apk, "JadxClient", _ClosingJadx)
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
    finally:
        service.close_all()


def test_apk_decompile_maps_a_jadx_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        class _BoomJadx:
            def __init__(self, exe: Any) -> None:
                pass

            def decompile(self, *args: Any, **kwargs: Any) -> Any:
                raise JadxError("jadx_failed", "decompile crashed")

        monkeypatch.setattr(service_apk, "JadxClient", _BoomJadx)
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "jadx_failed"
    finally:
        service.close_all()


def test_apk_export_sources_succeeds(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
        result = service.apk_export_sources(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["exported"] is True
    finally:
        service.close_all()


def test_apk_export_sources_rolls_back_when_the_session_closes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        class _ClosingJadx:
            def __init__(self, exe: Any) -> None:
                pass

            def export_sources(
                self, binary: Path, out_dir: Path, *, timeout: float, no_imports: bool
            ) -> Any:
                service.registry.transition(session_id, SessionState.FAILED)
                return {"exported": True}

        monkeypatch.setattr(service_apk, "JadxClient", _ClosingJadx)
        result = service.apk_export_sources(session_id)
        assert result.ok is False
    finally:
        service.close_all()


def test_apk_export_sources_maps_a_jadx_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        class _BoomJadx:
            def __init__(self, exe: Any) -> None:
                pass

            def export_sources(self, *args: Any, **kwargs: Any) -> Any:
                raise JadxError("jadx_failed", "export crashed")

        monkeypatch.setattr(service_apk, "JadxClient", _BoomJadx)
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "jadx_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# apktool-backed methods                                                       #
# --------------------------------------------------------------------------- #
def test_apk_decode_succeeds_and_maps_errors(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
        ok = service.apk_decode(session_id)
        assert ok.ok, ok.error
        assert ok.data is not None
        assert ok.data["decoded"] is True

        class _BoomApktool(_FakeApktool):
            def decode(self, *args: Any, **kwargs: Any) -> Any:
                raise ApktoolError("apktool_failed", "decode crashed")

        monkeypatch.setattr(service_apk, "ApktoolClient", _BoomApktool)
        failed = service.apk_decode(session_id)
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "apktool_failed"
    finally:
        service.close_all()


def test_apk_repack_succeeds_and_maps_errors(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
        ok = service.apk_repack(session_id)
        assert ok.ok, ok.error
        assert ok.data is not None
        assert ok.data["built"] is True

        class _BoomApktool(_FakeApktool):
            def build(self, *args: Any, **kwargs: Any) -> Any:
                raise ApktoolError("build_failed", "rebuild crashed")

        monkeypatch.setattr(service_apk, "ApktoolClient", _BoomApktool)
        failed = service.apk_repack(session_id)
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "build_failed"
    finally:
        service.close_all()


def test_apk_sign_succeeds_and_maps_errors(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
        ok = service.apk_sign(session_id)
        assert ok.ok, ok.error
        assert ok.data is not None
        assert ok.data["signed"] is True

        class _BoomApktool(_FakeApktool):
            def sign(self, *args: Any, **kwargs: Any) -> Any:
                raise ApktoolError("sign_failed", "signing crashed")

        monkeypatch.setattr(service_apk, "ApktoolClient", _BoomApktool)
        failed = service.apk_sign(session_id)
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "sign_failed"
    finally:
        service.close_all()


def test_apk_repack_maps_an_unresolvable_home_decoded_dir_to_invalid_params(
    tmp_path: Path,
) -> None:
    """A ~user decoded_dir whose home cannot be resolved makes Path.expanduser()
    raise RuntimeError -- not the ApkError the mixin maps -- so before the guard
    a path the caller fully controls filed an internal_error incident instead of
    the invalid_params a path outside the session tree already gets."""
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        result = service.apk_repack(session_id, decoded_dir="~nosuchuser_zzz/decoded")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_apk_sign_maps_an_unresolvable_home_keystore_to_invalid_params(
    tmp_path: Path,
) -> None:
    """Same guard on the keystore path apk.sign accepts from the caller."""
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        result = service.apk_sign(session_id, keystore="~nosuchuser_zzz/keystore.jks")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()
