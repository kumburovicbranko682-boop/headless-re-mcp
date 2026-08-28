"""Happy-path and error-mapping coverage for the APK static-analysis service.

The apk.* field suites drive the androguard/jadx/apktool clients directly, and
the *_closed_session suites drive the retained-CLOSED guard, but the service
mixin's own body -- record the backend, append a timeline row, wrap the payload
in ``_success``, and map an ``ApkError`` / ``JadxError`` / ``ApktoolError`` back
into the canonical envelope -- ran on an *open* session in none of them. Neither
did the shared ``_apk_call`` helper, the ``_refuse_oversized_tree`` capture cap,
or the "session closed mid-run before any tree was written" cleanup arc.

These drive a real ``AnalysisService`` with an open APK session and fake backend
clients, so the service layer runs end to end without a real androguard, jadx or
apktool install.
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
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _FakeApkClient:
    """An androguard stand-in whose every read returns a marked payload."""

    def open(self, path: Path) -> dict[str, Any]:
        del path
        return {"opened": True, "package": "com.example.app"}

    def manifest(self, path: Path) -> dict[str, Any]:
        del path
        return {"manifest_xml": "<manifest/>", "truncated": False}

    def permissions(self, path: Path) -> dict[str, Any]:
        del path
        return {"permissions": [], "requested_permissions": [], "count": 0, "has_more": False}

    def certificates(self, path: Path) -> dict[str, Any]:
        del path
        return {"signature_files": [], "certificates": [], "v1_signed": False, "has_more": False}

    def components(self, path: Path) -> dict[str, Any]:
        del path
        return {"activities": [], "services": [], "receivers": [], "providers": []}

    def native_libs(self, path: Path) -> dict[str, Any]:
        del path
        return {"native_libs": [], "abis": [], "count": 0, "has_more": False}

    def classes(self, path: Path, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        del path, offset, limit
        return {"classes": ["Lcom/example/Main;"], "total": 1}

    def methods(
        self, path: Path, class_name: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        del path, offset, limit
        return {"class_name": class_name, "methods": [], "total": 0}

    def strings(self, path: Path, *, offset: int = 0, limit: int = 200) -> dict[str, Any]:
        del path, offset, limit
        return {"strings": ["hello"], "total": 1}

    def xrefs(self, path: Path, method_name: str, *, limit: int = 100) -> dict[str, Any]:
        del path, limit
        return {"method_name": method_name, "callers": [], "count": 0, "has_more": False}


class _RaisingApkClient:
    """Every read raises ApkError so the envelope-mapping arc is exercised."""

    def __getattr__(self, _name: str) -> Any:
        def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise ApkError("backend_error", "androguard exploded")

        return _boom


class _GenericErrorApkClient:
    """Every read raises a plain error so the internal_error arc is exercised."""

    def __getattr__(self, _name: str) -> Any:
        def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("unexpected androguard fault")

        return _boom


class _FakeJadx:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> dict[str, Any]:
        del binary, out_dir, timeout
        return {"class_name": class_name, "source": "class Main {}"}

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
    ) -> dict[str, Any]:
        del binary, out_dir, timeout, no_imports
        return {"exported": True}


class _FakeApktool:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float = 600.0, no_resources: bool = False
    ) -> dict[str, Any]:
        del binary, out_dir, timeout, no_resources
        return {"decoded": True}

    def build(self, source: Path, out_apk: Path, *, timeout: float = 600.0) -> dict[str, Any]:
        del source, out_apk, timeout
        return {"built": True}

    def sign(
        self,
        source: Path,
        out_apk: Path,
        *,
        keystore: Path | None = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        del source, out_apk, keystore, keystore_password, key_alias, timeout
        return {"signed": True}


def _open_apk_session(tmp_path: Path) -> tuple[AnalysisService, str, Settings]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], settings


# --- androguard read success paths ------------------------------------------


def test_apk_read_methods_record_and_wrap_on_an_open_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every androguard-backed read returns ok and carries the apk backend tag."""
    monkeypatch.setattr(service_apk, "ApkClient", _FakeApkClient)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        cases = [
            (service.apk_open(session_id), "package", "com.example.app"),
            (service.apk_manifest(session_id), "manifest_xml", "<manifest/>"),
            (service.apk_permissions(session_id), "count", 0),
            (service.apk_certificates(session_id), "v1_signed", False),
            (service.apk_components(session_id), "activities", []),
            (service.apk_native_libs(session_id), "count", 0),
            (service.apk_classes(session_id), "total", 1),
            (service.apk_methods(session_id, "com.example.Main"), "class_name", "com.example.Main"),
            (service.apk_strings(session_id), "total", 1),
            (service.apk_xrefs(session_id, "invoke"), "method_name", "invoke"),
        ]
        for result, key, expected in cases:
            assert result.ok is True, result.error
            assert result.data is not None
            assert result.data[key] == expected
            assert result.meta.get("backend") == "apk"
    finally:
        service.close_all()


def test_apk_reads_map_backend_errors_to_the_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ApkError from androguard becomes an ok=False envelope, code preserved."""
    monkeypatch.setattr(service_apk, "ApkClient", _RaisingApkClient)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        results = [
            service.apk_open(session_id),
            service.apk_manifest(session_id),
            service.apk_classes(session_id),
            service.apk_methods(session_id, "com.example.Main"),
            service.apk_strings(session_id),
            service.apk_xrefs(session_id, "invoke"),
        ]
        for result in results:
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "backend_error"
            assert "androguard exploded" in result.error.message
    finally:
        service.close_all()


# --- jadx / apktool success paths -------------------------------------------


def test_apk_decompile_and_export_wrap_jadx_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """jadx decompile/export record the backend and return the payload."""
    monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        decompiled = service.apk_decompile(session_id, "com.example.Main")
        assert decompiled.ok is True, decompiled.error
        assert decompiled.data is not None
        assert decompiled.data["class_name"] == "com.example.Main"

        exported = service.apk_export_sources(session_id)
        assert exported.ok is True, exported.error
        assert exported.data is not None
        assert exported.data["exported"] is True
    finally:
        service.close_all()


def test_apk_decode_repack_sign_wrap_apktool_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apktool decode/repack/sign each return ok on an open session."""
    monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        decoded = service.apk_decode(session_id)
        assert decoded.ok is True, decoded.error
        assert decoded.data is not None and decoded.data["decoded"] is True

        repacked = service.apk_repack(session_id)
        assert repacked.ok is True, repacked.error
        assert repacked.data is not None and repacked.data["built"] is True

        signed = service.apk_sign(session_id)
        assert signed.ok is True, signed.error
        assert signed.data is not None and signed.data["signed"] is True
    finally:
        service.close_all()


def test_apk_decode_maps_an_apktool_error_to_the_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ApktoolError from decode surfaces as ok=False with the code intact."""

    class _RaisingApktool(_FakeApktool):
        def decode(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise ApktoolError("backend_error", "apktool failed to decode")

    monkeypatch.setattr(service_apk, "ApktoolClient", _RaisingApktool)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_decompile_maps_a_jadx_error_to_the_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A JadxError surfaces as ok=False with the code intact."""

    class _RaisingJadx(_FakeJadx):
        def decompile(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise JadxError("backend_error", "jadx crashed")

    monkeypatch.setattr(service_apk, "JadxClient", _RaisingJadx)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_export_maps_a_jadx_error_to_the_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """export_sources maps its JadxError through the same envelope arc."""

    class _RaisingJadx(_FakeJadx):
        def export_sources(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise JadxError("backend_error", "jadx export crashed")

    monkeypatch.setattr(service_apk, "JadxClient", _RaisingJadx)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_repack_and_sign_map_an_apktool_error_to_the_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """repack/sign each map their ApktoolError through the envelope arc."""

    class _RaisingApktool(_FakeApktool):
        def build(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise ApktoolError("backend_error", "apktool build failed")

        def sign(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise ApktoolError("backend_error", "apksigner failed")

    monkeypatch.setattr(service_apk, "ApktoolClient", _RaisingApktool)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        repacked = service.apk_repack(session_id)
        assert repacked.ok is False
        assert repacked.error is not None and repacked.error.code == "backend_error"

        signed = service.apk_sign(session_id)
        assert signed.ok is False
        assert signed.error is not None and signed.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_reads_map_an_unexpected_error_to_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-ApkError fault still becomes a structured internal_error envelope."""
    monkeypatch.setattr(service_apk, "ApkClient", _GenericErrorApkClient)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        results = [
            service.apk_manifest(session_id),  # via _apk_call
            service.apk_classes(session_id),
            service.apk_methods(session_id, "com.example.Main"),
            service.apk_strings(session_id),
            service.apk_xrefs(session_id, "invoke"),
        ]
        for result in results:
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --- session-id and path-ownership guards ------------------------------------


def test_jadx_and_repack_dirs_reject_an_unsafe_session_segment(tmp_path: Path) -> None:
    """A traversal-flavoured session id never becomes an artifact path."""
    service, _session_id, _ = _open_apk_session(tmp_path)
    try:
        for helper in (service._jadx_out_dir, service._repack_dir):
            with pytest.raises(ApkError) as caught:
                helper("..")
            assert caught.value.code == "invalid_params"
    finally:
        service.close_all()


def test_apk_repack_rejects_a_decoded_dir_outside_the_session_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decoded_dir pointing outside the owned tree is refused before apktool runs."""
    monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        result = service.apk_repack(session_id, decoded_dir=str(tmp_path / "outside"))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_apk_sign_rejects_an_apk_path_outside_the_session_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller-supplied apk_path outside the owned tree is refused."""
    monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
    service, session_id, _ = _open_apk_session(tmp_path)
    try:
        result = service.apk_sign(session_id, apk_path=str(tmp_path / "outside.apk"))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


# --- close-mid-run cleanup when no tree was written --------------------------


def test_apk_decompile_close_mid_run_without_a_tree_is_invalid_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session closed during jadx, with no out_dir written, still fails cleanly.

    The existing close-mid test writes a tree so the cleanup rmtree runs; this
    one leaves no tree, so the guard steps straight to the re-raise instead.
    """
    service, session_id, settings = _open_apk_session(tmp_path)

    class _CloseThenDecompile(_FakeJadx):
        def decompile(self, *args: object, **kwargs: object) -> dict[str, Any]:
            service.close_session(session_id)
            return {"class_name": "com.example.Main", "source": ""}

    monkeypatch.setattr(service_apk, "JadxClient", lambda *a, **k: _CloseThenDecompile())
    try:
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        project = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not project.exists()
    finally:
        service.close_all()


def test_apk_export_close_mid_run_without_a_tree_is_invalid_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same guard for export_sources: close mid-run, no tree, clean failure."""
    service, session_id, settings = _open_apk_session(tmp_path)

    class _CloseThenExport(_FakeJadx):
        def export_sources(self, *args: object, **kwargs: object) -> dict[str, Any]:
            service.close_session(session_id)
            return {"exported": True}

    monkeypatch.setattr(service_apk, "JadxClient", lambda *a, **k: _CloseThenExport())
    try:
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        project = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not project.exists()
    finally:
        service.close_all()


# --- _refuse_oversized_tree --------------------------------------------------


def test_refuse_oversized_tree_ignores_a_missing_path(tmp_path: Path) -> None:
    """A path that was never written is a no-op, not an error."""
    service_apk._refuse_oversized_tree(
        tmp_path / "gone", kind="jadx", error_type=JadxError
    )


def test_refuse_oversized_tree_swallows_a_sizing_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory whose size cannot be measured is left alone, not deleted."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("x", encoding="utf-8")

    def _boom(_directory: Path) -> int:
        raise OSError("cannot stat")

    monkeypatch.setattr(service_apk, "_dir_size", _boom)
    service_apk._refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)
    assert tree.exists()


def test_refuse_oversized_tree_deletes_and_raises_for_an_oversized_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An output directory past the capture cap is removed and reported."""
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)
    tree = tmp_path / "big"
    tree.mkdir()
    (tree / "blob.bin").write_bytes(b"data")
    with pytest.raises(JadxError) as caught:
        service_apk._refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)
    assert caught.value.code == "too_large"
    assert not tree.exists()


def test_refuse_oversized_tree_deletes_and_raises_for_an_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single oversized artifact file is unlinked and reported."""
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)
    blob = tmp_path / "repacked.apk"
    blob.write_bytes(b"data")
    with pytest.raises(ApktoolError) as caught:
        service_apk._refuse_oversized_tree(blob, kind="apktool", error_type=ApktoolError)
    assert caught.value.code == "too_large"
    assert not blob.exists()


def test_refuse_oversized_tree_keeps_a_tree_within_the_cap(tmp_path: Path) -> None:
    """A small output tree passes without deletion (the common case)."""
    tree = tmp_path / "small"
    tree.mkdir()
    (tree / "a.txt").write_text("x", encoding="utf-8")
    service_apk._refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)
    assert tree.exists()
    assert UNREGISTERED_CAPTURE_MAX_BYTES > 0
