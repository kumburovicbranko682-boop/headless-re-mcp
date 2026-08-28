"""The APK service mixin's success paths, error mappings, and the size guard.

The apk suites pin the close-during-run guards and the host-path refusals, and
the apk *_fields suites pin the backend clients directly, so at the service
layer only the exception arms run. Unexercised: apk.open recording androguard
and returning its data, the generic _apk_call used by manifest/permissions/
certificates/components/native_libs, the classes/methods/strings/xrefs pages,
the jadx decompile/export_sources and apktool decode/repack/sign happy paths,
the ApkError/JadxError/ApktoolError-to-Result mapping on each, and every arm of
_refuse_oversized_tree (missing path, an OSError while sizing, and an oversized
tree or file that must be deleted and refused). This drives all of it with fake
backends and the size cap shrunk so a tiny tree trips it.
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

JsonObject = dict[str, Any]


def _apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _FakeApkClient:
    """Every androguard-backed call returns a small canned payload."""

    def open(self, path: Path) -> JsonObject:
        return {"package": "com.example.app", "opened": True}

    def manifest(self, path: Path) -> JsonObject:
        return {"manifest_xml": "<manifest/>", "truncated": False}

    def permissions(self, path: Path) -> JsonObject:
        return {"permissions": ["android.permission.INTERNET"]}

    def certificates(self, path: Path) -> JsonObject:
        return {"certificates": []}

    def components(self, path: Path) -> JsonObject:
        return {"activities": []}

    def native_libs(self, path: Path, *, offset: int = 0, limit: int = 256) -> JsonObject:
        return {"native_libs": [], "count": 0, "total": 0, "has_more": False, "offset": offset}

    def classes(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        return {"classes": [], "count": 0, "total": 0, "has_more": False, "offset": offset}

    def methods(
        self, path: Path, class_name: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        return {"methods": [], "class_name": class_name, "count": 0, "has_more": False}

    def strings(self, path: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        return {"strings": [], "count": 0, "has_more": False, "limit": limit}

    def xrefs(self, path: Path, method_name: str, *, limit: int = 100) -> JsonObject:
        return {"callers": [], "method_name": method_name, "count": 0, "has_more": False}


class _FakeJadx:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> JsonObject:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "Foo.java").write_text("class Foo {}", encoding="utf-8")
        return {"source": "class Foo {}", "class_name": class_name, "truncated": False}

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
    ) -> JsonObject:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "C.java").write_text("class C {}", encoding="utf-8")
        return {"java_files": ["C.java"], "java_file_count": 1, "no_imports": no_imports}


class _FakeApktool:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float = 600.0, no_resources: bool = False
    ) -> JsonObject:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "apktool.yml").write_text("x\n", encoding="utf-8")
        return {"decoded": True, "no_resources": no_resources}

    def build(self, source: Path, out_apk: Path, *, timeout: float = 600.0) -> JsonObject:
        out_apk.write_bytes(b"PK\x03\x04rebuilt")
        return {"signed": False, "size": out_apk.stat().st_size}

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
        out_apk.write_bytes(b"PK\x03\x04signed")
        return {"signed": True, "debug_keystore": keystore is None}


@pytest.fixture
def apk_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[AnalysisService, str]:
    monkeypatch.setattr(service_apk, "ApkClient", _FakeApkClient)
    monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
    monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, str(created.data["session"]["id"])


# --------------------------------------------------------------------------- #
# apk.open and the generic _apk_call surface                                  #
# --------------------------------------------------------------------------- #
def test_open_records_androguard_and_returns_its_data(
    apk_service: tuple[AnalysisService, str],
) -> None:
    service, sid = apk_service
    try:
        result = service.apk_open(sid)
        assert result.ok and result.data is not None, result.error
        assert result.data["package"] == "com.example.app"
        backends = {row["kind"] for row in service.repository.list_backends(sid)}
        assert "apk" in backends
    finally:
        service.close_all()


def test_open_maps_an_androguard_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _BadOpen(_FakeApkClient):
        def open(self, path: Path) -> JsonObject:
            raise ApkError("backend_error", "failed to read package name", opened=False)

    monkeypatch.setattr(service_apk, "ApkClient", _BadOpen)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
    sid = str(created.data["session"]["id"])  # type: ignore[index]
    try:
        result = service.apk_open(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "backend_error"
        assert not service.repository.list_backends(sid), "a failed open records no backend"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "key"),
    [
        ("apk_manifest", "manifest_xml"),
        ("apk_permissions", "permissions"),
        ("apk_certificates", "certificates"),
        ("apk_components", "activities"),
        ("apk_native_libs", "native_libs"),
    ],
)
def test_the_androguard_readouts_return_their_payloads(
    apk_service: tuple[AnalysisService, str], method: str, key: str
) -> None:
    service, sid = apk_service
    try:
        result = getattr(service, method)(sid)
        assert result.ok and result.data is not None, result.error
        assert key in result.data
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "args", "field"),
    [
        ("apk_classes", (), "classes"),
        ("apk_methods", ("com.example.Foo",), "methods"),
        ("apk_strings", (), "strings"),
        ("apk_xrefs", ("decrypt",), "callers"),
    ],
)
def test_the_paginated_readouts_return_their_pages(
    apk_service: tuple[AnalysisService, str], method: str, args: tuple[Any, ...], field: str
) -> None:
    service, sid = apk_service
    try:
        result = getattr(service, method)(sid, *args)
        assert result.ok and result.data is not None, result.error
        assert field in result.data
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("apk_manifest", ()),
        ("apk_classes", ()),
        ("apk_methods", ("com.example.Foo",)),
        ("apk_strings", ()),
        ("apk_xrefs", ("decrypt",)),
    ],
)
def test_an_androguard_error_is_mapped_to_its_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, args: tuple[Any, ...]
) -> None:
    class _Boom(_FakeApkClient):
        def __getattribute__(self, name: str) -> Any:
            if name in {
                "manifest",
                "classes",
                "methods",
                "strings",
                "xrefs",
            }:

                def raise_it(*_a: Any, **_k: Any) -> JsonObject:
                    raise ApkError("backend_error", "androguard blew up", stage=name)

                return raise_it
            return super().__getattribute__(name)

    monkeypatch.setattr(service_apk, "ApkClient", _Boom)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
    sid = str(created.data["session"]["id"])  # type: ignore[index]
    try:
        result = getattr(service, method)(sid, *args)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# jadx and apktool happy paths                                                #
# --------------------------------------------------------------------------- #
def test_decompile_writes_a_tree_records_and_returns_source(
    apk_service: tuple[AnalysisService, str],
) -> None:
    service, sid = apk_service
    try:
        result = service.apk_decompile(sid, "com.example.Foo")
        assert result.ok and result.data is not None, result.error
        assert result.data["class_name"] == "com.example.Foo"
        out = service.settings.artifact_root.expanduser().resolve() / "jadx" / sid
        assert out.is_dir()
    finally:
        service.close_all()


def test_export_sources_forwards_no_imports_and_records(
    apk_service: tuple[AnalysisService, str],
) -> None:
    service, sid = apk_service
    try:
        result = service.apk_export_sources(sid, no_imports=True)
        assert result.ok and result.data is not None, result.error
        assert result.data["no_imports"] is True
    finally:
        service.close_all()


def test_decode_writes_the_decoded_tree(apk_service: tuple[AnalysisService, str]) -> None:
    service, sid = apk_service
    try:
        result = service.apk_decode(sid, no_resources=True)
        assert result.ok and result.data is not None, result.error
        assert result.data["no_resources"] is True
        apktool_root = service.settings.artifact_root.expanduser().resolve() / "apktool" / sid
        assert (apktool_root / "decoded").is_dir()
    finally:
        service.close_all()


def test_repack_builds_into_the_session_tree(apk_service: tuple[AnalysisService, str]) -> None:
    service, sid = apk_service
    try:
        result = service.apk_repack(sid)
        assert result.ok and result.data is not None, result.error
        assert result.data["signed"] is False
        assert result.data["size"] > 0
    finally:
        service.close_all()


def test_sign_signs_the_repacked_apk(apk_service: tuple[AnalysisService, str]) -> None:
    service, sid = apk_service
    try:
        result = service.apk_sign(sid)
        assert result.ok and result.data is not None, result.error
        assert result.data["signed"] is True
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "args", "error"),
    [
        ("apk_decompile", ("com.example.Foo",), JadxError),
        ("apk_export_sources", (), JadxError),
        ("apk_decode", (), ApktoolError),
    ],
)
def test_a_tool_error_is_mapped_to_its_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    args: tuple[Any, ...],
    error: type,
) -> None:
    class _FailingJadx(_FakeJadx):
        def decompile(self, *_a: Any, **_k: Any) -> JsonObject:
            raise JadxError("backend_error", "jadx failed")

        def export_sources(self, *_a: Any, **_k: Any) -> JsonObject:
            raise JadxError("backend_error", "jadx failed")

    class _FailingApktool(_FakeApktool):
        def decode(self, *_a: Any, **_k: Any) -> JsonObject:
            raise ApktoolError("backend_error", "apktool failed")

    monkeypatch.setattr(service_apk, "JadxClient", _FailingJadx)
    monkeypatch.setattr(service_apk, "ApktoolClient", _FailingApktool)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
    sid = str(created.data["session"]["id"])  # type: ignore[index]
    try:
        result = getattr(service, method)(sid, *args)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# a close mid-run that produced no tree still fails, and cleanup tolerates it  #
# --------------------------------------------------------------------------- #
def test_decompile_closing_mid_run_with_no_tree_fails_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The post-run guard fires while out_dir was never written; the cleanup
    must skip the missing tree rather than trip over it, and the call fails."""
    monkeypatch.setattr(service_apk, "ApkClient", _FakeApkClient)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
    sid = str(created.data["session"]["id"])  # type: ignore[index]

    class _CloseThenDecompile(_FakeJadx):
        def decompile(self, *_a: Any, **_k: Any) -> JsonObject:
            service.close_session(sid)  # tree never created
            return {"source": "", "class_name": "X"}

    monkeypatch.setattr(service_apk, "JadxClient", _CloseThenDecompile)
    try:
        result = service.apk_decompile(sid, "com.example.Foo")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()


def test_export_sources_closing_mid_run_with_no_tree_fails_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "ApkClient", _FakeApkClient)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    created = service.create_session(str(_apk(tmp_path / "app.apk")), target="apk")
    sid = str(created.data["session"]["id"])  # type: ignore[index]

    class _CloseThenExport(_FakeJadx):
        def export_sources(self, *_a: Any, **_k: Any) -> JsonObject:
            service.close_session(sid)  # tree never created
            return {"java_files": [], "java_file_count": 0}

    monkeypatch.setattr(service_apk, "JadxClient", _CloseThenExport)
    try:
        result = service.apk_export_sources(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# _refuse_oversized_tree: every arm, with the cap shrunk to a few bytes        #
# --------------------------------------------------------------------------- #
def test_refuse_is_a_noop_for_a_missing_path(tmp_path: Path) -> None:
    service_apk._refuse_oversized_tree(
        tmp_path / "absent", kind="jadx", error_type=JadxError
    )  # returns without raising


def test_refuse_swallows_a_sizing_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A tree that vanishes mid-size must degrade to a no-op, not a crash."""
    tree = tmp_path / "tree"
    tree.mkdir()

    def exploding_dir_size(_path: Path) -> int:
        raise OSError("stat race")

    monkeypatch.setattr(service_apk, "_dir_size", exploding_dir_size)
    service_apk._refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)
    assert tree.is_dir(), "an unsized tree is left in place, not deleted"


def test_refuse_deletes_and_rejects_an_oversized_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "big.bin").write_bytes(b"x" * 64)

    with pytest.raises(ApktoolError) as caught:
        service_apk._refuse_oversized_tree(tree, kind="apktool", error_type=ApktoolError)

    assert caught.value.code == "too_large"
    assert caught.value.details["cap"] == 8
    assert not tree.exists(), "the oversized tree must be deleted"


def test_refuse_deletes_and_rejects_an_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"x" * 64)

    with pytest.raises(JadxError) as caught:
        service_apk._refuse_oversized_tree(blob, kind="jadx", error_type=JadxError)

    assert caught.value.code == "too_large"
    assert not blob.exists(), "the oversized file must be deleted"
