"""Edge-path coverage for core/service_apk.py.

Targets the oversized-tree guard, the androguard-backed success and error
arms (via a fake ApkClient), the jadx success tails, and the apktool-backed
decode/repack/sign flows driven by fake POSIX tool scripts.
"""

from __future__ import annotations

import os
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_apk
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_apk import _refuse_oversized_tree

_posix_only = pytest.mark.skipif(os.name == "nt", reason="fake tools are POSIX shell scripts")


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def _script(tmp_path: Path, body: str, *, name: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


def _service(tmp_path: Path, **overrides: Any) -> AnalysisService:
    fields: dict[str, Any] = {
        "artifact_root": tmp_path / "artifacts",
        "jadx": None,
        "apktool": None,
        "apksigner": None,
    }
    fields.update(overrides)
    return AnalysisService(replace(Settings.load(), **fields))


def _apk_session(service: AnalysisService, tmp_path: Path) -> str:
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


# --- _refuse_oversized_tree ---


def test_oversized_guard_ignores_a_missing_path(tmp_path: Path) -> None:
    _refuse_oversized_tree(tmp_path / "missing", kind="jadx", error_type=JadxError)


def test_oversized_guard_ignores_an_unmeasurable_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()

    def _unmeasurable(path: Path) -> int:
        raise OSError("permission denied")

    monkeypatch.setattr(service_apk, "_dir_size", _unmeasurable)

    _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

    assert tree.is_dir()


def test_oversized_guard_removes_a_directory_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "big.java").write_bytes(b"x" * 64)
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 1)

    with pytest.raises(JadxError) as caught:
        _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

    assert caught.value.code == "too_large"
    assert not tree.exists()


def test_oversized_guard_removes_a_file_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"x" * 64)
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 1)

    with pytest.raises(JadxError):
        _refuse_oversized_tree(blob, kind="jadx", error_type=JadxError)

    assert not blob.exists()


# --- androguard-backed arms via a fake ApkClient ---


class _FakeApk:
    def open(self, path: Path) -> dict[str, Any]:
        return {"package": "a.b", "opened": True}

    def manifest(self, path: Path) -> dict[str, Any]:
        return {"manifest": "<manifest/>"}

    def classes(self, path: Path, *, offset: int, limit: int) -> dict[str, Any]:
        return {"classes": ["La/b;"], "offset": offset, "limit": limit}

    def methods(
        self, path: Path, class_name: str, *, offset: int, limit: int
    ) -> dict[str, Any]:
        return {"class": class_name, "methods": ["onCreate"]}

    def strings(self, path: Path, *, offset: int, limit: int) -> dict[str, Any]:
        return {"strings": ["hello"]}

    def xrefs(self, path: Path, method_name: str, *, limit: int) -> dict[str, Any]:
        return {"method": method_name, "xrefs": []}


def test_apk_readers_succeed_with_a_working_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        opened = service.apk_open(session_id)
        assert opened.ok and opened.data is not None, opened.error
        assert opened.data["package"] == "a.b"

        manifest = service.apk_manifest(session_id)
        assert manifest.ok and manifest.data is not None
        assert manifest.data["manifest"] == "<manifest/>"

        classes = service.apk_classes(session_id, offset=1, limit=5)
        assert classes.ok and classes.data is not None
        assert classes.data["offset"] == 1

        methods = service.apk_methods(session_id, "La/b;")
        assert methods.ok and methods.data is not None
        assert methods.data["class"] == "La/b;"

        strings = service.apk_strings(session_id)
        assert strings.ok and strings.data is not None
        assert strings.data["strings"] == ["hello"]

        xrefs = service.apk_xrefs(session_id, "onCreate")
        assert xrefs.ok and xrefs.data is not None
        assert xrefs.data["method"] == "onCreate"
    finally:
        service.close_all()


def test_apk_readers_degrade_without_androguard(tmp_path: Path) -> None:
    """The real client refuses each call the same typed way when the optional
    dependency is absent (which it is in this test environment)."""
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        for result in (
            service.apk_open(session_id),
            service.apk_manifest(session_id),
            service.apk_permissions(session_id),
            service.apk_certificates(session_id),
            service.apk_components(session_id),
            service.apk_native_libs(session_id),
            service.apk_classes(session_id),
            service.apk_methods(session_id, "La/b;"),
            service.apk_strings(session_id),
            service.apk_xrefs(session_id, "onCreate"),
        ):
            assert not result.ok and result.error is not None
            assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


class _BrokenApk:
    def __getattr__(self, name: str) -> Any:
        def _explode(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("androguard fell over")

        return _explode


def test_apk_readers_wrap_an_unexpected_client_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "ApkClient", _BrokenApk)
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        for result in (
            service.apk_manifest(session_id),
            service.apk_classes(session_id),
            service.apk_methods(session_id, "La/b;"),
            service.apk_strings(session_id),
            service.apk_xrefs(session_id, "onCreate"),
        ):
            assert not result.ok and result.error is not None
            assert "fell over" in result.error.message
    finally:
        service.close_all()


def test_artifact_dir_helpers_refuse_a_traversal_session_id(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        with pytest.raises(ApkError) as jadx_refusal:
            service._jadx_out_dir("..")
        assert jadx_refusal.value.code == "invalid_params"
        with pytest.raises(ApkError) as repack_refusal:
            service._repack_dir("..")
        assert repack_refusal.value.code == "invalid_params"
    finally:
        service.close_all()


# --- jadx-backed arms ---


class _FakeJadx:
    def __init__(self, path: Any) -> None:
        self.path = path

    def decompile(
        self, apk: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "Cls.java").write_text("class Cls {}")
        return {"class": class_name, "java": "class Cls {}"}

    def export_sources(
        self, apk: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        return {"exported": True, "no_imports": no_imports}


def test_decompile_and_export_succeed_with_a_working_jadx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        decompiled = service.apk_decompile(session_id, "a.b.Cls")
        assert decompiled.ok and decompiled.data is not None, decompiled.error
        assert decompiled.data["class"] == "a.b.Cls"

        exported = service.apk_export_sources(session_id, no_imports=True)
        assert exported.ok and exported.data is not None, exported.error
        assert exported.data["no_imports"] is True
    finally:
        service.close_all()


def test_decompile_and_export_degrade_without_jadx(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)
        for result in (
            service.apk_decompile(session_id, "a.b.Cls"),
            service.apk_export_sources(session_id),
        ):
            assert not result.ok and result.error is not None
            assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_decompile_skips_cleanup_when_no_tree_was_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A close mid-decompile with no output tree has nothing to sweep."""
    service = _service(tmp_path)

    class _ClosingJadx(_FakeJadx):
        def decompile(
            self, apk: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
        ) -> dict[str, Any]:
            closed = service.close_session(_ClosingJadx.session_id)
            assert closed.ok, closed.error
            return {"class": class_name}

        session_id = ""

    monkeypatch.setattr(service_apk, "JadxClient", _ClosingJadx)
    try:
        session_id = _apk_session(service, tmp_path)
        _ClosingJadx.session_id = session_id

        result = service.apk_decompile(session_id, "a.b.Cls")

        assert not result.ok and result.error is not None
        assert "closed" in result.error.message
    finally:
        service.close_all()


# --- apktool-backed arms ---


@_posix_only
def test_decode_succeeds_with_a_working_apktool(tmp_path: Path) -> None:
    apktool = _script(
        tmp_path,
        'for a in "$@"; do out="$a"; done\n'
        'case "$*" in *"-o"*) : ;; esac\n'
        'mkdir -p "$4"\n'
        'touch "$4/AndroidManifest.xml"',
        name="apktool.sh",
    )
    service = _service(tmp_path, apktool=apktool)
    try:
        session_id = _apk_session(service, tmp_path)

        result = service.apk_decode(session_id)

        assert result.ok and result.data is not None, result.error
        assert result.data["decoded_dir"].endswith("decoded")
    finally:
        service.close_all()


def test_decode_degrades_without_apktool(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _apk_session(service, tmp_path)

        result = service.apk_decode(session_id)

        assert not result.ok and result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


@_posix_only
def test_repack_succeeds_with_a_working_apktool(tmp_path: Path) -> None:
    template = tmp_path / "template.apk"
    _write_minimal_apk(template)
    apktool = _script(
        tmp_path,
        f'if [ "$1" = "b" ]; then cp "{template}" "$4"; fi',
        name="apktool.sh",
    )
    service = _service(tmp_path, apktool=apktool)
    try:
        session_id = _apk_session(service, tmp_path)
        decoded = (
            service.settings.artifact_root.expanduser().resolve()
            / "apktool"
            / session_id
            / "decoded"
        )
        decoded.mkdir(parents=True)
        (decoded / "AndroidManifest.xml").write_text("<manifest/>")

        result = service.apk_repack(session_id)

        assert result.ok and result.data is not None, result.error
        assert result.data["signed"] is False
        assert Path(str(result.data["apk"])).name == "repacked.apk"
    finally:
        service.close_all()


@_posix_only
def test_sign_succeeds_with_a_working_apksigner(tmp_path: Path) -> None:
    apksigner = _script(
        tmp_path,
        'if [ "$1" = "sign" ]; then\n'
        '  prev=""; out=""\n'
        '  for a in "$@"; do\n'
        '    if [ "$prev" = "--out" ]; then out="$a"; fi\n'
        '    prev="$a"; last="$a"\n'
        "  done\n"
        '  cp "$last" "$out"\n'
        "fi\n"
        "exit 0",
        name="apksigner.sh",
    )
    service = _service(tmp_path, apksigner=apksigner)
    try:
        session_id = _apk_session(service, tmp_path)
        root = (
            service.settings.artifact_root.expanduser().resolve()
            / "apktool"
            / session_id
        )
        root.mkdir(parents=True, exist_ok=True)
        _write_minimal_apk(root / "repacked.apk")
        keystore = root / "release.keystore"
        keystore.write_bytes(b"jks")

        result = service.apk_sign(
            session_id,
            keystore=str(keystore),
            keystore_password="hunter2",
            key_alias="release",
        )

        assert result.ok and result.data is not None, result.error
        assert result.data["signed"] is True
        assert Path(str(result.data["apk"])).name == "signed.apk"
    finally:
        service.close_all()
