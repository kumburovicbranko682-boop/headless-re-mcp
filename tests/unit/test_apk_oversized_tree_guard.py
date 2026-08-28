"""A decoded/decompiled tree over the capture cap is deleted and refused.

``check_zip_expansion`` refuses a *declared*-size bomb before apktool/jadx
start, but a hostile archive can also declare an honest central directory and
still inflate to gigabytes on disk once the tool runs (nested archives, densely
generated smali, a resource table that expands far past its stored size). The
service-layer backstop ``_refuse_oversized_tree`` measures the tree apktool/jadx
actually wrote and, when it outran ``UNREGISTERED_CAPTURE_MAX_BYTES``, deletes it
and raises ``too_large`` -- so a decode that filled the disk does not leave the
fill behind for the next close or artifacts.gc to inherit.

Nothing pinned this: the declared-size guard is tested, the actual-size backstop
was not, so removing the call at any of its three sites (apk.decode,
apk.decompile, apk.export_sources) would regress silently. These fix both the
helper contract and that it is still wired into the apktool and jadx paths.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apktool import ApktoolError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_apk
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_apk import _refuse_oversized_tree


def _tree_of(root: Path, member_bytes: int) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AndroidManifest.xml").write_bytes(b"x" * member_bytes)
    return root


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def test_the_helper_deletes_and_refuses_a_tree_over_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The refusal must remove the tree, not just report it.

    Leaving the oversized tree on disk would defeat the point: the disk stays
    full and the next close/gc never sees a tree written after
    _forget_session_work_dirs. Shrinking the cap keeps the test from writing
    real gigabytes -- what matters is the measured size crossing it.
    """
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)
    tree = _tree_of(tmp_path / "decoded", 500)
    with pytest.raises(ApktoolError) as caught:
        _refuse_oversized_tree(tree, kind="apktool", error_type=ApktoolError)
    assert caught.value.code == "too_large"
    assert caught.value.details["cap"] == 100
    assert caught.value.details["size"] >= 500
    assert not tree.exists()


def test_the_helper_leaves_a_tree_within_the_cap_untouched(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 10_000)
    tree = _tree_of(tmp_path / "decoded", 500)
    _refuse_oversized_tree(tree, kind="apktool", error_type=ApktoolError)
    assert (tree / "AndroidManifest.xml").is_file()


def test_the_helper_treats_a_missing_tree_as_nothing_to_refuse(tmp_path: Path) -> None:
    """A tool that produced no tree is a different failure, not a too_large one."""
    _refuse_oversized_tree(tmp_path / "never-written", kind="apktool", error_type=ApktoolError)


def test_the_helper_deletes_and_refuses_a_single_file_over_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The backstop also covers a single-file output (a repacked/signed APK)."""
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)
    blob = tmp_path / "repacked.apk"
    blob.write_bytes(b"x" * 500)
    with pytest.raises(ApktoolError) as caught:
        _refuse_oversized_tree(blob, kind="apktool", error_type=ApktoolError)
    assert caught.value.code == "too_large"
    assert not blob.exists()


def test_apk_decode_refuses_and_deletes_an_oversized_apktool_tree(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apk.decode must still be wired to the backstop.

    A fake apktool writes a tree past the (shrunk) cap; the envelope has to come
    back too_large and the tree must be gone, or a real decode that overran
    would answer ok and strand the fill under artifact_root.
    """
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)

    class _FatApktool:
        def decode(
            self, apk: Path, out_dir: Path, *, timeout: float = 600.0, no_resources: bool = False
        ) -> dict[str, Any]:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "AndroidManifest.xml").write_bytes(b"x" * 500)
            return {
                "decoded_dir": str(out_dir),
                "manifest": "AndroidManifest.xml",
                "smali_dirs": [],
                "has_resources": False,
            }

    service._apktool_client = lambda: _FatApktool()  # type: ignore[method-assign]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large"
        decoded = settings.artifact_root.expanduser().resolve() / "apktool" / session_id / "decoded"
        assert not decoded.exists()
    finally:
        service.close_all()


def test_apk_decompile_refuses_and_deletes_an_oversized_jadx_tree(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apk.decompile is the third guard site the docstring names, and until now
    no test drove it.

    ``_refuse_oversized_tree`` is called at three separate lines -- apk.decode,
    apk.export_sources and apk.decompile -- and the guard's contract is that
    dropping the call at *any* of them regresses silently. decode and
    export_sources are pinned above, but apk.decompile calls the guard on its own
    line: it shares export_sources' jadx out dir yet the two are distinct source
    sites, so a refactor that removed only decompile's call would leave a
    single-class decompile that inflated past the cap answering ok and stranding
    the fill under artifact_root -- and every other test here would still pass.
    This exercises that third site directly, so the "any of three" claim is now
    actually enforced rather than asserted.
    """
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)

    class _FatJadx:
        def __init__(self, _jadx: Any = None) -> None:
            pass

        def decompile(
            self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
        ) -> dict[str, Any]:
            (out_dir / "sources").mkdir(parents=True, exist_ok=True)
            (out_dir / "sources" / "Target.java").write_bytes(b"x" * 500)
            return {"sources_dir": str(out_dir)}

    monkeypatch.setattr(service_apk, "JadxClient", _FatJadx)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_decompile(session_id, "com.example.Target")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large"
        out_dir = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not out_dir.exists()
    finally:
        service.close_all()


def test_apk_export_sources_refuses_and_deletes_an_oversized_jadx_tree(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The jadx path shares the same backstop; pin that it is still wired.

    apk.export_sources calls the guard on its own line (as does apk.decompile,
    pinned above); this exercises the export_sources site directly.
    """
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 100)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)

    class _FatJadx:
        def __init__(self, _jadx: Any = None) -> None:
            pass

        def export_sources(
            self, binary: Path, out_dir: Path, *, timeout: float = 300.0, no_imports: bool = False
        ) -> dict[str, Any]:
            (out_dir / "sources").mkdir(parents=True, exist_ok=True)
            (out_dir / "sources" / "Main.java").write_bytes(b"x" * 500)
            return {"sources_dir": str(out_dir)}

    monkeypatch.setattr(service_apk, "JadxClient", _FatJadx)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large"
        out_dir = settings.artifact_root.expanduser().resolve() / "jadx" / session_id
        assert not out_dir.exists()
    finally:
        service.close_all()
