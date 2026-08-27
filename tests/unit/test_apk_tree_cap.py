"""jadx/apktool output trees over the capture cap must be deleted and refused.

The apk write tools produce whole directory trees (a jadx source export, an
apktool decode) that are not registered artifacts, so retention never reclaims
them; _refuse_oversized_tree is the only bound between a hostile or just huge
APK and an artifact root that grows without limit. The web and device capture
caps have behavioural tests; this one had none -- neither the helper's
delete-and-raise body nor the three service call sites (apk.decompile,
apk.export_sources, apk.decode) that must return too_large with the tree gone.
A regression dropping the call, or swallowing its error, would leave the ok
envelope pointing at an unbounded tree with every existing apk test green.

The service tests drive the real call sites with a fake jadx/apktool that
writes an oversized tree exactly where the service points it, and shrink the
module's cap so a few KiB trips the real check. No jadx or apktool install is
needed; nothing here touches a subprocess.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_apk as service_apk_module
from headless_re_mcp.backends.apktool import ApktoolError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_apk import _refuse_oversized_tree

_CAP = 1024


def _shrink_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_apk_module, "UNREGISTERED_CAPTURE_MAX_BYTES", _CAP)


class TestRefuseOversizedTree:
    def test_an_oversized_directory_is_deleted_and_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _shrink_cap(monkeypatch)
        tree = tmp_path / "out"
        (tree / "sources").mkdir(parents=True)
        (tree / "sources" / "Big.java").write_bytes(b"x" * (_CAP * 4))

        with pytest.raises(JadxError) as caught:
            _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

        assert caught.value.code == "too_large"
        assert caught.value.details["cap"] == _CAP
        assert caught.value.details["size"] > _CAP
        assert not tree.exists(), "the refused tree must not stay on disk"

    def test_an_oversized_single_file_is_unlinked_with_the_callers_error_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The helper takes error_type so each call site reports as its own
        backend; a repacked .apk (a file, not a tree) goes down the unlink arm."""
        _shrink_cap(monkeypatch)
        blob = tmp_path / "repacked.apk"
        blob.write_bytes(b"x" * (_CAP * 2))

        with pytest.raises(ApktoolError) as caught:
            _refuse_oversized_tree(blob, kind="apktool", error_type=ApktoolError)

        assert caught.value.code == "too_large"
        assert not blob.exists()

    def test_a_tree_within_the_cap_is_kept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _shrink_cap(monkeypatch)
        tree = tmp_path / "out"
        tree.mkdir()
        keep = tree / "Small.java"
        keep.write_bytes(b"x" * 16)

        _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

        assert keep.is_file()

    def test_a_missing_path_is_a_no_op(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """jadx may have failed before writing anything; that is the tool's
        error to report, not a size violation."""
        _shrink_cap(monkeypatch)
        _refuse_oversized_tree(tmp_path / "never-written", kind="jadx", error_type=JadxError)


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def _apk_service(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, str(created.data["session"]["id"])


class _OversizedJadx:
    """JadxClient stand-in that fills the out_dir past the (shrunk) cap."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, **kwargs: object
    ) -> dict[str, Any]:
        sources = out_dir / "sources"
        sources.mkdir(parents=True, exist_ok=True)
        (sources / "Big.java").write_bytes(b"x" * (_CAP * 4))
        return {"output_dir": str(out_dir), "sources_dir": str(sources)}


class _OversizedApktool:
    """ApktoolClient stand-in whose decode writes an oversized tree."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float = 600.0, **kwargs: object
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "resources.arsc").write_bytes(b"x" * (_CAP * 4))
        return {"decoded_dir": str(out_dir), "manifest": "", "smali_dirs": []}


def test_apk_export_sources_over_the_cap_returns_too_large_with_the_tree_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service must honor the cap, not just define it: the fake writes a
    real oversized tree into artifact_root/jadx/<session>, and the caller must
    see too_large with nothing left to grow."""
    _shrink_cap(monkeypatch)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient",
        lambda *args, **kwargs: _OversizedJadx(),
    )
    service, session_id = _apk_service(tmp_path)
    try:
        result = service.apk_export_sources(session_id)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large"
        assert result.error.details.get("cap") == _CAP
        out_dir = tmp_path / "artifacts" / "jadx" / session_id
        assert not out_dir.exists(), "the oversized jadx tree must be deleted, not kept"
    finally:
        service.close_all()


def test_apk_decode_over_the_cap_returns_too_large_with_the_tree_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apk.decode has its own wiring through the apktool client; pinning it
    separately catches a regression that keeps the jadx check and drops this one."""
    _shrink_cap(monkeypatch)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.ApktoolClient",
        lambda *args, **kwargs: _OversizedApktool(),
    )
    service, session_id = _apk_service(tmp_path)
    try:
        result = service.apk_decode(session_id)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "too_large"
        decoded = tmp_path / "artifacts" / "apktool" / session_id / "decoded"
        assert not decoded.exists(), "the oversized decode tree must be deleted, not kept"
    finally:
        service.close_all()


def test_the_cap_is_documented_on_the_apk_write_tools() -> None:
    """The refusal is agent-visible behaviour (the tree the reply pointed at is
    gone), so the three capped tools must say so, like web.script.source does
    for its capture cap."""
    import ast

    from headless_re_mcp.tools.apk import build_apk_tools

    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docs: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    docs[str(keyword.value.value)] = ast.get_docstring(node) or ""
    for name in ("apk.decompile", "apk.export_sources", "apk.decode"):
        assert "too_large" in docs[name], f"{name} does not document the tree cap"
