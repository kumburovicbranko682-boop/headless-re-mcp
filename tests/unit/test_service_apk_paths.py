"""APK service paths: success envelopes, error mapping, oversized-tree cap.

The backend tests bound androguard/jadx/apktool clients themselves; these pin
the mixin the tool surface calls -- each success answer carries the apk
backend name and its bookkeeping, a backend error keeps its code through the
envelope, the mid-operation close rollback copes with a tree that was never
written, and the unregistered-capture cap removes what it refuses.
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
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_apk import _refuse_oversized_tree

JsonObject = dict[str, Any]

_MODULE = "headless_re_mcp.core.service_apk"


class _FakeApkClient:
    """Stands in for ApkClient; one shared instance is scripted per test."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.answers: dict[str, JsonObject | BaseException] = {}

    def _record(self, name: str, *args: Any, **kwargs: Any) -> JsonObject:
        self.calls.append((name, args, kwargs))
        value = self.answers.get(name, {})
        if isinstance(value, BaseException):
            raise value
        return dict(value)

    def open(self, binary: Path) -> JsonObject:
        return self._record("open", binary)

    def manifest(self, binary: Path) -> JsonObject:
        return self._record("manifest", binary)

    def certificates(self, binary: Path) -> JsonObject:
        return self._record("certificates", binary)

    def classes(self, binary: Path, *, offset: int, limit: int) -> JsonObject:
        return self._record("classes", binary, offset=offset, limit=limit)

    def methods(self, binary: Path, class_name: str, *, offset: int, limit: int) -> JsonObject:
        return self._record("methods", binary, class_name, offset=offset, limit=limit)

    def strings(self, binary: Path, *, offset: int, limit: int) -> JsonObject:
        return self._record("strings", binary, offset=offset, limit=limit)

    def xrefs(self, binary: Path, method_name: str, *, limit: int) -> JsonObject:
        return self._record("xrefs", binary, method_name, limit=limit)


class _FakeJadxClient:
    def __init__(self) -> None:
        self.answers: dict[str, JsonObject | BaseException] = {}
        self.on_call: Any = None

    def _reply(self, name: str) -> JsonObject:
        if self.on_call is not None:
            self.on_call()
        value = self.answers.get(name, {})
        if isinstance(value, BaseException):
            raise value
        return dict(value)

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float
    ) -> JsonObject:
        return self._reply("decompile")

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float, no_imports: bool
    ) -> JsonObject:
        return self._reply("export_sources")


class _FakeApktoolClient:
    def __init__(self) -> None:
        self.answers: dict[str, JsonObject | BaseException] = {}

    def _reply(self, name: str) -> JsonObject:
        value = self.answers.get(name, {})
        if isinstance(value, BaseException):
            raise value
        return dict(value)

    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float, no_resources: bool
    ) -> JsonObject:
        return self._reply("decode")

    def build(self, source: Path, out_apk: Path, *, timeout: float) -> JsonObject:
        return self._reply("build")

    def sign(
        self,
        source: Path,
        out_apk: Path,
        *,
        keystore: Path | None,
        keystore_password: str,
        key_alias: str,
        timeout: float,
    ) -> JsonObject:
        return self._reply("sign")


def _make_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", "dex")
    return apk


def _service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AnalysisService, str, _FakeApkClient, _FakeJadxClient, _FakeApktoolClient]:
    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    apk = _FakeApkClient()
    jadx = _FakeJadxClient()
    apktool = _FakeApktoolClient()
    monkeypatch.setattr(f"{_MODULE}.ApkClient", lambda: apk)
    monkeypatch.setattr(f"{_MODULE}.JadxClient", lambda _settings: jadx)
    monkeypatch.setattr(f"{_MODULE}.ApktoolClient", lambda _apktool, _apksigner: apktool)
    session = service.registry.create(str(_make_apk(tmp_path)))
    return service, session.id, apk, jadx, apktool


def test_refuse_oversized_tree_ignores_missing_and_unsizable_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refuse_oversized_tree(tmp_path / "never-written", kind="jadx", error_type=JadxError)

    # A tree whose size cannot be read is left alone rather than guessed at.
    tree = tmp_path / "unreadable"
    tree.mkdir()

    def _unsizable(path: Path) -> int:
        raise OSError("permission denied")

    monkeypatch.setattr(f"{_MODULE}._dir_size", _unsizable)
    _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)
    assert tree.exists()


def test_refuse_oversized_tree_removes_the_dir_it_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raising while leaving the tree would keep the bytes the cap exists to
    bound; what is refused must also be reclaimed."""
    monkeypatch.setattr(f"{_MODULE}.UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    tree = tmp_path / "decoded"
    tree.mkdir()
    (tree / "big.smali").write_bytes(b"x" * 100)
    with pytest.raises(JadxError) as info:
        _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)
    assert info.value.code == "too_large"
    assert info.value.details["cap"] == 8
    assert not tree.exists()


def test_refuse_oversized_tree_removes_the_file_it_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(f"{_MODULE}.UNREGISTERED_CAPTURE_MAX_BYTES", 8)
    artifact = tmp_path / "repacked.apk"
    artifact.write_bytes(b"x" * 100)
    with pytest.raises(ApktoolError) as info:
        _refuse_oversized_tree(artifact, kind="apktool", error_type=ApktoolError)
    assert info.value.code == "too_large"
    assert not artifact.exists()


def test_apk_open_success_and_error_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, apk, _jadx, _apktool = _service(tmp_path, monkeypatch)
    try:
        apk.answers["open"] = {"package": "com.example.app", "version_name": "1.0"}
        result = service.apk_open(session_id)
        assert result.ok is True
        assert result.data is not None
        assert result.data["package"] == "com.example.app"
        assert result.meta["backend"] == "apk"

        apk.answers["open"] = ApkError("backend_error", "androguard is not installed")
        result = service.apk_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_call_ops_answer_and_keep_error_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, apk, _jadx, _apktool = _service(tmp_path, monkeypatch)
    try:
        apk.answers["manifest"] = {"manifest": "<manifest/>"}
        result = service.apk_manifest(session_id)
        assert result.ok is True
        assert result.data == {"manifest": "<manifest/>"}

        apk.answers["certificates"] = ApkError("not_found", "no signing block")
        result = service.apk_certificates(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_apk_paged_ops_forward_arguments_and_keep_error_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, apk, _jadx, _apktool = _service(tmp_path, monkeypatch)
    try:
        binary = service.registry.get(session_id).binary
        apk.answers["classes"] = {"classes": [], "total": 0}
        assert service.apk_classes(session_id, offset=3, limit=9).ok is True
        apk.answers["methods"] = {"methods": [], "total": 0}
        assert service.apk_methods(session_id, "Lcom/example/Main;", offset=1, limit=2).ok is True
        apk.answers["strings"] = {"strings": [], "total": 0}
        assert service.apk_strings(session_id, offset=0, limit=5).ok is True
        apk.answers["xrefs"] = {"xrefs": []}
        assert service.apk_xrefs(session_id, "decrypt", limit=4).ok is True
        assert apk.calls == [
            ("classes", (binary,), {"offset": 3, "limit": 9}),
            ("methods", (binary, "Lcom/example/Main;"), {"offset": 1, "limit": 2}),
            ("strings", (binary,), {"offset": 0, "limit": 5}),
            ("xrefs", (binary, "decrypt"), {"limit": 4}),
        ]

        failure = ApkError("invalid_params", "bad request")
        apk.answers.update(
            {"classes": failure, "methods": failure, "strings": failure, "xrefs": failure}
        )
        for result in (
            service.apk_classes(session_id),
            service.apk_methods(session_id, "Lcom/example/Main;"),
            service.apk_strings(session_id),
            service.apk_xrefs(session_id, "decrypt"),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_apk_decompile_success_and_error_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _apk, jadx, _apktool = _service(tmp_path, monkeypatch)
    try:
        jadx.answers["decompile"] = {"source": "class Main {}", "class_name": "Main"}
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is True
        assert result.data is not None
        assert result.data["source"] == "class Main {}"

        jadx.answers["decompile"] = JadxError("timeout", "jadx exceeded 300s")
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "timeout"
    finally:
        service.close_all()


def test_apk_decompile_rollback_copes_with_a_tree_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A close that lands mid-decompile triggers the rollback; when jadx
    wrote nothing there is nothing to remove and the failure still answers."""
    service, session_id, _apk, jadx, _apktool = _service(tmp_path, monkeypatch)
    try:
        jadx.on_call = lambda: service.registry.transition(session_id, SessionState.CLOSING)
        result = service.apk_decompile(session_id, "com.example.Main")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        out_dir = service._jadx_out_dir(session_id)
        assert not out_dir.exists()
    finally:
        service.close_all()


def test_apk_export_sources_success_error_and_bare_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _apk, jadx, _apktool = _service(tmp_path, monkeypatch)
    try:
        jadx.answers["export_sources"] = {"files": 12}
        result = service.apk_export_sources(session_id)
        assert result.ok is True
        assert result.data == {"files": 12}

        jadx.answers["export_sources"] = JadxError("backend_error", "jadx crashed")
        result = service.apk_export_sources(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()

    service2, session2, _apk2, jadx2, _apktool2 = _service(tmp_path, monkeypatch)
    try:
        jadx2.on_call = lambda: service2.registry.transition(session2, SessionState.CLOSING)
        result = service2.apk_export_sources(session2)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert not service2._jadx_out_dir(session2).exists()
    finally:
        service2.close_all()


def test_apk_decode_success_and_error_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _apk, _jadx, apktool = _service(tmp_path, monkeypatch)
    try:
        apktool.answers["decode"] = {"decoded": True}
        result = service.apk_decode(session_id)
        assert result.ok is True
        assert result.data == {"decoded": True}

        apktool.answers["decode"] = ApktoolError("backend_error", "apktool is not installed")
        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_apk_repack_and_sign_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _apk, _jadx, apktool = _service(tmp_path, monkeypatch)
    try:
        apktool.answers["build"] = {"apk": "repacked.apk"}
        result = service.apk_repack(session_id)
        assert result.ok is True
        assert result.data == {"apk": "repacked.apk"}

        apktool.answers["sign"] = {"apk": "signed.apk", "signed": True}
        result = service.apk_sign(session_id)
        assert result.ok is True
        assert result.data is not None
        assert result.data["signed"] is True
    finally:
        service.close_all()
