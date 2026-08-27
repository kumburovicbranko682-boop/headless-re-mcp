"""The APK service mixin must envelope androguard/jadx/apktool and bound spills.

``ApkAnalysisMixin`` fronts three backends: androguard (in-process), and the
jadx/apktool subprocess adapters that write into a per-session artifact tree.
Every method gates on session state and target, records bookkeeping on success,
maps a backend error through ``_as_rpc`` (a jadx/apktool timeout stays
retryable), and lets anything else fall through. None of the tools are installed
here, so all three clients are faked -- the point is the mixin's gating,
translation, and the ``_refuse_oversized_tree`` cap that keeps an unregistered
decode/decompile tree from filling the disk.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
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
from headless_re_mcp.core.service_apk import _refuse_oversized_tree

JsonObject = dict[str, Any]


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _FakeApk:
    results: dict[str, Any] = {}
    errors: dict[str, BaseException] = {}

    def _answer(self, name: str, default: Any) -> Any:
        err = _FakeApk.errors.get(name)
        if err is not None:
            raise err
        return _FakeApk.results.get(name, default)

    def open(self, path: Path) -> Any:
        return self._answer("open", {"package": "a.b"})

    def manifest(self, path: Path) -> Any:
        return self._answer("manifest", {"manifest": {}})

    def permissions(self, path: Path) -> Any:
        return self._answer("permissions", {"permissions": []})

    def certificates(self, path: Path) -> Any:
        return self._answer("certificates", {"certificates": []})

    def components(self, path: Path) -> Any:
        return self._answer("components", {"components": []})

    def native_libs(self, path: Path) -> Any:
        return self._answer("native_libs", {"native_libs": []})

    def classes(self, path: Path, offset: int = 0, limit: int = 100) -> Any:
        return self._answer("classes", {"classes": [], "offset": offset, "limit": limit})

    def methods(self, path: Path, class_name: str, offset: int = 0, limit: int = 100) -> Any:
        return self._answer("methods", {"methods": [], "class": class_name})

    def strings(self, path: Path, offset: int = 0, limit: int = 200) -> Any:
        return self._answer("strings", {"strings": []})

    def xrefs(self, path: Path, method_name: str, limit: int = 100) -> Any:
        return self._answer("xrefs", {"xrefs": [], "method": method_name})


class _FakeJadx:
    error: BaseException | None = None

    def __init__(self, tool: Any) -> None:
        self.tool = tool

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, timeout: float = 300.0
    ) -> Any:
        if _FakeJadx.error is not None:
            raise _FakeJadx.error
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "X.java").write_text("class X{}", encoding="utf-8")
        return {"class": class_name, "out_dir": str(out_dir)}

    def export_sources(
        self, binary: Path, out_dir: Path, timeout: float = 300.0, no_imports: bool = False
    ) -> Any:
        if _FakeJadx.error is not None:
            raise _FakeJadx.error
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "src.java").write_text("class Y{}", encoding="utf-8")
        return {"out_dir": str(out_dir)}


class _FakeApktool:
    error: BaseException | None = None

    def __init__(self, apktool: Any, apksigner: Any) -> None:
        self.apktool = apktool
        self.apksigner = apksigner

    def decode(
        self, binary: Path, out_dir: Path, timeout: float = 600.0, no_resources: bool = False
    ) -> Any:
        if _FakeApktool.error is not None:
            raise _FakeApktool.error
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text("<m/>", encoding="utf-8")
        return {"decoded_dir": str(out_dir)}

    def build(self, source: Path, out_apk: Path, timeout: float = 600.0) -> Any:
        if _FakeApktool.error is not None:
            raise _FakeApktool.error
        return {"apk": str(out_apk)}

    def sign(
        self,
        source: Path,
        out_apk: Path,
        keystore: Any = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> Any:
        if _FakeApktool.error is not None:
            raise _FakeApktool.error
        return {"signed_apk": str(out_apk)}


@pytest.fixture(autouse=True)
def _reset_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeApk.results = {}
    _FakeApk.errors = {}
    _FakeJadx.error = None
    _FakeApktool.error = None
    monkeypatch.setattr(service_apk, "ApkClient", _FakeApk)
    monkeypatch.setattr(service_apk, "JadxClient", _FakeJadx)
    monkeypatch.setattr(service_apk, "ApktoolClient", _FakeApktool)


@pytest.fixture
def apk_env(tmp_path: Path) -> Iterator[tuple[AnalysisService, str]]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        yield service, str(created.data["session"]["id"])
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# _refuse_oversized_tree
# --------------------------------------------------------------------------


def test_refuse_oversized_tree_ignores_a_missing_path(tmp_path: Path) -> None:
    _refuse_oversized_tree(tmp_path / "absent", kind="jadx", error_type=JadxError)


def test_refuse_oversized_tree_tolerates_a_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "tree"
    target.mkdir()

    def boom(path: Path) -> int:
        raise OSError("du refused")

    monkeypatch.setattr(service_apk, "_dir_size", boom)
    _refuse_oversized_tree(target, kind="jadx", error_type=JadxError)
    assert target.exists()


def test_refuse_oversized_tree_deletes_and_refuses_an_oversized_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "big.bin").write_bytes(b"x" * 32)
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)
    with pytest.raises(JadxError) as exc:
        _refuse_oversized_tree(target, kind="jadx", error_type=JadxError)
    assert exc.value.code == "too_large"
    assert not target.exists()


def test_refuse_oversized_tree_deletes_and_refuses_an_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"x" * 32)
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)
    with pytest.raises(ApktoolError) as exc:
        _refuse_oversized_tree(target, kind="apktool", error_type=ApktoolError)
    assert exc.value.code == "too_large"
    assert not target.exists()


# --------------------------------------------------------------------------
# androguard reads: success + error mapping
# --------------------------------------------------------------------------


def test_apk_open_records_a_parsed_apk(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApk.results["open"] = {"package": "com.example"}
    result = service.apk_open(session_id)
    assert result.ok, result.error
    assert result.data == {"package": "com.example"}
    backends = service.repository.list_backends(session_id)
    assert any(b["kind"] == "apk" for b in backends)


def test_apk_open_maps_an_androguard_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApk.errors["open"] = ApkError("backend_error", "not a valid apk")
    result = service.apk_open(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


@pytest.mark.parametrize(
    "method, op",
    [
        ("apk_manifest", "manifest"),
        ("apk_permissions", "permissions"),
        ("apk_certificates", "certificates"),
        ("apk_components", "components"),
        ("apk_native_libs", "native_libs"),
    ],
)
def test_apk_call_reads_return_success(
    apk_env: tuple[AnalysisService, str], method: str, op: str
) -> None:
    service, session_id = apk_env
    _FakeApk.results[op] = {op: ["value"]}
    result = getattr(service, method)(session_id)
    assert result.ok, result.error
    assert result.data == {op: ["value"]}


def test_apk_call_maps_an_androguard_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApk.errors["manifest"] = ApkError("backend_error", "manifest parse failed")
    result = service.apk_manifest(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_apk_call_surfaces_an_unexpected_exception(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApk.errors["permissions"] = RuntimeError("androguard exploded")
    result = service.apk_permissions(session_id)
    assert result.ok is False
    assert result.error is not None


@pytest.mark.parametrize(
    "method, args",
    [
        ("apk_classes", ()),
        ("apk_methods", ("a.B",)),
        ("apk_strings", ()),
        ("apk_xrefs", ("a.B->m",)),
    ],
)
def test_paged_reads_surface_an_unexpected_exception(
    apk_env: tuple[AnalysisService, str], method: str, args: tuple[Any, ...]
) -> None:
    service, session_id = apk_env
    op = method.removeprefix("apk_")
    _FakeApk.errors[op] = RuntimeError("androguard exploded")
    result = getattr(service, method)(session_id, *args)
    assert result.ok is False
    assert result.error is not None


def test_apk_classes_methods_strings_xrefs_return_success(
    apk_env: tuple[AnalysisService, str],
) -> None:
    service, session_id = apk_env
    assert service.apk_classes(session_id, offset=2, limit=5).data == {
        "classes": [],
        "offset": 2,
        "limit": 5,
    }
    assert service.apk_methods(session_id, "a.B").data == {"methods": [], "class": "a.B"}
    assert service.apk_strings(session_id).data == {"strings": []}
    assert service.apk_xrefs(session_id, "a.B->m").data == {"xrefs": [], "method": "a.B->m"}


@pytest.mark.parametrize(
    "method, op, args",
    [
        ("apk_classes", "classes", ()),
        ("apk_methods", "methods", ("a.B",)),
        ("apk_strings", "strings", ()),
        ("apk_xrefs", "xrefs", ("a.B->m",)),
    ],
)
def test_paged_reads_map_an_androguard_error(
    apk_env: tuple[AnalysisService, str], method: str, op: str, args: tuple[Any, ...]
) -> None:
    service, session_id = apk_env
    _FakeApk.errors[op] = ApkError("invalid_params", "bad page")
    result = getattr(service, method)(session_id, *args)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


# --------------------------------------------------------------------------
# jadx: decompile / export_sources
# --------------------------------------------------------------------------


def test_apk_decompile_records_the_output_tree(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    result = service.apk_decompile(session_id, "a.B")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["class"] == "a.B"


def test_apk_decompile_maps_a_jadx_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeJadx.error = JadxError("timeout", "jadx timed out")
    result = service.apk_decompile(session_id, "a.B")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


def test_apk_export_sources_records_the_output_tree(
    apk_env: tuple[AnalysisService, str],
) -> None:
    service, session_id = apk_env
    result = service.apk_export_sources(session_id)
    assert result.ok, result.error
    assert result.data is not None


def test_apk_export_sources_maps_a_jadx_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeJadx.error = JadxError("backend_error", "jadx crashed")
    result = service.apk_export_sources(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


# --------------------------------------------------------------------------
# apktool: decode / repack / sign
# --------------------------------------------------------------------------


def test_apk_decode_records_the_decoded_tree(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    result = service.apk_decode(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert "decoded_dir" in result.data


def test_apk_decode_maps_an_apktool_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApktool.error = ApktoolError("backend_error", "aapt failed")
    result = service.apk_decode(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_apk_repack_rebuilds_the_decoded_tree(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    result = service.apk_repack(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert "apk" in result.data


def test_apk_repack_maps_an_apktool_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApktool.error = ApktoolError("timeout", "apktool timed out")
    result = service.apk_repack(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_apk_sign_signs_the_repacked_apk(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    result = service.apk_sign(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert "signed_apk" in result.data


def test_apk_sign_maps_an_apktool_error(apk_env: tuple[AnalysisService, str]) -> None:
    service, session_id = apk_env
    _FakeApktool.error = ApktoolError("invalid_params", "no keystore password")
    result = service.apk_sign(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


# --------------------------------------------------------------------------
# mid-op session close: the write-after-close abort branches
# --------------------------------------------------------------------------


def test_apk_decompile_aborts_when_the_session_closes_mid_run(
    apk_env: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk_env

    class _CloseThenDecompile(_FakeJadx):
        def decompile(
            self, binary: Path, out_dir: Path, class_name: str, timeout: float = 300.0
        ) -> Any:
            service.close_session(session_id)
            # No output tree is written, so the abort path takes the
            # ``out_dir.is_dir()`` False branch on its way to re-raising.
            return {"class": class_name, "out_dir": str(out_dir)}

    monkeypatch.setattr(service_apk, "JadxClient", _CloseThenDecompile)
    result = service.apk_decompile(session_id, "a.B")
    assert result.ok is False
    assert result.error is not None


def test_apk_export_sources_aborts_when_the_session_closes_mid_run(
    apk_env: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk_env

    class _CloseThenExport(_FakeJadx):
        def export_sources(
            self, binary: Path, out_dir: Path, timeout: float = 300.0, no_imports: bool = False
        ) -> Any:
            service.close_session(session_id)
            return {"out_dir": str(out_dir)}

    monkeypatch.setattr(service_apk, "JadxClient", _CloseThenExport)
    result = service.apk_export_sources(session_id)
    assert result.ok is False
    assert result.error is not None


def test_apk_decode_aborts_when_the_session_closes_mid_run(
    apk_env: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk_env

    class _CloseThenDecode(_FakeApktool):
        def decode(
            self, binary: Path, out_dir: Path, timeout: float = 600.0, no_resources: bool = False
        ) -> Any:
            out_dir.mkdir(parents=True, exist_ok=True)
            service.close_session(session_id)
            return {"decoded_dir": str(out_dir)}

    monkeypatch.setattr(service_apk, "ApktoolClient", _CloseThenDecode)
    result = service.apk_decode(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# unsafe session id guards on the artifact-dir helpers
# --------------------------------------------------------------------------


def test_jadx_out_dir_refuses_an_unsafe_session_id(
    apk_env: tuple[AnalysisService, str],
) -> None:
    service, _ = apk_env
    with pytest.raises(ApkError) as exc:
        service._jadx_out_dir("../escape")
    assert exc.value.code == "invalid_params"


def test_repack_dir_refuses_an_unsafe_session_id(
    apk_env: tuple[AnalysisService, str],
) -> None:
    service, _ = apk_env
    with pytest.raises(ApkError) as exc:
        service._repack_dir("../escape")
    assert exc.value.code == "invalid_params"
