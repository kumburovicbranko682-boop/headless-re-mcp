"""Guard, delegation and error-mapping paths of the APK static-analysis mixin.

The androguard/jadx/apktool backends have their own suites; this file covers
the service layer -- the oversized-tree refusal, the per-read delegators, the
close-mid-run rollback on the jadx tools, and the ``ApkError`` / ``JadxError`` /
``ApktoolError`` -> envelope mapping. A real ``AnalysisService`` is built with an
APK session and every backend is faked, so no decompiler runs.
"""

from __future__ import annotations

import zipfile
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_apk as service_apk
from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.apktool import ApktoolError
from headless_re_mcp.backends.jadx import JadxError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_apk import _refuse_oversized_tree


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


@pytest.fixture
def apk(tmp_path: Path) -> Iterator[tuple[AnalysisService, str]]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    apk_file = _write_minimal_apk(tmp_path / "app.apk")
    created = svc.create_session(str(apk_file), target="apk")
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    try:
        yield svc, session_id
    finally:
        svc.close_all()


class _BroadApk:
    def _ok(self, *_a: Any, **_k: Any) -> dict[str, Any]:
        return {"ok": True}

    def open(self, *_a: Any, **_k: Any) -> dict[str, Any]:
        return {"package": "a.b"}

    manifest = permissions = certificates = components = native_libs = _ok
    classes = methods = strings = xrefs = _ok


def _raising_apk(exc: BaseException) -> Any:
    class _R:
        def __getattr__(self, _name: str) -> Any:
            def _fn(*_a: Any, **_k: Any) -> Any:
                raise exc

            return _fn

    return _R()


def _install_apk(monkeypatch: pytest.MonkeyPatch, factory: Callable[[], Any]) -> None:
    monkeypatch.setattr(service_apk, "ApkClient", factory)


def _install_jadx(monkeypatch: pytest.MonkeyPatch, **methods: Any) -> None:
    fake = type("_FakeJadx", (), {"__init__": lambda self, cfg=None: None, **methods})
    monkeypatch.setattr(service_apk, "JadxClient", fake)


def _install_apktool(monkeypatch: pytest.MonkeyPatch, **methods: Any) -> None:
    fake = type("_FakeApktool", (), {"__init__": lambda self, a=None, b=None: None, **methods})
    monkeypatch.setattr(service_apk, "ApktoolClient", fake)


# ---------------------------------------------------------------------------
# _refuse_oversized_tree


def test_refuse_ignores_a_path_that_is_not_there(tmp_path: Path) -> None:
    _refuse_oversized_tree(tmp_path / "gone", kind="jadx", error_type=JadxError)


def test_refuse_keeps_a_tree_within_the_cap(tmp_path: Path) -> None:
    tree = tmp_path / "small"
    tree.mkdir()
    (tree / "a.txt").write_text("x", encoding="utf-8")

    _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

    assert tree.is_dir()


def test_refuse_swallows_a_sizing_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "unsizable"
    tree.mkdir()

    def _boom(_path: Path) -> int:
        raise OSError("cannot stat")

    monkeypatch.setattr(service_apk, "_dir_size", _boom)

    _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

    assert tree.is_dir()


def test_refuse_deletes_and_raises_on_an_oversized_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "big"
    tree.mkdir()
    (tree / "blob.bin").write_bytes(b"payload")
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)

    with pytest.raises(JadxError) as exc:
        _refuse_oversized_tree(tree, kind="jadx", error_type=JadxError)

    assert exc.value.code == "too_large"
    assert not tree.exists()


def test_refuse_deletes_and_raises_on_an_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"payload")
    monkeypatch.setattr(service_apk, "UNREGISTERED_CAPTURE_MAX_BYTES", 0)

    with pytest.raises(ApktoolError) as exc:
        _refuse_oversized_tree(blob, kind="apktool", error_type=ApktoolError)

    assert exc.value.code == "too_large"
    assert not blob.exists()


# ---------------------------------------------------------------------------
# apk.open


def test_apk_open_records_androguard(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_apk(monkeypatch, _BroadApk)

    result = service.apk_open(session_id)

    assert result.ok, result.error
    assert result.data == {"package": "a.b"}


def test_apk_open_maps_an_apk_error(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_apk(monkeypatch, lambda: _raising_apk(ApkError("parse_error", "bad dex")))

    result = service.apk_open(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "parse_error"


def test_apk_open_maps_an_unexpected_error(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_apk(monkeypatch, lambda: _raising_apk(ValueError("boom")))

    result = service.apk_open(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# read-only delegators: manifest / permissions / certificates / components /
# native_libs / classes / methods / strings / xrefs


_READ_CALLS: list[tuple[str, Callable[[AnalysisService, str], Any]]] = [
    ("apk_manifest", lambda s, sid: s.apk_manifest(sid)),
    ("apk_permissions", lambda s, sid: s.apk_permissions(sid)),
    ("apk_certificates", lambda s, sid: s.apk_certificates(sid)),
    ("apk_components", lambda s, sid: s.apk_components(sid)),
    ("apk_native_libs", lambda s, sid: s.apk_native_libs(sid)),
    ("apk_classes", lambda s, sid: s.apk_classes(sid)),
    ("apk_methods", lambda s, sid: s.apk_methods(sid, "La/b;")),
    ("apk_strings", lambda s, sid: s.apk_strings(sid)),
    ("apk_xrefs", lambda s, sid: s.apk_xrefs(sid, "m")),
]


@pytest.mark.parametrize("name,call", _READ_CALLS, ids=[name for name, _ in _READ_CALLS])
def test_read_delegator_returns_the_backend_payload(
    apk: tuple[AnalysisService, str],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    call: Callable[[AnalysisService, str], Any],
) -> None:
    service, session_id = apk
    _install_apk(monkeypatch, _BroadApk)

    result = call(service, session_id)

    assert result.ok, result.error
    assert result.meta.get("backend") == "apk"


@pytest.mark.parametrize("name,call", _READ_CALLS, ids=[name for name, _ in _READ_CALLS])
def test_read_delegator_maps_an_apk_error(
    apk: tuple[AnalysisService, str],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    call: Callable[[AnalysisService, str], Any],
) -> None:
    service, session_id = apk
    _install_apk(monkeypatch, lambda: _raising_apk(ApkError("not_found", "missing")))

    result = call(service, session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


@pytest.mark.parametrize("name,call", _READ_CALLS, ids=[name for name, _ in _READ_CALLS])
def test_read_delegator_maps_an_unexpected_error(
    apk: tuple[AnalysisService, str],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    call: Callable[[AnalysisService, str], Any],
) -> None:
    service, session_id = apk
    _install_apk(monkeypatch, lambda: _raising_apk(RuntimeError("boom")))

    result = call(service, session_id)

    assert not result.ok
    assert result.error is not None


# ---------------------------------------------------------------------------
# apk.decompile / apk.export_sources (jadx)


def test_apk_decompile_records_the_output_tree(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_jadx(
        monkeypatch,
        decompile=lambda self, binary, out_dir, class_name, timeout=300.0: {"class": class_name},
    )

    result = service.apk_decompile(session_id, "La/b;")

    assert result.ok, result.error
    assert result.data == {"class": "La/b;"}


def test_apk_decompile_maps_a_jadx_error(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(self: Any, *_a: Any, **_k: Any) -> Any:
        raise JadxError("timeout", "jadx timed out")

    service, session_id = apk
    _install_jadx(monkeypatch, decompile=_boom)

    result = service.apk_decompile(session_id, "La/b;")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "timeout"


def test_apk_decompile_refuses_to_record_if_the_session_closes_mid_run(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk

    def _closing(self: Any, binary: Path, out_dir: Path, class_name: str, timeout: float = 300.0):
        service.close_session(session_id)
        return {"class": class_name}

    _install_jadx(monkeypatch, decompile=_closing)

    result = service.apk_decompile(session_id, "La/b;")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_apk_export_sources_records_the_output_tree(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_jadx(
        monkeypatch,
        export_sources=lambda self, binary, out_dir, timeout=300.0, no_imports=False: {
            "exported": True
        },
    )

    result = service.apk_export_sources(session_id)

    assert result.ok, result.error
    assert result.data == {"exported": True}


def test_apk_export_sources_maps_a_jadx_error(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(self: Any, *_a: Any, **_k: Any) -> Any:
        raise JadxError("backend_error", "jadx failed")

    service, session_id = apk
    _install_jadx(monkeypatch, export_sources=_boom)

    result = service.apk_export_sources(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_apk_export_sources_refuses_to_record_if_the_session_closes_mid_run(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk

    def _closing(
        self: Any,
        binary: Path,
        out_dir: Path,
        timeout: float = 300.0,
        no_imports: bool = False,
    ) -> dict[str, Any]:
        service.close_session(session_id)
        return {"exported": True}

    _install_jadx(monkeypatch, export_sources=_closing)

    result = service.apk_export_sources(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# apk.decode / apk.repack / apk.sign (apktool)


def test_apk_decode_records_the_decoded_tree(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_apktool(
        monkeypatch,
        decode=lambda self, binary, out_dir, timeout=600.0, no_resources=False: {
            "decoded_dir": str(out_dir)
        },
    )

    result = service.apk_decode(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["decoded_dir"].endswith("decoded")


def test_apk_decode_maps_an_apktool_error(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(self: Any, *_a: Any, **_k: Any) -> Any:
        raise ApktoolError("backend_error", "apktool failed")

    service, session_id = apk
    _install_apktool(monkeypatch, decode=_boom)

    result = service.apk_decode(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_apk_repack_rebuilds_and_reports(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk
    _install_apktool(
        monkeypatch,
        build=lambda self, source, out_apk, timeout=600.0: {"apk": str(out_apk)},
    )

    result = service.apk_repack(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["apk"].endswith("repacked.apk")


def test_apk_sign_signs_and_reports(
    apk: tuple[AnalysisService, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = apk

    def _sign(
        self: Any,
        source: Path,
        out_apk: Path,
        keystore: Path | None = None,
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        return {"signed": str(out_apk)}

    _install_apktool(monkeypatch, sign=_sign)

    result = service.apk_sign(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["signed"].endswith("signed.apk")
