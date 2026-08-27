"""The apk write tools must delete their output when the session races to terminal.

Every apk write op (decompile, export_sources, decode, repack, sign) re-checks
the session state *after* its subprocess ran: session.close runs
_forget_session_work_dirs and then returns, so a tree the tool finished
writing after that is invisible to the next close and to artifacts.gc --
orphaned bytes nothing can reclaim, the same leak the proxy.start rollback
(test_proxy_start_race_rollback) prevents for a bound port. The pre-check
half (a session already closed never starts the tool) is pinned by the
*_closed_session tests; the post-run race half -- five independent copies of
the rollback, one per op -- had no coverage, so any one of them could be
dropped in a refactor with the suite green.

Fake jadx/apktool clients make the race deterministic: their write method
writes real output where the service pointed it, then drives the session to
FAILED (allowed from created) as its side effect, exactly what a concurrent
close/fail landing during the subprocess run produces. The caller must see
invalid_request, not ok, and the output tree must be gone.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


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


class _RacingJadx:
    """JadxClient stand-in: writes real output, then the session goes terminal."""

    def __init__(self, service: AnalysisService, session_id: str, *, race: bool) -> None:
        self._service = service
        self._session_id = session_id
        self._race = race

    def _maybe_fail(self) -> None:
        if self._race:
            self._service.registry.transition(self._session_id, SessionState.FAILED)

    def decompile(
        self, binary: Path, out_dir: Path, class_name: str, *, timeout: float = 300.0
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "Main.java").write_text("class Main {}\n", encoding="utf-8")
        self._maybe_fail()
        return {
            "class_name": class_name,
            "path": str(out_dir / "Main.java"),
            "source": "class Main {}\n",
        }

    def export_sources(
        self, binary: Path, out_dir: Path, *, timeout: float = 300.0, **kwargs: object
    ) -> dict[str, Any]:
        sources = out_dir / "sources"
        sources.mkdir(parents=True, exist_ok=True)
        (sources / "Main.java").write_text("class Main {}\n", encoding="utf-8")
        self._maybe_fail()
        return {"output_dir": str(out_dir), "sources_dir": str(sources)}


class _RacingApktool:
    """ApktoolClient stand-in covering decode, build and sign."""

    def __init__(self, service: AnalysisService, session_id: str, *, race: bool) -> None:
        self._service = service
        self._session_id = session_id
        self._race = race

    def _maybe_fail(self) -> None:
        if self._race:
            self._service.registry.transition(self._session_id, SessionState.FAILED)

    def decode(
        self, binary: Path, out_dir: Path, *, timeout: float = 600.0, **kwargs: object
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "apktool.yml").write_text("version: 2\n", encoding="utf-8")
        self._maybe_fail()
        return {"decoded_dir": str(out_dir), "manifest": "", "smali_dirs": []}

    def build(
        self, source: Path, out_apk: Path, *, timeout: float = 600.0
    ) -> dict[str, Any]:
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK\x03\x04rebuilt")
        self._maybe_fail()
        return {"apk": str(out_apk), "size": 11, "signed": False, "note": ""}

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
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK\x03\x04signed")
        self._maybe_fail()
        return {"apk": str(out_apk), "signed": True}


def _patch_jadx(
    monkeypatch: pytest.MonkeyPatch, service: AnalysisService, session_id: str, *, race: bool
) -> None:
    fake = _RacingJadx(service, session_id, race=race)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.JadxClient", lambda *args, **kwargs: fake
    )


def _patch_apktool(
    monkeypatch: pytest.MonkeyPatch, service: AnalysisService, session_id: str, *, race: bool
) -> None:
    fake = _RacingApktool(service, session_id, race=race)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_apk.ApktoolClient", lambda *args, **kwargs: fake
    )


def _assert_rolled_back(result: Any, tree: Path, op: str) -> None:
    assert result.ok is False, f"{op}: a session that went terminal mid-run must not report ok"
    assert result.error is not None, op
    assert result.error.code == "invalid_request", f"{op}: {result.error.code}"
    assert not tree.exists(), (
        f"{op}: the output written after the session went terminal must be deleted; "
        "close already forgot this session's work dirs, so nothing else ever reclaims it"
    )


def test_decompile_rolls_back_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_service(tmp_path)
    try:
        _patch_jadx(monkeypatch, service, session_id, race=True)
        result = service.apk_decompile(session_id, "com.example.Main")
        _assert_rolled_back(
            result, tmp_path / "artifacts" / "jadx" / session_id, "apk.decompile"
        )
    finally:
        service.close_all()


def test_export_sources_rolls_back_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_service(tmp_path)
    try:
        _patch_jadx(monkeypatch, service, session_id, race=True)
        result = service.apk_export_sources(session_id)
        _assert_rolled_back(
            result, tmp_path / "artifacts" / "jadx" / session_id, "apk.export_sources"
        )
    finally:
        service.close_all()


def test_decode_rolls_back_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """decode's rollback removes the whole apktool/<session> root, not just the
    decoded subdirectory -- pin the stronger property."""
    service, session_id = _apk_service(tmp_path)
    try:
        _patch_apktool(monkeypatch, service, session_id, race=True)
        result = service.apk_decode(session_id)
        _assert_rolled_back(
            result, tmp_path / "artifacts" / "apktool" / session_id, "apk.decode"
        )
    finally:
        service.close_all()


def test_repack_rolls_back_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_service(tmp_path)
    try:
        _patch_apktool(monkeypatch, service, session_id, race=True)
        result = service.apk_repack(session_id)
        _assert_rolled_back(
            result, tmp_path / "artifacts" / "apktool" / session_id, "apk.repack"
        )
    finally:
        service.close_all()


def test_sign_rolls_back_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _apk_service(tmp_path)
    try:
        _patch_apktool(monkeypatch, service, session_id, race=True)
        result = service.apk_sign(session_id)
        _assert_rolled_back(
            result, tmp_path / "artifacts" / "apktool" / session_id, "apk.sign"
        )
    finally:
        service.close_all()


def test_a_live_session_keeps_its_output_and_reports_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with no race the same fakes succeed and the tree survives.

    This is what proves the rollback tests fail for the right reason -- the
    fakes' payloads satisfy the happy path, so a rolled-back call can only be
    the post-run re-check acting, not a malformed fake erroring earlier.
    """
    service, session_id = _apk_service(tmp_path)
    try:
        _patch_jadx(monkeypatch, service, session_id, race=False)
        exported = service.apk_export_sources(session_id)
        assert exported.ok, exported.error
        assert (tmp_path / "artifacts" / "jadx" / session_id / "sources").is_dir()

        _patch_apktool(monkeypatch, service, session_id, race=False)
        signed = service.apk_sign(session_id)
        assert signed.ok, signed.error
        assert (tmp_path / "artifacts" / "apktool" / session_id / "signed.apk").is_file()
    finally:
        service.close_all()
