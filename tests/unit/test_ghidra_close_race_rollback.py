"""ghidra.analyze / export must not orphan their project tree on a close race.

ghidra_analyze and _ghidra_export write a headless project under
artifact_root/ghidra/<session_id> and then re-check the session state, because
session.close runs _forget_session_work_dirs and returns: a project finished
after that is invisible to the next close and to artifacts.gc (only the
registered export_*.json is reclaimable; the project subdirs are not). The apk
write tools delete their tree in exactly this window; ghidra raised
invalid_request but left the project on disk -- the same orphaned-tree leak,
unguarded on the portable-backend line.

A fake GhidraClient makes the race deterministic: analyze/export writes a real
project subtree where the service points it, then drives the session to FAILED
(allowed from created) as its side effect, reproducing a concurrent close that
lands mid-run. The caller must see invalid_request with the project gone; a
live session must keep its project (so subsequent exports reuse the analysis).
No Ghidra install is needed.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _RacingGhidra:
    """GhidraClient stand-in: writes a project subtree, then the session fails.

    The service passes ``project = artifact_root/ghidra/<session_id>``. A real
    headless run leaves unregistered project remnants there (a *.rep dir, a
    .gpr file) alongside any export JSON; the fake writes a remnant subdir so
    the orphan is observable, plus an export_*.json for the export modes so the
    registered-file path is represented too.
    """

    def __init__(self, service: AnalysisService, session_id: str, *, race: bool) -> None:
        self._service = service
        self._session_id = session_id
        self._race = race

    def _write_and_maybe_fail(self, project: Path, *, with_export: bool) -> dict[str, Any]:
        (project / "sample.rep").mkdir(parents=True, exist_ok=True)
        (project / "sample.rep" / "project.prp").write_text("proj", encoding="utf-8")
        payload: dict[str, Any] = {"project_dir": str(project)}
        if with_export:
            export = project / "export_functions.json"
            export.write_text('{"functions": []}', encoding="utf-8")
            payload["export_path"] = str(export)
        if self._race:
            self._service.registry.transition(self._session_id, SessionState.FAILED)
        return payload

    def analyze_binary(
        self, binary: Path, project: Path, *, timeout: float = 120.0
    ) -> dict[str, Any]:
        return self._write_and_maybe_fail(project, with_export=False)

    def functions(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return self._write_and_maybe_fail(project, with_export=True)


def _pe_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, race: bool) -> tuple[
    AnalysisService, str, Path
]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    fake_factory = lambda **kwargs: _RacingGhidra(service, session_id, race=race)  # noqa: E731
    monkeypatch.setattr("headless_re_mcp.core.service_ext.GhidraClient", fake_factory)
    project = settings.artifact_root.expanduser().resolve() / "ghidra" / session_id
    return service, session_id, project


def test_analyze_deletes_the_project_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, project = _pe_service(tmp_path, monkeypatch, race=True)
    try:
        result = service.ghidra_analyze(session_id)
        assert result.ok is False, "a session that went terminal mid-analyze must not report ok"
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert not project.exists(), (
            "the ghidra project written after the racing close must be deleted; close already "
            "forgot this session's work dirs, so nothing else reclaims it"
        )
    finally:
        service.close_all()


def test_export_deletes_the_project_when_the_session_races_to_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The export path shares the leak (and additionally writes a registered
    export json); the whole session-keyed project dir must go on the race."""
    service, session_id, project = _pe_service(tmp_path, monkeypatch, race=True)
    try:
        result = service.ghidra_functions(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert not project.exists()
    finally:
        service.close_all()


def test_a_live_session_keeps_its_ghidra_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with no race the analysis succeeds and the project persists,
    so a following export can reuse it. This proves the rollback tests fail for
    the right reason -- the re-check firing, not a malformed fake."""
    service, session_id, project = _pe_service(tmp_path, monkeypatch, race=False)
    try:
        result = service.ghidra_analyze(session_id)
        assert result.ok, result.error
        assert (project / "sample.rep").is_dir(), "a live session must keep its ghidra project"
    finally:
        service.close_all()
