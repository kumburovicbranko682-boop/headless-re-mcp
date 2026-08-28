"""Ghidra adapter guard and failure paths without a real analyzeHeadless.

Complements test_ghidra_client.py: this file drives the refusal guards
(capability, missing binary, missing packaged script), the launch failures
(timeout, unlaunchable script), the export-file failures (never written,
unreadable, non-object JSON) and the analyzeHeadless discovery fallbacks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    # A real distribution ships both launchers side by side; discovery resolves
    # the one this OS can exec (.bat on Windows, the bare script on POSIX), so
    # the fixture must provide both or the client reads as capability_unavailable
    # on whichever platform the test happens to run.
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    (support / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    return home


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def _client(tmp_path: Path) -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _unavailable_client() -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=None)
    assert client.available is False
    return client


def _run_writing(payload: str | None, *, exit_code: int) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        if payload is not None:
            for arg in cmd:
                if str(arg).endswith(".json"):
                    Path(str(arg)).write_text(payload, encoding="utf-8")
        return Completed(exit_code, b"analyze log", b"boom")

    return fake_run


def test_analyze_binary_requires_a_configured_backend(tmp_path: Path) -> None:
    with pytest.raises(ghidra_client.GhidraError) as caught:
        _unavailable_client().analyze_binary(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "capability_unavailable"


def test_analyze_binary_requires_an_existing_binary(tmp_path: Path) -> None:
    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).analyze_binary(tmp_path / "gone.exe", tmp_path / "project")

    assert caught.value.code == "not_found"
    assert cast(str, caught.value.details["path"]).endswith("gone.exe")


def test_analyze_binary_surfaces_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_writing(None, exit_code=2))

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).analyze_binary(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2
    assert caught.value.details["stderr"] == "boom"


def test_analyze_binary_can_keep_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        commands.append([str(part) for part in cmd])
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)

    _client(tmp_path).analyze_binary(_binary(tmp_path), tmp_path / "project", delete_project=False)

    assert "-deleteProject" not in commands[0]


def test_symbols_and_xrefs_delegate_to_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        argv = [str(part) for part in cmd]
        commands.append(argv)
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    binary = _binary(tmp_path)

    symbols = client.symbols(binary, tmp_path / "project")
    xrefs = client.xrefs(binary, tmp_path / "project", 0x401000)

    assert symbols["items"] == []
    assert xrefs["items"] == []
    assert "symbols" in commands[0]
    assert "xrefs" in commands[1]
    assert "0x401000" in commands[1]


def test_export_requires_a_configured_backend(tmp_path: Path) -> None:
    with pytest.raises(ghidra_client.GhidraError) as caught:
        _unavailable_client().functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "capability_unavailable"


def test_export_requires_an_existing_binary(tmp_path: Path) -> None:
    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(tmp_path / "gone.exe", tmp_path / "project")

    assert caught.value.code == "not_found"


def test_export_requires_the_packaged_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no-scripts")

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "ExportJson.java" in caught.value.message


def test_export_failure_without_a_file_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_writing(None, exit_code=1))

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"
    assert caught.value.details["exit_code"] == 1


def test_export_missing_after_a_clean_exit_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_writing(None, exit_code=0))

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON missing after postScript"


def test_export_that_cannot_be_read_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_writing('{"items": []}', exit_code=0))
    real_open = Path.open

    def unreadable_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if self.suffix == ".json" and "b" in mode:
            raise OSError("permission denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", unreadable_open)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "export JSON unreadable" in caught.value.message


def test_export_that_is_not_an_object_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_writing("[1, 2]", exit_code=0))

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON must be an object"


def test_a_timed_out_headless_run_reports_the_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timing_out(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        raise TimedOut(timeout=1.0, killed=[123, 456])

    monkeypatch.setattr(ghidra_client, "run_bounded", timing_out)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project", timeout=1.0)

    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [123, 456]


def test_an_unlaunchable_headless_script_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unlaunchable(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        raise OSError("exec format error")

    monkeypatch.setattr(ghidra_client, "run_bounded", unlaunchable)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        _client(tmp_path).functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "failed to launch analyzeHeadless" in caught.value.message


def test_find_analyze_headless_without_a_home_returns_none() -> None:
    assert ghidra_client._find_analyze_headless(None) is None


def test_find_analyze_headless_scans_the_known_locations(tmp_path: Path) -> None:
    assert ghidra_client._find_analyze_headless(tmp_path) is None

    bare = tmp_path / "analyzeHeadless"
    bare.write_text("#!/bin/sh\n", encoding="utf-8")

    assert ghidra_client._find_analyze_headless(tmp_path) == bare
