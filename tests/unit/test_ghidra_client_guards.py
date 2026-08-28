"""Guard and failure-path coverage for the Ghidra headless adapter.

The happy paths -- decompile `found` derivation, empty-vs-failed exports,
oversized/corrupt JSON, project-lock serialization -- live in
test_ghidra_client.py. This file pins the guards around them: what happens
when analyzeHeadless is not configured, the binary is missing, the packaged
postScript is gone, the run times out, exits non-zero without an export, or
leaves something behind that is not the JSON object the caller was promised.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
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


def _run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    exit_code: int = 0,
    json_text: str | None = '{"items": []}',
) -> list[list[str]]:
    """Stub run_bounded; ``json_text=None`` simulates a script that wrote nothing."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        argv = [str(part) for part in cmd]
        calls.append(argv)
        if json_text is not None:
            for arg in argv:
                if arg.endswith(".json"):
                    Path(arg).write_text(json_text, encoding="utf-8")
        return Completed(exit_code, b"analyze log", b"script stderr")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return calls


# ---------------------------------------------------------------------------
# analyzeHeadless discovery


def test_a_client_without_a_home_is_not_available() -> None:
    client = ghidra_client.GhidraClient(home=None)
    assert client.analyze is None
    assert client.available is False


def test_a_home_without_any_launcher_yields_no_analyze_path(tmp_path: Path) -> None:
    (tmp_path / "ghidra-empty").mkdir()
    client = ghidra_client.GhidraClient(home=tmp_path / "ghidra-empty")
    assert client.analyze is None
    assert client.available is False


def test_discovery_walks_the_candidate_list_to_a_bare_launcher(tmp_path: Path) -> None:
    home = tmp_path / "ghidra"
    home.mkdir()
    (home / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    assert ghidra_client._find_analyze_headless(home) == home / "analyzeHeadless"


# ---------------------------------------------------------------------------
# analyze_binary guards


def test_analyze_without_a_configured_ghidra_is_capability_unavailable(tmp_path: Path) -> None:
    client = ghidra_client.GhidraClient(home=None)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_analyze_of_a_missing_binary_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _run(monkeypatch)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(tmp_path / "gone.exe", tmp_path / "project")
    assert caught.value.code == "not_found"
    assert str(caught.value.details["path"]).endswith("gone.exe")
    assert calls == [], "a missing binary must never reach analyzeHeadless"


def test_analyze_surfaces_a_nonzero_exit_as_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(monkeypatch, exit_code=2, json_text=None)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2
    assert "script stderr" in str(caught.value.details["stderr"])


def test_analyze_can_keep_the_project_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _run(monkeypatch, json_text=None)
    client = _client(tmp_path)

    client.analyze_binary(_binary(tmp_path), tmp_path / "project", delete_project=False)

    (cmd,) = calls
    assert "-deleteProject" not in cmd
    assert "-import" in cmd


# ---------------------------------------------------------------------------
# export guards shared by functions/symbols/xrefs/decompile


def test_export_without_a_configured_ghidra_is_capability_unavailable(tmp_path: Path) -> None:
    client = ghidra_client.GhidraClient(home=None)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_export_of_a_missing_binary_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _run(monkeypatch)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.symbols(tmp_path / "gone.exe", tmp_path / "project")
    assert caught.value.code == "not_found"
    assert calls == []


def test_a_package_missing_its_postscript_is_reported_before_any_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ExportJson.py the headless run could only ever produce nothing."""
    calls = _run(monkeypatch)
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no-scripts")
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "ExportJson.py" in caught.value.message
    assert calls == []


def test_a_failed_run_that_wrote_nothing_reports_the_exit_and_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(monkeypatch, exit_code=1, json_text=None)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"
    assert caught.value.details["exit_code"] == 1
    assert "script stderr" in str(caught.value.details["stderr"])


def test_a_clean_exit_that_wrote_no_export_is_still_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 0 with no JSON must not read as an export; there is nothing to return."""
    _run(monkeypatch, exit_code=0, json_text=None)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "missing" in caught.value.message


def test_an_export_that_is_not_a_json_object_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A top-level array parses fine but breaks every payload["..."] contract."""
    _run(monkeypatch, json_text='["not", "an", "object"]')
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "must be an object" in caught.value.message


def test_an_unreadable_export_file_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(monkeypatch)
    real_open = Path.open

    def broken_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        # Only the adapter's read-back uses "rb"; the stub's write_text must work.
        if path.suffix == ".json" and args[:1] == ("rb",):
            raise OSError("I/O error reading export")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", broken_open)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "unreadable" in caught.value.message


def test_a_timed_out_headless_run_reports_the_killed_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timeout mapping must carry the PIDs run_bounded had to kill."""

    def timing_out(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        raise TimedOut(1.5, [111, 222])

    monkeypatch.setattr(ghidra_client, "run_bounded", timing_out)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project", timeout=1.5)
    assert caught.value.code == "timeout"
    assert caught.value.details["timeout"] == 1.5
    assert caught.value.details["killed_pids"] == [111, 222]


# ---------------------------------------------------------------------------
# per-mode wiring


def test_symbols_passes_its_mode_and_capped_limit_to_the_postscript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _run(monkeypatch, json_text='{"mode": "symbols", "items": [], "count": 0}')
    client = _client(tmp_path)

    listed = client.symbols(_binary(tmp_path), tmp_path / "project", limit=5000)

    (cmd,) = calls
    script_args = cmd[cmd.index("ExportJson.py") + 1 :]
    assert script_args[0] == "symbols"
    assert script_args[2] == "1024", "limits are capped at 1024 before reaching the script"
    assert listed["items"] == []


def test_xrefs_passes_an_integer_address_as_hex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _run(monkeypatch, json_text='{"mode": "xrefs", "items": [], "count": 0}')
    client = _client(tmp_path)

    client.xrefs(_binary(tmp_path), tmp_path / "project", 0x401000, limit=0)

    (cmd,) = calls
    script_args = cmd[cmd.index("ExportJson.py") + 1 :]
    assert script_args[0] == "xrefs"
    assert script_args[2] == "1", "a non-positive limit is raised to 1"
    assert script_args[3] == "0x401000"


def test_a_stale_export_from_a_previous_run_is_removed_before_the_new_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leftover export_functions.json must never be served as this run's answer."""
    project = tmp_path / "project"
    project.mkdir()
    stale = project / "export_functions.json"
    stale.write_text('{"items": [{"name": "stale"}], "count": 1}', encoding="utf-8")

    _run(monkeypatch, exit_code=0, json_text=None)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), project)
    assert caught.value.code == "backend_error"
    assert "missing" in caught.value.message
    assert not stale.exists()
