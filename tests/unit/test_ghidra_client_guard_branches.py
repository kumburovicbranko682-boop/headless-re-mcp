"""Guard, error and discovery branches of the Ghidra analyzeHeadless adapter.

The existing ghidra tests pin the heap wiring, the project serialization, the
decompile `found` derivation and the corrupt/oversized/empty-export contracts.
This file fills in the branches those step over: the availability and
missing-binary guards on both entry points, the missing-script guard, the
symbols/xrefs export paths, the failed / missing / unreadable / non-object
export JSON, the delete-project skip, the timeout translation, and launcher
discovery. Each test pins one branch and needs no real Ghidra: `run_bounded`
is faked at the seam and the JSON is written (or withheld) by the fake.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError


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


def _client(tmp_path: Path) -> GhidraClient:
    client = GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    return client


def _writing_run(payload: str | None, *, exit_code: int) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        if payload is not None:
            for arg in cmd:
                if str(arg).endswith(".json"):
                    Path(str(arg)).write_text(payload, encoding="utf-8")
        return Completed(exit_code, b"analyze log", b"stderr text")

    return fake_run


# ---------------------------------------------------------------------------
# available.
# ---------------------------------------------------------------------------
def test_available_requires_both_analyze_and_java(tmp_path: Path) -> None:
    assert GhidraClient(home=None, java=None).available is False
    client = _client(tmp_path)
    assert client.available is True
    client.java = None
    assert client.available is False


# ---------------------------------------------------------------------------
# analyze_binary guards.
# ---------------------------------------------------------------------------
def test_analyze_binary_without_ghidra_is_capability_unavailable(tmp_path: Path) -> None:
    client = GhidraClient(home=None, java=None)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "capability_unavailable"


def test_analyze_binary_reports_a_missing_binary(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(tmp_path / "absent.exe", tmp_path / "proj")
    assert caught.value.code == "not_found"


def test_analyze_binary_wraps_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _writing_run(None, exit_code=1))
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1


def test_analyze_binary_can_keep_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """delete_project=False omits -deleteProject so the project survives the run."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        calls.append([str(part) for part in cmd])
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    payload = client.analyze_binary(
        _binary(tmp_path), tmp_path / "proj", delete_project=False
    )
    assert "-deleteProject" not in calls[0]
    assert payload["project_dir"].endswith("proj")
    assert "completed" in payload["note"]


# ---------------------------------------------------------------------------
# symbols / xrefs export paths.
# ---------------------------------------------------------------------------
def test_symbols_exports_items(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _writing_run('{"items": []}', exit_code=0)
    )
    client = _client(tmp_path)
    payload = client.symbols(_binary(tmp_path), tmp_path / "proj")
    assert payload["items"] == []
    assert payload["export_path"].endswith("export_symbols.json")


def test_xrefs_exports_items(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _writing_run('{"items": []}', exit_code=0)
    )
    client = _client(tmp_path)
    payload = client.xrefs(_binary(tmp_path), tmp_path / "proj", "0x401000")
    assert payload["items"] == []
    assert payload["export_path"].endswith("export_xrefs.json")


# ---------------------------------------------------------------------------
# _export guards.
# ---------------------------------------------------------------------------
def test_export_without_ghidra_is_capability_unavailable(tmp_path: Path) -> None:
    client = GhidraClient(home=None, java=None)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "capability_unavailable"


def test_export_reports_a_missing_binary(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(tmp_path / "absent.exe", tmp_path / "proj")
    assert caught.value.code == "not_found"


def test_export_reports_a_missing_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A packaging that lost ExportJson.py fails clearly, before spawning a JVM."""
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no_scripts_here")
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "backend_error"
    assert "ExportJson.py missing" in caught.value.message


def test_export_failed_without_output_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "run_bounded", _writing_run(None, exit_code=1))
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"
    assert caught.value.details["exit_code"] == 1


def test_export_missing_json_on_a_clean_exit_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clean exit that wrote no JSON is a failed export, not an empty result."""
    monkeypatch.setattr(ghidra_client, "run_bounded", _writing_run(None, exit_code=0))
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "backend_error"
    assert "export JSON missing" in caught.value.message


def test_export_unreadable_json_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A JSON present at stat time but unreadable at open time is a structured error.

    is_file() passing then open() raising models a race or a permission flip;
    the client wraps the OSError rather than letting it escape as an internal
    incident.
    """
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _writing_run('{"items": []}', exit_code=0)
    )
    real_open = Path.open

    def flaky_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".json" and "r" in mode and "b" in mode:
            raise OSError("read denied")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", flaky_open)
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "backend_error"
    assert "unreadable" in caught.value.message


def test_export_non_object_json_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _writing_run("[1, 2, 3]", exit_code=0)
    )
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "backend_error"
    assert "must be an object" in caught.value.message


def test_export_timeout_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(5.0, [4242])

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [4242]


# ---------------------------------------------------------------------------
# _find_analyze_headless.
# ---------------------------------------------------------------------------
def test_find_analyze_headless_returns_none_without_a_home() -> None:
    assert ghidra_client._find_analyze_headless(None) is None


def test_find_analyze_headless_returns_none_when_absent(tmp_path: Path) -> None:
    assert ghidra_client._find_analyze_headless(tmp_path) is None


def test_find_analyze_headless_finds_the_launcher(tmp_path: Path) -> None:
    support = tmp_path / "support"
    support.mkdir()
    launcher = support / "analyzeHeadless"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    assert ghidra_client._find_analyze_headless(tmp_path) == launcher
