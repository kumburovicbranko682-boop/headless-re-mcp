"""Guard-path coverage for the Ghidra adapter (no real analyzeHeadless).

Complements ``test_ghidra_client.py`` (heap options, project serialization, the
decompile ``found`` signal, oversized/corrupt exports) with the error contracts
and discovery branches nothing exercised:

* ``analyze_binary`` when Ghidra is not configured (``capability_unavailable``),
  on a missing binary (``not_found``), on a non-zero analyzeHeadless exit
  (``backend_error``), and with ``delete_project=False`` (no ``-deleteProject``).
* the ``symbols`` and ``xrefs`` public methods, which pick their postScript mode.
* ``_export`` when Ghidra is not configured / the binary is missing / the bundled
  ExportJson.py is gone, when analyzeHeadless times out, when a non-zero exit
  wrote no file, when a clean exit wrote no file, when the export is unreadable,
  and when the export JSON is not an object.
* ``_find_analyze_headless`` with no home, an empty home, and a launcher that is
  not the ``.bat`` first candidate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.ghidra.client import (
    GhidraClient,
    GhidraError,
    _find_analyze_headless,
)


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


def _run_returning(
    recorded: list[list[str]],
    *,
    exit_code: int = 0,
    write: str | None = '{"items": [], "count": 0}',
) -> Any:
    """A run_bounded stub that records argv and optionally writes the export."""

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        argv = [str(part) for part in cmd]
        recorded.append(argv)
        if write is not None:
            for arg in argv:
                if arg.endswith(".json"):
                    Path(arg).write_text(write, encoding="utf-8")
        return Completed(exit_code, b"analyze log", b"stderr text")

    return fake_run


# --- analyze_binary ----------------------------------------------------------


def test_analyze_binary_without_ghidra_is_capability_unavailable(tmp_path: Path) -> None:
    """No home means no analyzeHeadless; analyze cannot run."""
    client = GhidraClient(home=None)
    assert client.available is False
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_analyze_binary_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(tmp_path / "gone.exe", tmp_path / "project")
    assert caught.value.code == "not_found"


def test_analyze_binary_maps_a_nonzero_exit_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyze runs no postScript, so a non-zero exit is simply a failed import."""
    recorded: list[list[str]] = []
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_returning(recorded, exit_code=1))
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless failed"
    assert caught.value.details["exit_code"] == 1


def test_analyze_binary_can_keep_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """delete_project=False must not pass -deleteProject to analyzeHeadless."""
    recorded: list[list[str]] = []
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_returning(recorded))
    client = _client(tmp_path)
    client.analyze_binary(_binary(tmp_path), tmp_path / "project", delete_project=False)
    assert len(recorded) == 1
    assert "-import" in recorded[0]
    assert "-deleteProject" not in recorded[0]


# --- symbols / xrefs public methods ------------------------------------------


def test_symbols_asks_the_postscript_for_the_symbols_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: list[list[str]] = []
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_returning(recorded))
    client = _client(tmp_path)
    payload = client.symbols(_binary(tmp_path), tmp_path / "project")
    assert payload["items"] == []
    assert "symbols" in recorded[0]


def test_xrefs_asks_the_postscript_for_the_xrefs_mode_and_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded: list[list[str]] = []
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_returning(recorded))
    client = _client(tmp_path)
    payload = client.xrefs(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["items"] == []
    assert "xrefs" in recorded[0]
    assert "0x401000" in recorded[0]


# --- _export error contracts -------------------------------------------------


def test_export_without_ghidra_is_capability_unavailable(tmp_path: Path) -> None:
    client = GhidraClient(home=None)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_export_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(tmp_path / "gone.exe", tmp_path / "project")
    assert caught.value.code == "not_found"


def test_export_reports_a_missing_bundled_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ExportJson.py ships in the package; if it is gone, say so before the JVM."""
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no-scripts")
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "ExportJson.py missing" in caught.value.message


def test_export_reports_a_nonzero_exit_with_no_file_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed run that wrote nothing is a backend error, not an empty listing."""
    recorded: list[list[str]] = []
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _run_returning(recorded, exit_code=1, write=None)
    )
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"
    assert caught.value.details["exit_code"] == 1


def test_export_reports_a_clean_exit_with_no_file_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zero exit that still left no JSON is a postScript that never wrote."""
    recorded: list[list[str]] = []
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _run_returning(recorded, exit_code=0, write=None)
    )
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON missing after postScript"


def test_export_reports_an_unreadable_json_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file exists but the read raises OSError: a backend error, not a crash."""
    recorded: list[list[str]] = []
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_returning(recorded))
    real_open = Path.open

    def failing_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        # Only the client's read of the export ("rb") fails; the stub's
        # write_text ("w") still works, so the file is present but unreadable.
        if "b" in mode and "r" in mode and self.suffix == ".json":
            raise OSError("simulated unreadable export")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "unreadable" in caught.value.message


def test_export_reports_a_non_object_json_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ExportJson.py always writes an object; a bare array is a contract break."""
    recorded: list[list[str]] = []
    monkeypatch.setattr(ghidra_client, "run_bounded", _run_returning(recorded, write="[]"))
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON must be an object"


def test_export_maps_a_timeout_to_a_timeout_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyzeHeadless outran its deadline; the killed process tree is reported."""

    def timing_out(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        raise TimedOut(timeout=180.0, killed=[4321, 4322])

    monkeypatch.setattr(ghidra_client, "run_bounded", timing_out)
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [4321, 4322]


# --- caller timeout clamping -------------------------------------------------


def _run_capturing_timeout(captured: dict[str, float], recorded: list[list[str]]) -> Any:
    """A run_bounded stub that records the timeout it was granted."""

    def fake_run(cmd: list[str], *, timeout: float, **kwargs: Any) -> Completed:
        del kwargs
        captured["timeout"] = timeout
        argv = [str(part) for part in cmd]
        recorded.append(argv)
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text('{"items": [], "count": 0}', encoding="utf-8")
        return Completed(0, b"analyze log", b"")

    return fake_run


@pytest.mark.parametrize("bad", [0.0, -1.0, float("nan")])
def test_analyze_binary_rejects_a_non_positive_or_nan_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: float
) -> None:
    """A bad deadline is invalid_params, and the JVM is never launched for it.

    The ghidra.* schemas declare 0 < timeout <= 600, but the agent transport
    calls handlers straight from model arguments with no schema enforcement.
    """

    def must_not_launch(cmd: list[str], **kwargs: Any) -> Completed:
        raise AssertionError("run_bounded must not be reached for a bad timeout")

    monkeypatch.setattr(ghidra_client, "run_bounded", must_not_launch)
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project", timeout=bad)
    assert caught.value.code == "invalid_params"


def test_analyze_binary_caps_an_oversized_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timeout past the schema ceiling is capped, not passed straight to cdb."""
    captured: dict[str, float] = {}
    recorded: list[list[str]] = []
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _run_capturing_timeout(captured, recorded)
    )
    client = _client(tmp_path)
    client.analyze_binary(_binary(tmp_path), tmp_path / "project", timeout=100_000.0)
    assert captured["timeout"] == ghidra_client._MAX_TIMEOUT_S


def test_export_caps_an_oversized_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The export path shares the _run_headless choke point, so it is bounded too."""
    captured: dict[str, float] = {}
    recorded: list[list[str]] = []
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _run_capturing_timeout(captured, recorded)
    )
    client = _client(tmp_path)
    client.functions(_binary(tmp_path), tmp_path / "project", timeout=100_000.0)
    assert captured["timeout"] == ghidra_client._MAX_TIMEOUT_S


# --- _find_analyze_headless --------------------------------------------------


def test_find_analyze_headless_returns_none_without_a_home() -> None:
    assert _find_analyze_headless(None) is None


def test_find_analyze_headless_returns_none_when_the_home_has_no_launcher(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "not-ghidra"
    empty.mkdir()
    assert _find_analyze_headless(empty) is None


def test_find_analyze_headless_accepts_a_non_bat_launcher(tmp_path: Path) -> None:
    """A POSIX install has support/analyzeHeadless, not the .bat first candidate."""
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    launcher = support / "analyzeHeadless"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    assert _find_analyze_headless(home) == launcher
