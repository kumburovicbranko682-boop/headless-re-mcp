"""GhidraClient must fail closed before, during, and after analyzeHeadless.

The main adapter suite drives the happy export and the timeout/too-large/empty
guards. This module covers the entry-point and post-run arms it leaves open:

* ``_require_address`` refusing a boolean up front,
* ``analyze_binary`` reporting an unconfigured tool, a missing binary, a failed
  run, and dropping ``-deleteProject`` when asked to keep the project,
* ``_export_unlocked`` reporting an unconfigured tool, a missing binary, a
  missing bundled script, a failed run that wrote nothing, a clean run that
  wrote nothing, an unreadable export, and a non-object export,
* ``_run_headless`` mapping a deadline to a structured ``timeout``, and
* ``_find_analyze_headless`` returning ``None`` when the home has no launcher.

No real analyzeHeadless is installed; a fake home makes the client ``available``
and ``run_bounded`` is monkeypatched so no JVM is launched.
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


# --------------------------------------------------------------------------
# _require_address
# --------------------------------------------------------------------------


def test_require_address_rejects_a_boolean() -> None:
    with pytest.raises(ghidra_client.GhidraError) as caught:
        ghidra_client._require_address(True)
    assert caught.value.code == "invalid_params"


# --------------------------------------------------------------------------
# analyze_binary
# --------------------------------------------------------------------------


def test_analyze_binary_needs_a_configured_tool(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.analyze = None
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_analyze_binary_reports_a_missing_binary(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(tmp_path / "absent.exe", tmp_path / "project")
    assert caught.value.code == "not_found"


def test_analyze_binary_maps_a_failed_run_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"analyze log", b"import failed")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1


def test_analyze_binary_can_keep_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        seen.append([str(part) for part in cmd])
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    payload = client.analyze_binary(
        _binary(tmp_path), tmp_path / "project", delete_project=False
    )
    assert "-deleteProject" not in seen[0]
    assert payload["project_dir"].endswith("project")


# --------------------------------------------------------------------------
# _export_unlocked pre-run guards
# --------------------------------------------------------------------------


def test_export_needs_a_configured_tool(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.analyze = None
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_export_reports_a_missing_binary(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(tmp_path / "absent.exe", tmp_path / "project")
    assert caught.value.code == "not_found"


def test_export_reports_a_missing_bundled_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "noscripts"
    empty.mkdir()
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", empty)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "ExportJson.py" in caught.value.message


# --------------------------------------------------------------------------
# _export_unlocked post-run guards
# --------------------------------------------------------------------------


def test_export_reports_a_failed_run_that_wrote_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(1, b"analyze log", b"script blew up")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1


def test_export_reports_missing_output_after_a_clean_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "missing after postScript" in caught.value.message


def test_export_reports_an_unreadable_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text("{}", encoding="utf-8")
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)

    real_open = Path.open

    def guarded_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if self.name.endswith(".json") and "b" in mode:
            raise OSError("export unreadable")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "unreadable" in caught.value.message


def test_export_rejects_a_non_object_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text('"just a string"', encoding="utf-8")
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "must be an object" in caught.value.message


# --------------------------------------------------------------------------
# _run_headless timeout mapping
# --------------------------------------------------------------------------


def test_run_headless_maps_a_deadline_to_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(120.0, [4321])

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [4321]


# --------------------------------------------------------------------------
# _find_analyze_headless
# --------------------------------------------------------------------------


def test_find_analyze_headless_returns_none_without_a_launcher(tmp_path: Path) -> None:
    assert ghidra_client._find_analyze_headless(tmp_path) is None


def test_find_analyze_headless_finds_a_launcher(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    found = ghidra_client._find_analyze_headless(home)
    assert found is not None
    assert found.name == "analyzeHeadless.bat"
