"""Capability, not-found, and export-failure arms of the Ghidra client.

The env/heap wiring, project serialization, decompile ``found`` derivation, and
the corrupt/too-large/empty-export contracts already live in
``test_ghidra_client.py``. This file covers what it skips: the analyze_binary
guards, the ``symbols``/``xrefs`` delegators, the ``_export`` capability/
not-found/script-missing/missing-JSON/non-object arms, the ``_run_headless``
no-delete branch and timeout, and ``_find_analyze_headless`` discovery. A
stubbed ``run_bounded`` stands in for analyzeHeadless so no JVM runs.
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


def _writes(payload: str, code: int) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text(payload, encoding="utf-8")
        return Completed(code, b"log", b"err")

    return fake_run


def _writes_nothing(code: int) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        return Completed(code, b"log", b"err")

    return fake_run


# ---------------------------------------------------------------------------
# analyze_binary
# ---------------------------------------------------------------------------


def test_analyze_binary_refuses_when_unavailable(tmp_path: Path) -> None:
    client = GhidraClient()  # no home -> no analyzeHeadless
    with pytest.raises(GhidraError) as raised:
        client.analyze_binary(tmp_path / "a.exe", tmp_path / "proj")
    assert raised.value.code == "capability_unavailable"


def test_analyze_binary_reports_a_missing_binary(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as raised:
        client.analyze_binary(tmp_path / "missing.exe", tmp_path / "proj")
    assert raised.value.code == "not_found"


def test_analyze_binary_wraps_a_nonzero_exit(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "run_bounded", _writes_nothing(1))
    with pytest.raises(GhidraError) as raised:
        client.analyze_binary(_binary(tmp_path), tmp_path / "proj")
    assert raised.value.code == "backend_error"
    assert raised.value.details["exit_code"] == 1


def test_analyze_binary_omits_delete_project_when_asked(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client = _client(tmp_path)
    captured: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        captured.append([str(part) for part in cmd])
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    result = client.analyze_binary(
        _binary(tmp_path), tmp_path / "proj", delete_project=False
    )
    assert "-deleteProject" not in captured[0]
    assert result["project_dir"].endswith("proj")


# ---------------------------------------------------------------------------
# symbols / xrefs delegators
# ---------------------------------------------------------------------------


def test_symbols_delegates_and_returns_items(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "run_bounded", _writes('{"items": []}', 0))
    result = client.symbols(_binary(tmp_path), tmp_path / "proj")
    assert result["items"] == []


def test_xrefs_delegates_and_returns_items(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "run_bounded", _writes('{"items": []}', 0))
    result = client.xrefs(_binary(tmp_path), tmp_path / "proj", "0x401000")
    assert result["items"] == []


# ---------------------------------------------------------------------------
# _export guards
# ---------------------------------------------------------------------------


def test_export_refuses_when_unavailable(tmp_path: Path) -> None:
    client = GhidraClient()
    with pytest.raises(GhidraError) as raised:
        client.functions(tmp_path / "a.exe", tmp_path / "proj")
    assert raised.value.code == "capability_unavailable"


def test_export_reports_a_missing_binary(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(GhidraError) as raised:
        client.functions(tmp_path / "missing.exe", tmp_path / "proj")
    assert raised.value.code == "not_found"


def test_export_reports_a_missing_script(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no-scripts")
    with pytest.raises(GhidraError) as raised:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert raised.value.code == "backend_error"
    assert "ExportJson.py missing" in raised.value.message


def test_export_wraps_a_nonzero_exit_with_no_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "run_bounded", _writes_nothing(1))
    with pytest.raises(GhidraError) as raised:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert raised.value.code == "backend_error"
    assert raised.value.details["exit_code"] == 1


def test_export_reports_missing_json_on_a_clean_exit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "run_bounded", _writes_nothing(0))
    with pytest.raises(GhidraError) as raised:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert raised.value.code == "backend_error"
    assert "export JSON missing" in raised.value.message


def test_export_rejects_a_non_object_payload(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client(tmp_path)
    monkeypatch.setattr(ghidra_client, "run_bounded", _writes("[]", 0))
    with pytest.raises(GhidraError) as raised:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert raised.value.code == "backend_error"
    assert "must be an object" in raised.value.message


# ---------------------------------------------------------------------------
# _run_headless timeout
# ---------------------------------------------------------------------------


def test_run_headless_maps_a_timeout(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client(tmp_path)

    def boom(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(5.0, [77])

    monkeypatch.setattr(ghidra_client, "run_bounded", boom)
    with pytest.raises(GhidraError) as raised:
        client.functions(_binary(tmp_path), tmp_path / "proj")
    assert raised.value.code == "timeout"
    assert raised.value.details["killed_pids"] == [77]


# ---------------------------------------------------------------------------
# _find_analyze_headless
# ---------------------------------------------------------------------------


def test_find_analyze_headless_is_none_without_a_home() -> None:
    assert ghidra_client._find_analyze_headless(None) is None


def test_find_analyze_headless_is_none_when_no_launcher_exists(tmp_path: Path) -> None:
    empty = tmp_path / "ghidra"
    empty.mkdir()
    assert ghidra_client._find_analyze_headless(empty) is None


def test_find_analyze_headless_returns_the_launcher(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    found = ghidra_client._find_analyze_headless(home)
    assert found == home / "support" / "analyzeHeadless.bat"


# ---------------------------------------------------------------------------
# GhidraError
# ---------------------------------------------------------------------------


def test_ghidra_error_is_a_runtime_error_carrying_code_and_details() -> None:
    err = GhidraError("not_found", "gone", path="/x")
    assert isinstance(err, RuntimeError)
    assert err.code == "not_found"
    assert err.details["path"] == "/x"
