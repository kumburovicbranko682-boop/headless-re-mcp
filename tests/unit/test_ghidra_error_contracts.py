"""Ghidra adapter error contracts: honest degradation and failure classification.

The happy paths and a few failure modes (oversized/invalid JSON, pyghidra
launch/timeout) are pinned elsewhere. These lock in the classification an agent
and the doctor rely on to tell apart "Ghidra is not installed here" from "the
call failed": a backend that is not configured degrades to
``capability_unavailable`` rather than crashing, a missing binary is
``not_found``, and every analyzeHeadless failure mode -- a non-zero exit, an
export that wrote nothing, a missing or non-object export JSON, a missing
packaged script -- is a structured ``backend_error`` instead of an uncaught
exception the service would file as an internal_error incident.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed

GhidraError = ghidra_client.GhidraError


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    return home


def _available_client(tmp_path: Path) -> ghidra_client.GhidraClient:
    client = ghidra_client.GhidraClient(home=_fake_home(tmp_path))
    client.java = tmp_path / "java.exe"
    client.java.write_bytes(b"")
    assert client.available is True
    return client


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ")
    return path


def _stub_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    code: int = 0,
    json_text: str = '{"items": []}',
    write: bool = True,
) -> None:
    """Drive analyzeHeadless: choose the exit code and what lands on disk."""

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        if write:
            for arg in cmd:
                if str(arg).endswith(".json"):
                    Path(str(arg)).write_text(json_text, encoding="utf-8")
        return Completed(code, b"analyze output", b"analyze stderr")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)


# --- honest degradation: not configured / bad input ---


def test_analyze_binary_is_capability_unavailable_when_ghidra_is_not_configured(
    tmp_path: Path,
) -> None:
    """No configured launcher must degrade, not crash mid-call.

    A client with no Ghidra home has no analyzeHeadless; analyze_binary reports
    capability_unavailable so the doctor and the caller see "install Ghidra"
    rather than a stack trace from a None launcher.
    """
    client = ghidra_client.GhidraClient(home=None)
    assert client.available is False
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_export_is_capability_unavailable_when_ghidra_is_not_configured(
    tmp_path: Path,
) -> None:
    """The read tools (functions/symbols/xrefs/decompile) degrade the same way."""
    client = ghidra_client.GhidraClient(home=None)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "capability_unavailable"


def test_analyze_binary_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(tmp_path / "gone.exe", tmp_path / "project")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("path") == str(tmp_path / "gone.exe")


def test_export_reports_a_missing_binary_as_not_found(tmp_path: Path) -> None:
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(tmp_path / "gone.exe", tmp_path / "project")
    assert caught.value.code == "not_found"


# --- failure classification: every analyzeHeadless failure is backend_error ---


def test_analyze_binary_classifies_a_nonzero_exit_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_run(monkeypatch, code=1)
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless failed"
    assert caught.value.details.get("exit_code") == 1


def test_export_classifies_a_failed_run_that_wrote_nothing_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-zero exit with no export JSON is a hard failure, not a partial one."""
    _stub_run(monkeypatch, code=1, write=False)
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"


def test_export_reports_a_missing_json_after_a_clean_run_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clean exit that still produced no JSON is a backend fault, not empty data.

    analyzeHeadless can exit zero yet the postScript never wrote its output; the
    adapter must not return that as a binary with no functions -- it is a
    backend_error naming the missing artifact.
    """
    _stub_run(monkeypatch, code=0, write=False)
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON missing after postScript"


def test_export_rejects_a_json_payload_that_is_not_an_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The export must be a JSON object; a bare array is a backend_error.

    Everything downstream reads named fields off the payload, so a top-level
    array (or scalar) that slipped out of the script is refused here rather than
    handed on to raise a confusing KeyError later.
    """
    _stub_run(monkeypatch, code=0, json_text="[1, 2, 3]")
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON must be an object"


def test_export_reports_a_missing_packaged_script_as_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A packaging defect that drops ExportJson.py is named, not a cryptic failure.

    The export script ships with the package; if it is not on disk the adapter
    says so as a backend_error before launching a JVM that would fail opaquely.
    """
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no_scripts")
    client = _available_client(tmp_path)
    with pytest.raises(GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "ExportJson.py missing" in caught.value.message


def test_symbols_and_xrefs_reach_the_export_and_stamp_the_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """symbols/xrefs delegate to the export and carry the standard path fields.

    They are thin wrappers over _export with a mode; a clean run must come back
    with the export_path/project_dir stamped, so a regression that broke the
    delegation (wrong mode, dropped call) surfaces here.
    """
    _stub_run(monkeypatch, code=0)
    client = _available_client(tmp_path)

    symbols = client.symbols(_binary(tmp_path), tmp_path / "project_symbols")
    xrefs = client.xrefs(_binary(tmp_path), tmp_path / "project_xrefs", "0x401000")

    for payload in (symbols, xrefs):
        assert payload["items"] == []
        assert payload["export_path"].endswith(".json")
        assert "project_dir" in payload
