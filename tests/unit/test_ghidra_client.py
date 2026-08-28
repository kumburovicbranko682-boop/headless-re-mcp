"""Ghidra adapter behaviour without a real analyzeHeadless install."""

from __future__ import annotations

import ast
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Lock
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.tools.ghidra import build_ghidra_tools


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


def _capture_run(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        argv = [str(part) for part in cmd]
        calls.append(argv)
        for arg in argv:
            if arg.endswith(".json"):
                Path(arg).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"analyze ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return calls


def test_ghidra_analyze_deletes_the_project_other_tools_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The catalog told the model to run analyze first so the rest could reuse it.

    Measured here: analyzeHeadless is invoked with -import and -deleteProject,
    then functions is invoked the same way against the same directory. The first
    call's project is gone before the second starts, so the recommended sequence
    is two full headless imports, default 120s then 180s, for one listing.
    """
    client = _client(tmp_path)
    calls = _capture_run(monkeypatch)
    project = tmp_path / "project"
    binary = _binary(tmp_path)

    analyzed = client.analyze_binary(binary, project)
    listed = client.functions(binary, project)

    assert len(calls) == 2
    analyze_cmd, functions_cmd = calls
    assert "-import" in analyze_cmd
    assert "-deleteProject" in analyze_cmd
    assert "-import" in functions_cmd
    assert "-deleteProject" in functions_cmd
    assert "deleted" in analyzed["note"]
    assert "import" in analyzed["note"]
    assert listed["export_path"]


def test_ghidra_serializes_clients_using_the_same_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _fake_home(tmp_path)
    java = tmp_path / "java.exe"
    java.write_bytes(b"")
    clients = [ghidra_client.GhidraClient(home=home, java=java) for _ in range(2)]
    project = tmp_path / "project"
    binary = _binary(tmp_path)
    state_lock = Lock()
    first_entered = Event()
    release_first = Event()
    calls = 0
    active = 0
    max_active = 0

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        nonlocal calls, active, max_active
        del kwargs
        with state_lock:
            calls += 1
            call_number = calls
            active += 1
            max_active = max(max_active, active)
        if call_number == 1:
            first_entered.set()
            release_first.wait(timeout=0.5)
        else:
            release_first.set()
        try:
            for arg in cmd:
                if str(arg).endswith(".json"):
                    Path(arg).write_text('{"items": []}', encoding="utf-8")
            return Completed(0, b"ok", b"")
        finally:
            with state_lock:
                active -= 1

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(clients[0].functions, binary, project)
        assert first_entered.wait(timeout=1.0)
        second = pool.submit(clients[1].functions, binary, project)
        assert first.result(timeout=2.0)["items"] == []
        assert second.result(timeout=2.0)["items"] == []

    assert calls == 2
    assert max_active == 1


def test_ghidra_analyze_description_does_not_tell_the_model_to_run_it_first() -> None:
    """A caller that believes the other tools read this project will spend minutes twice.

    The live description said they 'read what this produced, so run it first'.
    That is the opposite of -deleteProject.
    """
    source = Path(build_ghidra_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    described = ""
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == "ghidra.analyze"
                ):
                    described = ast.get_docstring(node) or ""
    assert described, "ghidra.analyze must describe itself"
    lowered = described.casefold()
    assert "delete" in lowered
    assert "imports the binary again" in lowered
    assert "do not read what this produced" in lowered
    assert "run it first" not in lowered


def _tool_docstring(name: str) -> str:
    source = Path(build_ghidra_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_ghidra_list_descriptions_name_the_fields_the_export_returns() -> None:
    """The catalog said address/size; a 5000-function export had neither.

    Measured against ExportJson.py: 256 of 5000 functions, 0 items had address
    or size, all 256 had entry and body_size. Looking for address after a
    successful list reads as Ghidra finding no addresses. Symbols have type,
    not namespace. Xrefs are getReferencesTo only.
    """
    functions = _tool_docstring("ghidra.functions")
    assert "entry" in functions
    assert "body_size" in functions
    assert "has_more" in functions
    assert "address, size and name" not in functions

    symbols = _tool_docstring("ghidra.symbols")
    assert "type" in symbols
    assert "has_more" in symbols
    assert "with address and namespace" not in symbols

    xrefs = _tool_docstring("ghidra.xrefs")
    assert "from" in xrefs
    assert "has_more" in xrefs
    assert "to and from" not in xrefs
    assert "Outgoing refs are not listed" in xrefs

    decompile = _tool_docstring("ghidra.decompile")
    assert "decompiled" in decompile
    assert "truncated" in decompile


def test_ghidra_refuses_an_oversized_export_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra_client, "_MAX_EXPORT_BYTES", 64)
    real_stat = Path.stat

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text('{"items": ["' + ("x" * 80) + '"]}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    def stale_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        result = real_stat(path, *args, **kwargs)
        if path.suffix == ".json":
            fields = list(result)
            fields[6] = 1
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    monkeypatch.setattr(Path, "stat", stale_stat)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "too_large"


@pytest.mark.parametrize(
    ("payload", "error_type"),
    [
        (b"\xff", "UnicodeDecodeError"),
        (b"{", "JSONDecodeError"),
    ],
)
def test_ghidra_reports_corrupt_export_as_a_backend_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    error_type: str,
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_bytes(payload)
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "export JSON invalid"
    assert error_type in str(caught.value.details["error"])


# --- configuration and input guards -----------------------------------------
#
# Everything below drives the adapter without a real analyzeHeadless: the guards
# refuse before any spawn, the export failure branches map each backend outcome
# to a structured code, and discovery/carve degrade rather than raise. These are
# the ELF/Mach-O line's error contract, proven on a device- and Ghidra-free VM.


def test_an_unconfigured_client_is_unavailable_and_declines(tmp_path: Path) -> None:
    # home=None means analyzeHeadless is never found, so the client is
    # unavailable regardless of whether a java happens to sit on PATH; both the
    # analyze and the export entry points must refuse with capability_unavailable
    # before attempting to spawn anything.
    client = ghidra_client.GhidraClient(home=None)
    assert client.available is False
    with pytest.raises(ghidra_client.GhidraError) as analyze:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert analyze.value.code == "capability_unavailable"
    with pytest.raises(ghidra_client.GhidraError) as export:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert export.value.code == "capability_unavailable"


def test_a_missing_binary_is_not_found_before_any_spawn(tmp_path: Path) -> None:
    client = _client(tmp_path)
    missing = tmp_path / "gone.bin"
    with pytest.raises(ghidra_client.GhidraError) as analyze:
        client.analyze_binary(missing, tmp_path / "project")
    assert analyze.value.code == "not_found"
    with pytest.raises(ghidra_client.GhidraError) as export:
        client.functions(missing, tmp_path / "project")
    assert export.value.code == "not_found"


def test_symbols_xrefs_and_decompile_each_run_through_the_shared_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The three thin wrappers forward to _export with their own mode; drive each
    # so the mode threads through and the enriched payload comes back with the
    # export path the tool layer surfaces.
    _capture_run(monkeypatch)
    client = _client(tmp_path)
    binary = _binary(tmp_path)
    project = tmp_path / "project"
    assert client.symbols(binary, project)["export_path"]
    assert client.xrefs(binary, project, 0x1000)["export_path"]
    assert client.decompile(binary, project, 0x1000)["export_path"]


def test_analyze_binary_maps_a_nonzero_exit_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(3, b"", b"analyze blew up")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 3


def test_analyze_binary_without_delete_keeps_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # delete_project=False must drop the -deleteProject flag so a caller can
    # inspect the project afterwards; the default True path is pinned elsewhere.
    calls = _capture_run(monkeypatch)
    client = _client(tmp_path)
    client.analyze_binary(_binary(tmp_path), tmp_path / "project", delete_project=False)
    assert "-deleteProject" not in calls[0]


def test_export_failure_with_no_output_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(1, b"", b"import failed")  # non-zero and writes no json

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 1


def test_export_missing_json_after_a_clean_exit_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, b"ok", b"")  # clean exit but the postScript wrote nothing

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "missing after postScript" in caught.value.message


def test_export_unreadable_json_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The postScript wrote a real file, but reading it back raises OSError; the
    # adapter maps that to backend_error rather than letting it escape.
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    real_open = Path.open

    def boom_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".json" and "r" in mode and "b" in mode:
            raise OSError("EIO")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    monkeypatch.setattr(Path, "open", boom_open)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "unreadable" in caught.value.message


def test_export_non_object_payload_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text("[1, 2, 3]", encoding="utf-8")  # a JSON array
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "must be an object" in caught.value.message


def test_export_missing_script_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The packaged ExportJson.py is the postScript; if it is not on disk the
    # adapter refuses up front rather than launching a headless run that would
    # find no script to execute.
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no-scripts")
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "ExportJson.py missing" in caught.value.message


def test_a_deadline_maps_to_timeout_with_the_killed_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd
        raise TimedOut(kwargs.get("timeout", 1.0), [4321])

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [4321]


# --- discovery and fat-slice carving ----------------------------------------


def test_find_analyze_headless_returns_none_when_absent(tmp_path: Path) -> None:
    # A home with a support/ dir but no launcher: neither the support layout nor
    # the flattened root matches, so discovery falls through to None and the
    # client reports itself unavailable rather than binding a phantom path.
    empty = tmp_path / "ghidra-empty"
    (empty / "support").mkdir(parents=True)
    client = ghidra_client.GhidraClient(home=empty)
    assert client.analyze is None
    assert client.available is False


def test_carve_slice_maps_an_os_error_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A valid slice span, but the copy raises OSError: carving must surface
    # backend_error rather than let the read escape the adapter.
    monkeypatch.setattr(ghidra_client, "macho_slice_span", lambda binary, arch: (0, 16))
    binary = tmp_path / "fat.bin"
    binary.write_bytes(b"\x00" * 32)
    real_open = Path.open

    def boom_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if "b" in mode:
            raise OSError("EIO")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", boom_open)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        ghidra_client._carve_slice(binary, tmp_path / "project", Architecture.X64)
    assert caught.value.code == "backend_error"
    assert "carving fat slice failed" in caught.value.message
