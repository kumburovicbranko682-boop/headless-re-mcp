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
from headless_re_mcp.backends.common.bounded_run import Completed
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


def _capture_env(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    envs: list[dict[str, str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        envs.append(dict(kwargs.get("env") or {}))
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return envs


def test_a_valid_max_heap_becomes_a_clean_java_tool_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envs = _capture_env(monkeypatch)
    client = _client(tmp_path)
    client.functions(_binary(tmp_path), tmp_path / "project", max_heap="512m")
    assert envs and envs[0]["JAVA_TOOL_OPTIONS"] == "-Xmx512m"


@pytest.mark.parametrize(
    "hostile",
    [
        "2G -XX:OnOutOfMemoryError=touch /tmp/pwned",
        "1g -javaagent:/tmp/evil.jar",
        "512m\n-Dfoo=bar",
        "$(reboot)",
        "",
    ],
)
def test_a_hostile_max_heap_is_rejected_before_any_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hostile: str
) -> None:
    """max_heap is spliced into JAVA_TOOL_OPTIONS, so it must be a bare size.

    The JVM reads that variable as a whitespace-separated option list; anything
    other than a heap size could inject -javaagent: or an OnOutOfMemoryError
    command hook. Rejection must happen before analyzeHeadless is spawned.
    """
    envs = _capture_env(monkeypatch)
    client = _client(tmp_path)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project", max_heap=hostile)
    assert caught.value.code == "invalid_params"
    assert envs == []


@pytest.mark.parametrize(
    "hostile",
    ["2G -XX:OnOutOfMemoryError=touch /tmp/pwned", "$(reboot)", ""],
)
def test_max_heap_is_invalid_params_before_the_capability_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hostile: str
) -> None:
    """A host without Ghidra must still call a bad max_heap invalid_params.

    max_heap is a property of the request, spliced into JAVA_TOOL_OPTIONS. Left
    inside _run_headless -- after the capability_unavailable gate -- a host with
    no analyzeHeadless answered capability_unavailable for the same hostile value
    that a configured host rejects as invalid_params: one bad input, two
    verdicts. Every entry point (analyze plus the four export modes) now judges
    max_heap before the gate, so both hosts agree and nothing ever spawns.
    """
    calls = _capture_run(monkeypatch)
    unavailable = ghidra_client.GhidraClient(home=None)
    assert unavailable.available is False
    binary = _binary(tmp_path)
    project = tmp_path / "p"
    invocations = (
        lambda: unavailable.analyze_binary(binary, project, max_heap=hostile),
        lambda: unavailable.functions(binary, project, max_heap=hostile),
        lambda: unavailable.symbols(binary, project, max_heap=hostile),
        lambda: unavailable.xrefs(binary, project, "0x1000", max_heap=hostile),
        lambda: unavailable.decompile(binary, project, "0x1000", max_heap=hostile),
    )
    for invoke in invocations:
        with pytest.raises(ghidra_client.GhidraError) as caught:
            invoke()
        assert caught.value.code == "invalid_params"
    assert calls == []


@pytest.mark.parametrize("address", ["", "   ", "\t"])
def test_xrefs_and_decompile_require_an_address_before_the_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    """An empty address must not cost a full analyzeHeadless import.

    address drives both exports; the Jython getAddress("") yields nothing, so a
    blank value returns an empty listing -- but only after importing and
    analysing the binary, minutes on a large one. The tool signature is a
    required str with no min_length, so pydantic sends "" (not None) and the
    service's ``address is None`` guard never fires. Rejecting it in the client
    before the gate mirrors apk.xrefs/methods; the tripwire run_bounded proves
    neither export spawns.
    """
    calls = _capture_run(monkeypatch)
    client = _client(tmp_path)
    binary = _binary(tmp_path)
    project = tmp_path / "project"
    with pytest.raises(ghidra_client.GhidraError) as xref_err:
        client.xrefs(binary, project, address)
    assert xref_err.value.code == "invalid_params"
    with pytest.raises(ghidra_client.GhidraError) as decomp_err:
        client.decompile(binary, project, address)
    assert decomp_err.value.code == "invalid_params"
    assert calls == []


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
