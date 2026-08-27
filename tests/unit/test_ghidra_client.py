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


def _capture_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        captured["env"] = kwargs.get("env")
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return captured


def test_ghidra_sets_the_heap_bound_when_no_operator_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _capture_env(monkeypatch)
    monkeypatch.delenv("JAVA_TOOL_OPTIONS", raising=False)
    client = _client(tmp_path)

    client.functions(_binary(tmp_path), tmp_path / "project")

    assert captured["env"]["JAVA_TOOL_OPTIONS"] == "-Xmx2G"


def test_ghidra_preserves_operator_java_tool_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyzeHeadless env must keep an operator's JAVA_TOOL_OPTIONS, not clobber it.

    Operators set it for a proxy, an encoding, or the JDK 17+ --add-opens Ghidra
    needs; overwriting it with only -Xmx silently breaks their runs. Ours is
    prepended so the heap bound is the default while their explicit -Xmx, which
    the JVM parses last, still wins.
    """
    captured = _capture_env(monkeypatch)
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Dfile.encoding=UTF-8 -Xmx8G")
    client = _client(tmp_path)

    client.functions(_binary(tmp_path), tmp_path / "project")

    opts = captured["env"]["JAVA_TOOL_OPTIONS"]
    assert "-Dfile.encoding=UTF-8" in opts
    assert opts.index("-Xmx2G") < opts.index("-Xmx8G")


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
    assert "found" in decompile
    assert "decompile_completed" in decompile


def _decompile_run(monkeypatch: pytest.MonkeyPatch, payload: str) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(arg).write_text(payload, encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)


def test_ghidra_decompile_reports_found_false_when_no_function_contains_the_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An address inside no function used to read as an empty function body.

    ExportJson writes decompiled "" and no function key when getFunctionContaining
    returns nothing. Without found, a caller cannot tell that from a function that
    decompiled to nothing, and an unattended pass would treat the empty string as
    the body.
    """
    _decompile_run(monkeypatch, '{"mode": "decompile", "decompiled": "", "truncated": false}')
    client = _client(tmp_path)
    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["found"] is False
    assert payload["decompiled"] == ""


def test_ghidra_decompile_reports_found_true_when_a_function_was_decompiled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _decompile_run(
        monkeypatch,
        '{"mode": "decompile", "function": "main", "entry": "0x401000",'
        ' "decompiled": "int main(){}", "truncated": false}',
    )
    client = _client(tmp_path)
    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["found"] is True
    assert payload["function"] == "main"


def test_ghidra_decompile_trusts_a_found_flag_the_script_already_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A found flag emitted by the script is not overwritten by the derivation."""
    _decompile_run(
        monkeypatch,
        '{"mode": "decompile", "found": true, "decompiled": "", "truncated": false}',
    )
    client = _client(tmp_path)
    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["found"] is True


def test_ghidra_decompile_reports_completed_true_when_c_came_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-empty C from an older script derives decompile_completed true."""
    _decompile_run(
        monkeypatch,
        '{"mode": "decompile", "function": "main", "entry": "0x401000",'
        ' "decompiled": "int main(){}", "truncated": false}',
    )
    client = _client(tmp_path)
    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["decompile_completed"] is True


def test_ghidra_decompile_flags_a_found_function_that_did_not_decompile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A found function with empty C is a failed decompile, not an empty body.

    When the decompiler times out or errors inside its 30s budget the script
    leaves decompiled "" for a function that was found. Without
    decompile_completed that reads exactly like an empty body, so an older
    script that emits no flag must derive it false from the empty C.
    """
    _decompile_run(
        monkeypatch,
        '{"mode": "decompile", "function": "main", "entry": "0x401000",'
        ' "decompiled": "", "truncated": false}',
    )
    client = _client(tmp_path)
    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["found"] is True
    assert payload["decompile_completed"] is False


def test_ghidra_decompile_trusts_a_completed_flag_the_script_already_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit decompile_completed false is not overwritten by the text.

    The new script emits decompile_completed and, when it can, decompile_error.
    Even if some C text is present, the script's own verdict wins.
    """
    _decompile_run(
        monkeypatch,
        '{"mode": "decompile", "function": "main", "entry": "0x401000",'
        ' "decompile_completed": false, "decompile_error": "timed out",'
        ' "decompiled": "partial", "truncated": false}',
    )
    client = _client(tmp_path)
    payload = client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")
    assert payload["decompile_completed"] is False
    assert payload["decompile_error"] == "timed out"


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


def _run_writing(payload: str, *, exit_code: int) -> Any:
    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text(payload, encoding="utf-8")
        return Completed(exit_code, b"analyze log", b"script blew up")

    return fake_run


def test_ghidra_does_not_call_an_empty_failed_list_export_a_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured: analyzeHeadless exit 1 plus a written {} still answered items=[].

    An unattended export treated the failed run as a binary that has no
    functions. An empty payload plus a non-zero exit is a backend error.
    """
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_writing('{"mode": "functions", "items": [], "count": 0}', exit_code=1),
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"
    assert caught.value.details["exit_code"] == 1


def test_ghidra_does_not_call_an_empty_failed_decompile_a_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_writing('{"decompiled": "", "truncated": false}', exit_code=1),
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.decompile(_binary(tmp_path), tmp_path / "project", "0x401000")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"


def test_ghidra_keeps_a_nonzero_exit_that_still_wrote_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyzeHeadless often exits 1 after a real postScript write; keep it."""
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_writing('{"items": [{"name": "main", "entry": "00401000"}], "count": 1}', exit_code=1),
    )
    client = _client(tmp_path)

    listed = client.functions(_binary(tmp_path), tmp_path / "project")

    assert listed["items"] == [{"name": "main", "entry": "00401000"}]


def test_ghidra_keeps_a_genuinely_empty_listing_on_a_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        _run_writing('{"items": [], "count": 0}', exit_code=0),
    )
    client = _client(tmp_path)

    listed = client.functions(_binary(tmp_path), tmp_path / "project")

    assert listed["items"] == []
