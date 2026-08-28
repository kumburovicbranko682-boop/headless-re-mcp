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


def _capture_timeout(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        captured["timeout"] = kwargs.get("timeout")
        for arg in cmd:
            if str(arg).endswith(".json"):
                Path(str(arg)).write_text('{"items": []}', encoding="utf-8")
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(ghidra_client, "run_bounded", fake_run)
    return captured


def test_ghidra_clamps_a_caller_timeout_the_agent_transport_left_unbounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timeout past the schema ceiling is clamped, matching the sibling adapters.

    The ghidra tool schemas declare ``0 < timeout <= 600`` but the agent
    transport calls handlers straight from model arguments with no schema
    enforcement. Without a clamp a wedged analyzeHeadless -- a JVM analysing a
    large binary -- would hold a worker and a core for as long as the caller
    named. r2/jadx/apktool/jsre all clamp; ghidra used to be the exception.
    """
    client = _client(tmp_path)
    captured = _capture_timeout(monkeypatch)
    client.functions(_binary(tmp_path), tmp_path / "project", timeout=10**9)
    assert captured["timeout"] == ghidra_client._MAX_TIMEOUT_S


@pytest.mark.parametrize("bad", [0.0, -5.0, float("nan")])
def test_ghidra_refuses_a_non_positive_timeout_before_launching_the_jvm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: float
) -> None:
    """A zero/negative/NaN deadline is a bad parameter, not a backend timeout.

    Left unchecked it reaches run_bounded, which launches analyzeHeadless only
    to kill it on the first loop iteration and report a misleading ``timeout``
    for what is really an ``invalid_params`` mistake.
    """
    client = _client(tmp_path)

    def must_not_spawn(cmd: list[str], **kwargs: Any) -> Completed:
        raise AssertionError("run_bounded was reached despite an invalid timeout")

    monkeypatch.setattr(ghidra_client, "run_bounded", must_not_spawn)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project", timeout=bad)
    assert caught.value.code == "invalid_params"


def test_ghidra_maps_an_unlaunchable_headless_to_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A launcher present at discovery but unexecutable at spawn is a backend fault.

    analyzeHeadless can be found (so availability passes) yet fail to exec -- not
    marked +x, or gone between discovery and Popen -- which surfaces as OSError.
    Uncaught it becomes an opaque internal_error incident; the sibling run_bounded
    adapters all map it to backend_error, and ghidra must agree.
    """
    client = _client(tmp_path)

    def refuse_to_launch(cmd: list[str], **kwargs: Any) -> Completed:
        raise OSError("Exec format error")

    monkeypatch.setattr(ghidra_client, "run_bounded", refuse_to_launch)
    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert "analyzeHeadless" in caught.value.message


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


def test_an_unconfigured_client_refuses_before_touching_the_filesystem(tmp_path: Path) -> None:
    """No Ghidra home means capability_unavailable, not a confusing spawn error.

    Both entry points -- the analyze pass and every export -- must refuse up
    front, and the refusal must not have created a project directory the
    operator would then wonder about.
    """
    client = ghidra_client.GhidraClient(home=None)
    project = tmp_path / "project"

    with pytest.raises(ghidra_client.GhidraError) as analyze_err:
        client.analyze_binary(_binary(tmp_path), project)
    with pytest.raises(ghidra_client.GhidraError) as export_err:
        client.functions(_binary(tmp_path), project)

    assert analyze_err.value.code == "capability_unavailable"
    assert export_err.value.code == "capability_unavailable"
    assert not project.exists()


def test_a_missing_binary_is_not_found_for_analyze_and_export(tmp_path: Path) -> None:
    client = _client(tmp_path)
    ghost = tmp_path / "gone.exe"

    with pytest.raises(ghidra_client.GhidraError) as analyze_err:
        client.analyze_binary(ghost, tmp_path / "project")
    with pytest.raises(ghidra_client.GhidraError) as export_err:
        client.symbols(ghost, tmp_path / "project")

    assert analyze_err.value.code == "not_found"
    assert export_err.value.code == "not_found"
    assert analyze_err.value.details["path"] == str(ghost)


def test_a_failed_analyze_reports_the_exit_code_and_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        lambda cmd, **kwargs: Completed(2, b"log", b"missing jdk"),
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.analyze_binary(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2
    assert "missing jdk" in caught.value.details["stderr"]


def test_symbols_and_xrefs_ask_the_postscript_for_their_own_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each wrapper must select its export mode, and an int address goes as hex.

    The postScript dispatches on the mode argv token, so a wrapper passing the
    wrong one would return the wrong listing under the right tool name. The
    xref address crosses into Jython as text; an int must arrive as 0x-hex so
    the script parses the same value the caller held.
    """
    calls = _capture_run(monkeypatch)
    client = _client(tmp_path)
    binary = _binary(tmp_path)

    client.symbols(binary, tmp_path / "project")
    client.xrefs(binary, tmp_path / "project", 0x401000)

    symbols_cmd, xrefs_cmd = calls
    script = symbols_cmd.index("ExportJson.py")
    assert symbols_cmd[script + 1] == "symbols"
    script = xrefs_cmd.index("ExportJson.py")
    assert xrefs_cmd[script + 1] == "xrefs"
    assert "0x401000" in xrefs_cmd


def test_a_package_missing_its_postscript_refuses_instead_of_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken install must be named before a JVM is started against it."""
    monkeypatch.setattr(ghidra_client, "_SCRIPT_DIR", tmp_path / "no-scripts")
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "ExportJson.py missing" in caught.value.message


def test_a_failed_run_that_wrote_nothing_is_an_export_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        lambda cmd, **kwargs: Completed(1, b"log tail", b"script crashed"),
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "analyzeHeadless export failed"
    assert caught.value.details["exit_code"] == 1


def test_a_clean_exit_without_the_export_file_is_still_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 0 with no JSON is a postScript that never ran, not an empty result."""
    monkeypatch.setattr(
        ghidra_client,
        "run_bounded",
        lambda cmd, **kwargs: Completed(0, b"ok", b""),
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "export JSON missing after postScript" in caught.value.message


def test_an_export_file_that_cannot_be_read_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write/read race or permission flip surfaces as unreadable, not a crash."""
    _capture_run(monkeypatch)
    real_open = Path.open

    def flaky_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".json" and args[:1] == ("rb",):
            raise OSError("input/output error")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", flaky_open)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "export JSON unreadable" in caught.value.message


def test_an_export_that_is_json_but_not_an_object_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare list parses fine and then breaks every key access downstream."""
    monkeypatch.setattr(
        ghidra_client, "run_bounded", _run_writing("[1, 2, 3]", exit_code=0)
    )
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project")

    assert caught.value.code == "backend_error"
    assert "must be an object" in caught.value.message


def test_analyze_can_keep_the_project_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_run(monkeypatch)
    client = _client(tmp_path)

    client.analyze_binary(_binary(tmp_path), tmp_path / "project", delete_project=False)

    assert "-deleteProject" not in calls[0]


def test_a_timed_out_analyze_names_the_pids_that_had_to_die(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyzeHeadless is a launcher for a JVM; the timeout must report both."""
    from headless_re_mcp.backends.common.bounded_run import TimedOut

    def timing_out(cmd: list[str], **kwargs: Any) -> Completed:
        raise TimedOut(5.0, killed=[101, 102])

    monkeypatch.setattr(ghidra_client, "run_bounded", timing_out)
    client = _client(tmp_path)

    with pytest.raises(ghidra_client.GhidraError) as caught:
        client.functions(_binary(tmp_path), tmp_path / "project", timeout=5.0)

    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [101, 102]
    assert caught.value.details["timeout"] == 5.0


def test_launcher_discovery_walks_the_known_layouts_and_reports_absence(tmp_path: Path) -> None:
    """A home without analyzeHeadless yields None; a bare layout is still found.

    The discovery order mirrors real installs: support/ first (release zips),
    then the home root (some repackaged builds). None of the four present means
    the client reports unavailable rather than guessing a path.
    """
    empty_home = tmp_path / "empty"
    empty_home.mkdir()
    assert ghidra_client._find_analyze_headless(empty_home) is None
    assert ghidra_client.GhidraClient(home=empty_home).available is False

    bare_home = tmp_path / "bare"
    bare_home.mkdir()
    launcher = bare_home / "analyzeHeadless"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    assert ghidra_client._find_analyze_headless(bare_home) == launcher
