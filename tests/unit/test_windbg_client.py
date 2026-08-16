from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _store_cdb(tmp_path: Path) -> Path:
    path = tmp_path / "WindowsApps" / "Microsoft.WinDbg_1.0_x64__abc" / "amd64" / "cdb.exe"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ")
    return path


def test_store_package_cdb_is_reported_unavailable(tmp_path: Path) -> None:
    """Store package paths stat fine but CreateProcess denies them."""
    client = WindbgClient(_store_cdb(tmp_path))

    assert client.available is False


def test_store_package_cdb_raises_actionable_error(tmp_path: Path) -> None:
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    client = WindbgClient(_store_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.modules(dump)

    assert exc.value.code == "capability_unavailable"
    assert "HEADLESS_RE_CDB" in exc.value.message


def test_a_dump_analysis_cut_at_the_cap_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cdb prints the whole session, and the analytical answer is inside it.

    A listing that stopped at the cap reads exactly like one that ended, so a
    caller working out where a stack or a module list finishes would take the
    buffer boundary for the answer. Every other backend in this tree already
    flags its own truncation.
    """
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"A" * 500, stderr=b"")

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).modules(dump)

    assert payload["truncated"] is True, "a cut session must not read as a complete one"
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    assert len(str(payload["modules"])) == 64
    # The wrapper renames output, so the notice has to travel with the rename
    # rather than stay behind in the nested raw payload.
    assert "truncated" not in {key for key in payload if key == "raw"}


def test_a_dump_analysis_that_fits_is_not_labelled_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flag has to mean something, so it stays off when nothing was cut."""
    import subprocess

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")

    def small(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(windbg_module, "run_bounded", small)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).modules(dump)

    assert "truncated" not in payload
    assert payload["modules"] == "ok"


def test_discovery_never_returns_a_store_package(monkeypatch: pytest.MonkeyPatch) -> None:
    store = r"C:\Program Files\WindowsApps\Microsoft.WinDbg_1.0_x64__abc\amd64\cdb.exe"
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: store)

    discovered = windbg_module._discover_cdb()

    assert discovered is None or "windowsapps" not in str(discovered).casefold()


def test_launch_failure_becomes_a_structured_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    client = WindbgClient(cdb)

    def denied(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)

    with pytest.raises(WindbgError) as exc:
        client.modules(dump)

    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message
    assert exc.value.details["cdb"] == str(cdb)


def test_an_attach_cut_keeps_the_probe_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """9000 banner characters plus vertarget used to come back as the banner.

    Measured: attach's 8000-character prefix was all B's and
    'Windows 10 Version 19045' was gone, so an agent treated the debugger
    splash as the probe.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    body = ("B" * 9000) + "Windows 10 Version 19045 MP (8 procs)\n"

    def fake_bounded(cmd: list[str], **kwargs: object) -> Completed:
        return Completed(0, body.encode("utf-8"), b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_bounded)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).attach(42, allowed_pid=42)
    assert "19045" in str(payload["output"])
    assert payload["truncated"] is True
    assert payload["output_chars"] == len(body)
    assert payload["returned_chars"] == windbg_module._MAX_ATTACH_OUTPUT
    assert len(str(payload["output"])) == windbg_module._MAX_ATTACH_OUTPUT


def test_the_attach_tool_names_the_session_cut() -> None:
    """The reply already set truncated; the description did not.

    An agent that only reads the tool text treats a cut probe as the whole
    target version dump.
    """
    import ast
    import inspect

    from headless_re_mcp.tools import windbg as windbg_tools

    tree = ast.parse(inspect.getsource(windbg_tools.build_windbg_tools))
    docs = {
        node.name: ast.get_docstring(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    assert docs["windbg_attach"]
    assert "truncated" in docs["windbg_attach"]


def test_the_threads_tool_names_the_session_cut() -> None:
    """The reply already set truncated; the description did not.

    An agent that only reads the tool text treats a cut ~* listing as every
    thread in the dump.
    """
    import ast
    import inspect

    from headless_re_mcp.tools import windbg as windbg_tools

    tree = ast.parse(inspect.getsource(windbg_tools.build_windbg_tools))
    docs = {
        node.name: ast.get_docstring(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    assert docs["windbg_threads"]
    assert "truncated" in docs["windbg_threads"]


def test_the_modules_tool_names_the_session_cut() -> None:
    """The reply already set truncated; the description did not.

    An agent that only reads the tool text treats a cut lm listing as every
    module in the dump.
    """
    import ast
    import inspect

    from headless_re_mcp.tools import windbg as windbg_tools

    tree = ast.parse(inspect.getsource(windbg_tools.build_windbg_tools))
    docs = {
        node.name: ast.get_docstring(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    assert docs["windbg_modules"]
    assert "truncated" in docs["windbg_modules"]
