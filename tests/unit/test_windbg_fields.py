"""windbg tool descriptions must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.windbg.client import WindbgClient
from headless_re_mcp.tools.windbg import build_windbg_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_windbg_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_windbg_live_threads_names_pid_not_process_id(monkeypatch: Any) -> None:
    """The catalog named threads and never named the pid field.

    Measured: live_threads(4242) -> pid 4242, threads holding the cdb text,
    no process_id or output key. Looking for process_id after a successful
    list reads as a debuggee that returned no process.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {"output": "~0  Suspended"},
    )
    payload = client.live_threads(4242, allowed_pid=4242)
    assert "process_id" not in payload
    assert "output" not in payload
    assert payload["pid"] == 4242
    assert payload["threads"] == "~0  Suspended"
    doc = " ".join(_tool_docstring("windbg.live_threads").split())
    assert "Answers with threads" in doc
    assert "pid" in doc
    assert "There is no process_id" in doc

def test_windbg_live_modules_names_pid_not_process_id(monkeypatch: Any) -> None:
    """The catalog named modules and never named the pid field.

    Measured: live_modules(4242) -> pid 4242, modules holding the cdb text,
    no process_id or output key. Looking for process_id after a successful
    list reads as a debuggee that returned no process.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {"output": "notepad  00007ff612340000"},
    )
    payload = client.live_modules(4242, allowed_pid=4242)
    assert "process_id" not in payload
    assert "output" not in payload
    assert payload["pid"] == 4242
    assert "notepad" in payload["modules"]
    doc = " ".join(_tool_docstring("windbg.live_modules").split())
    assert "Answers with modules" in doc
    assert "pid" in doc
    assert "There is no process_id" in doc

def test_windbg_live_disasm_names_pid_not_process_id(monkeypatch: Any) -> None:
    """The catalog named disasm and never named the pid field.

    Measured: live_disasm(4242, 0x401000) -> pid 4242, address 0x401000,
    length 16, disasm holding the cdb text, no process_id or output key.
    Looking for process_id after a successful disassembly reads as a
    debuggee that returned no process.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {"output": "00007ff612340000 90 nop"},
    )
    payload = client.live_disasm(4242, 0x401000, allowed_pid=4242, length=16)
    assert "process_id" not in payload
    assert "output" not in payload
    assert payload["pid"] == 4242
    assert payload["address"] == "0x401000"
    assert payload["length"] == 16
    assert "nop" in payload["disasm"]
    doc = " ".join(_tool_docstring("windbg.live_disasm").split())
    assert "Answers with disasm" in doc
    assert "pid" in doc
    assert "There is no process_id" in doc

def test_windbg_attach_names_pid_and_note(monkeypatch: Any) -> None:
    """The catalog named output/attached/mode and never named pid or note.

    Measured: attach(4242) -> pid 4242, attached True, mode noninvasive,
    note set, output holding the cdb text, no process_id or version key.
    Looking for process_id after a successful probe reads as a debuggee
    that returned no process.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {"output": "Windows 10 Version 19045"},
    )
    payload = client.attach(4242, allowed_pid=4242)
    assert "process_id" not in payload
    assert "version" not in payload
    assert payload["pid"] == 4242
    assert payload["attached"] is True
    assert payload["mode"] == "noninvasive"
    assert payload["note"]
    assert payload["output"] == "Windows 10 Version 19045"
    doc = " ".join(_tool_docstring("windbg.attach").split())
    assert "pid" in doc
    assert "note" in doc
    assert "There is no process_id" in doc

def test_windbg_modules_names_the_cut_sizes(tmp_path: Path, monkeypatch: Any) -> None:
    """The catalog said truncated and never named how much was cut.

    Measured: 500-char cdb stdout, cap 64 -> truncated True, output_chars
    500, returned_chars 64. Looking at truncated alone cannot tell a 64-char
    dump from a 500-char dump that was sliced.
    """
    import subprocess

    import headless_re_mcp.backends.windbg.client as windbg_module

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"A" * 500, stderr=b""
        )

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).modules(dump)
    assert payload["truncated"] is True
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    doc = " ".join(_tool_docstring("windbg.modules").split())
    assert "output_chars" in doc
    assert "returned_chars" in doc

def test_windbg_threads_names_the_cut_sizes(tmp_path: Path, monkeypatch: Any) -> None:
    """The catalog said truncated and never named how much was cut.

    Measured: 500-char cdb stdout, cap 64 -> truncated True, output_chars
    500, returned_chars 64. Looking at truncated alone cannot tell a 64-char
    thread list from a 500-char list that was sliced.
    """
    import subprocess

    import headless_re_mcp.backends.windbg.client as windbg_module

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"A" * 500, stderr=b""
        )

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).threads(dump)
    assert payload["truncated"] is True
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    doc = " ".join(_tool_docstring("windbg.threads").split())
    assert "output_chars" in doc
    assert "returned_chars" in doc

def test_windbg_open_dump_names_the_cut_sizes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said output and truncated and never named the rest.

    Measured: 500-char cdb stdout, cap 64 -> dump set, output 64 chars,
    truncated True, output_chars 500, returned_chars 64, plus stderr and
    exit_code. Looking at truncated alone cannot tell a short session from
    a sliced one, and looking for dump after success reads as no file.
    """
    import subprocess

    import headless_re_mcp.backends.windbg.client as windbg_module

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"A" * 500, stderr=b""
        )

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).open_dump(dump, ["~*"])
    assert payload["truncated"] is True
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    assert payload["dump"].endswith("crash.dmp")
    assert "exit_code" in payload
    doc = " ".join(_tool_docstring("windbg.open_dump").split())
    assert "output_chars" in doc
    assert "returned_chars" in doc
    assert "dump" in doc
    assert "exit_code" in doc
