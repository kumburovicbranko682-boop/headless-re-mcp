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


def test_a_cut_disasm_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A disasm that hit the buffer used to look complete if unread.

    Measured: 500 characters of ``u`` came back as 64 with truncated=True
    on disasm, while the tool text omitted truncated. An unattended agent
    that trusted the description treated the fragment as the listing.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> Completed:
        return Completed(0, b"U" * 500, b"")

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).disasm(dump, "0x1000", length=16)
    assert payload["truncated"] is True
    assert len(str(payload["disasm"])) == 64


def test_a_cut_live_thread_list_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live thread listing that hit the buffer used to look complete if unread.

    Measured: 500 characters of live ``~*`` came back as 64 with
    truncated=True on threads, while the tool text omitted truncated. An
    unattended agent that trusted the description treated the fragment as
    every thread.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> Completed:
        return Completed(0, b"L" * 500, b"")

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).live_threads(4242, allowed_pid=4242)
    assert payload["truncated"] is True
    assert len(str(payload["threads"])) == 64


def test_live_threads_tool_description_says_to_read_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "windbg.py"
    ).read_text(encoding="utf-8")
    block = source.split("def windbg_live_threads(")[1].split("def windbg_live_modules(")[0]
    assert "truncated" in block


def test_disasm_tool_description_says_to_read_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "windbg.py"
    ).read_text(encoding="utf-8")
    block = source.split("def windbg_disasm(")[1].split("def windbg_attach(")[0]
    assert "truncated" in block


def test_modules_tool_description_says_to_read_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "windbg.py"
    ).read_text(encoding="utf-8")
    block = source.split("def windbg_modules(")[1].split("def windbg_disasm(")[0]
    assert "truncated" in block


def test_a_cut_thread_list_says_it_was_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A thread listing that hit the buffer used to look complete if unread.

    Measured: 500 characters of ``~*`` came back as 64 with truncated=True
    on the threads field, while the tool text omitted truncated. An
    unattended agent that trusted the description treated the fragment as
    every thread.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> Completed:
        return Completed(0, b"T" * 500, b"")

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).threads(dump)
    assert payload["truncated"] is True
    assert len(str(payload["threads"])) == 64


def test_threads_tool_description_says_to_read_truncated() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "src" / "headless_re_mcp" / "tools" / "windbg.py"
    ).read_text(encoding="utf-8")
    block = source.split("def windbg_threads(")[1].split("def windbg_modules(")[0]
    assert "truncated" in block


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


def test_a_failed_dump_is_not_an_empty_module_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cdb that could not open the dump used to look like an empty listing.

    Measured: exit 2 and empty stdout still answered modules="", so an
    unattended agent treated a failed analysis as a dump with no modules.
    """
    from headless_re_mcp.backends.common.bounded_run import Completed

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")

    def failed(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(2, b"", b"Could not open dump file")

    monkeypatch.setattr(windbg_module, "run_bounded", failed)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    with pytest.raises(WindbgError) as exc:
        WindbgClient(cdb).modules(dump)
    assert exc.value.code == "backend_error"
    assert "dump analysis failed" in exc.value.message
    assert exc.value.details.get("exit_code") == 2
