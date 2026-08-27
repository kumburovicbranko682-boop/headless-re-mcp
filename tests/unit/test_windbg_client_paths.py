"""Guard and discovery paths of the WinDbg/cdb client.

The client's contract is the same on every OS: refuse bad addresses and pids
before a debugger is launched, map launch failures to structured errors, and
never discover a cdb it cannot launch. All of that is exercised here with a
stubbed ``run_bounded``, so the suite covers it on Linux CI as well.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _cdb(tmp_path: Path) -> Path:
    path = tmp_path / "cdb.exe"
    path.write_bytes(b"MZ")
    return path


def _dump(tmp_path: Path) -> Path:
    path = tmp_path / "crash.dmp"
    path.write_bytes(b"dump")
    return path


def _stub_run(monkeypatch: pytest.MonkeyPatch, completed: Completed) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> Completed:
        calls.append(list(argv))
        return completed

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    return calls


# ---------------------------------------------------------------------------
# disasm input guards


def test_disasm_refuses_a_length_outside_1_to_256(tmp_path: Path) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), 0x1000, length=0)

    assert exc.value.code == "invalid_params"
    assert "1..256" in exc.value.message


def test_disasm_refuses_a_negative_integer_address(tmp_path: Path) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), -1)

    assert exc.value.code == "invalid_params"
    assert "non-negative" in exc.value.message


def test_disasm_refuses_a_string_address_with_shell_metacharacters(tmp_path: Path) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), "0x1000; !process")

    assert exc.value.code == "invalid_params"


def test_disasm_hexes_an_integer_address_into_the_u_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = WindbgClient(_cdb(tmp_path))
    dump = _dump(tmp_path)
    calls = _stub_run(monkeypatch, Completed(0, b"mov rax, rbx", b""))

    payload = client.disasm(dump, 0x401000, length=4)

    assert payload["address"] == "0x401000"
    assert payload["length"] == 4
    assert payload["disasm"] == "mov rax, rbx"
    assert "u 0x401000 L4; q" in calls[0]


# ---------------------------------------------------------------------------
# live_disasm input guards


def test_live_disasm_refuses_a_length_outside_1_to_256(tmp_path: Path) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, 0x1000, allowed_pid=4242, length=257)

    assert exc.value.code == "invalid_params"


def test_live_disasm_refuses_a_negative_integer_address(tmp_path: Path) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, -1, allowed_pid=4242)

    assert exc.value.code == "invalid_params"


def test_live_disasm_refuses_a_string_address_with_shell_metacharacters(
    tmp_path: Path,
) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, "rip | del", allowed_pid=4242)

    assert exc.value.code == "invalid_params"


def test_live_disasm_passes_a_clean_symbolic_address_through(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = WindbgClient(_cdb(tmp_path))
    calls = _stub_run(monkeypatch, Completed(0, b"00007ff6`nop", b""))

    payload = client.live_disasm(4242, " ntdll!RtlUserThreadStart ", allowed_pid=4242)

    assert payload["address"] == "ntdll!RtlUserThreadStart"
    assert payload["disasm"] == "00007ff6`nop"
    assert "u ntdll!RtlUserThreadStart L16; q" in calls[0]


def test_live_disasm_refuses_an_empty_string_address(tmp_path: Path) -> None:
    client = WindbgClient(_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, "   ", allowed_pid=4242)

    assert exc.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# _run_process guards and failure mapping


def test_a_non_positive_pid_is_refused_before_cdb_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = WindbgClient(_cdb(tmp_path))
    calls = _stub_run(monkeypatch, Completed(0, b"", b""))

    with pytest.raises(WindbgError) as exc:
        client.live_threads(0, allowed_pid=0)

    assert exc.value.code == "invalid_params"
    assert "positive" in exc.value.message
    assert calls == []


def test_a_probe_launch_failure_becomes_a_structured_backend_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cdb = _cdb(tmp_path)
    client = WindbgClient(cdb)

    def denied(*_args: Any, **_kwargs: Any) -> Completed:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)

    with pytest.raises(WindbgError) as exc:
        client.attach(4242, allowed_pid=4242)

    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message
    assert exc.value.details["cdb"] == str(cdb)


def test_a_silent_nonzero_probe_exit_is_a_backend_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = WindbgClient(_cdb(tmp_path))
    _stub_run(monkeypatch, Completed(2, b"", b"cdb: cannot attach"))

    with pytest.raises(WindbgError) as exc:
        client.attach(4242, allowed_pid=4242)

    assert exc.value.code == "backend_error"
    assert exc.value.details["exit_code"] == 2
    assert "cannot attach" in str(exc.value.details["stderr"])


def test_a_nonzero_probe_exit_with_output_still_answers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cdb exits 1 after `q` on some targets while the session text is fine."""
    client = WindbgClient(_cdb(tmp_path))
    _stub_run(monkeypatch, Completed(1, b"0  Id: 1234.1 Suspend: 0", b""))

    payload = client.live_threads(4242, allowed_pid=4242)

    assert payload["threads"] == "0  Id: 1234.1 Suspend: 0"


# ---------------------------------------------------------------------------
# _run_dump guards


def test_a_missing_dump_is_reported_before_cdb_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = WindbgClient(_cdb(tmp_path))
    calls = _stub_run(monkeypatch, Completed(0, b"", b""))

    with pytest.raises(WindbgError) as exc:
        client.modules(tmp_path / "missing.dmp")

    assert exc.value.code == "not_found"
    assert exc.value.details["path"] == str(tmp_path / "missing.dmp")
    assert calls == []


# ---------------------------------------------------------------------------
# _discover_cdb


def test_discovery_honours_an_explicit_cdb_env_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cdb = _cdb(tmp_path)
    monkeypatch.setenv("HEADLESS_RE_CDB", str(cdb))

    assert windbg_module._discover_cdb() == cdb


def test_discovery_ignores_an_env_path_that_is_not_a_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEADLESS_RE_CDB", str(tmp_path / "missing" / "cdb.exe"))
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: None)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "nope"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "nope-x86"))

    assert windbg_module._discover_cdb() is None


def test_discovery_returns_a_non_store_cdb_found_on_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cdb = _cdb(tmp_path)
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: str(cdb))

    assert windbg_module._discover_cdb() == cdb


def test_discovery_walks_windows_kits_when_nothing_else_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The x64 SDK layout is found even when PATH and env give nothing."""
    kit = tmp_path / "pf-x86" / "Windows Kits" / "10" / "Debuggers" / "x64"
    kit.mkdir(parents=True)
    cdb = kit / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: None)
    # The first root is missing on purpose: discovery has to skip it and keep
    # walking rather than give up at the first absent Program Files.
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "nope"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "pf-x86"))

    assert windbg_module._discover_cdb() == cdb


def test_discovery_skips_a_store_package_inside_windows_kits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kit = tmp_path / "pf" / "Windows Kits" / "WindowsApps" / "Debuggers" / "x64"
    kit.mkdir(parents=True)
    (kit / "cdb.exe").write_bytes(b"MZ")
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: None)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "nope"))

    assert windbg_module._discover_cdb() is None
