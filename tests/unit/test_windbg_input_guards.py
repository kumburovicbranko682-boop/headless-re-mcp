"""Input guards and error mapping for the cdb/WinDbg client.

The client hands model-supplied addresses, lengths, PIDs and deadlines to cdb.
The command allow-list and truncation notices already have tests; this file pins
the refusals that keep a bad address, a wrong PID or a non-positive/oversized
timeout from ever reaching a launch, the translation of a failed or unlaunchable
probe into a structured error, and the cross-platform arms of cdb discovery. cdb
itself is stubbed, so these run on any host.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WindbgClient:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    return WindbgClient(cdb)


def _dump(tmp_path: Path) -> Path:
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    return dump


def _record_run(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Capture the argv cdb would be launched with; return canned output."""
    seen: list[list[str]] = []

    def fake_run(argv: list[str], *args: Any, **kwargs: Any) -> Completed:
        seen.append(list(argv))
        return Completed(0, b"session-text", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    return seen


def _record_timeout(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Capture the (already clamped) deadline handed to run_bounded."""
    seen: list[float] = []

    def fake_run(argv: list[str], *args: Any, **kwargs: Any) -> Completed:
        del argv, args
        seen.append(kwargs["timeout"])
        return Completed(0, b"session-text", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    return seen


# --- disasm address / length validation (dump path) ------------------------


@pytest.mark.parametrize("length", [0, 257, 1.5, True])
def test_disasm_length_must_be_an_int_in_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: object
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.disasm(_dump(tmp_path), 0x401000, length=length)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


def test_disasm_rejects_a_negative_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.disasm(_dump(tmp_path), -1)
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("address", ["", "   ", "0x1000; k", "0x1000|k", "0x1000&k"])
def test_disasm_rejects_a_hostile_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.disasm(_dump(tmp_path), address)
    assert caught.value.code == "invalid_params"


def test_disasm_emits_a_whitelisted_unassemble_for_an_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _record_run(monkeypatch)
    payload = client.disasm(_dump(tmp_path), 0x401000, length=32)
    assert payload["address"] == "0x401000"
    assert payload["length"] == 32
    # The integer is rendered as hex and folded into the whitelisted `u` form.
    assert "-c" in seen[0]
    script = seen[0][seen[0].index("-c") + 1]
    assert script == "u 0x401000 L32; q"


# --- live_disasm address / length validation (process path) ----------------


@pytest.mark.parametrize("length", [0, 512, 2.0])
def test_live_disasm_length_must_be_an_int_in_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: object
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.live_disasm(4242, 0x401000, allowed_pid=4242, length=length)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


def test_live_disasm_rejects_a_negative_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.live_disasm(4242, -5, allowed_pid=4242)
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("address", ["", "0x1000;k"])
def test_live_disasm_rejects_a_hostile_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.live_disasm(4242, address, allowed_pid=4242)
    assert caught.value.code == "invalid_params"


def test_live_disasm_emits_a_whitelisted_unassemble(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _record_run(monkeypatch)
    client.live_disasm(4242, 0x401000, allowed_pid=4242, length=16)
    script = seen[0][seen[0].index("-c") + 1]
    assert script == "u 0x401000 L16; q"
    # A non-invasive probe attaches by pid, not by loading a dump.
    assert "-pv" in seen[0]
    assert "-p" in seen[0]


def test_live_disasm_accepts_a_clean_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _record_run(monkeypatch)
    payload = client.live_disasm(4242, "kernel32!CreateFileW", allowed_pid=4242)
    assert payload["address"] == "kernel32!CreateFileW"
    script = seen[0][seen[0].index("-c") + 1]
    assert script == "u kernel32!CreateFileW L16; q"


# --- process PID gating -----------------------------------------------------


@pytest.mark.parametrize("pid", [0, -1])
def test_a_non_positive_pid_is_refused_before_any_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pid: int
) -> None:
    client = _client(tmp_path, monkeypatch)
    launched = _record_run(monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.attach(pid, allowed_pid=pid)
    assert caught.value.code == "invalid_params"
    assert launched == []


def test_attaching_to_a_pid_other_than_the_debuggee_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    launched = _record_run(monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.attach(1234, allowed_pid=4242)
    assert caught.value.code == "permission_denied"
    assert caught.value.details["pid"] == 1234
    assert caught.value.details["allowed_pid"] == 4242
    assert launched == []


# --- process error mapping --------------------------------------------------


def test_a_live_probe_that_cannot_launch_becomes_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def denied(*_args: Any, **_kwargs: Any) -> Completed:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)
    with pytest.raises(WindbgError) as caught:
        client.attach(4242, allowed_pid=4242)
    assert caught.value.code == "backend_error"
    assert "could not be launched" in caught.value.message


def test_a_failing_live_probe_with_no_output_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def failed(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(2, b"", b"attach failed: not found")

    monkeypatch.setattr(windbg_module, "run_bounded", failed)
    with pytest.raises(WindbgError) as caught:
        client.live_modules(4242, allowed_pid=4242)
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2


def test_a_failing_live_probe_that_still_printed_is_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # cdb often exits non-zero yet prints the useful session; when there is
    # output the client surfaces it instead of raising.
    client = _client(tmp_path, monkeypatch)

    def noisy(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(2, b"thread list here", b"warning")

    monkeypatch.setattr(windbg_module, "run_bounded", noisy)
    payload = client.live_threads(4242, allowed_pid=4242)
    assert payload["threads"] == "thread list here"


# --- dump path guards -------------------------------------------------------


def test_a_missing_dump_file_is_not_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(tmp_path, monkeypatch)
    _record_run(monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.modules(tmp_path / "absent.dmp")
    assert caught.value.code == "not_found"


def test_kernel_dump_analysis_needs_the_explicit_allow_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    _record_run(monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.open_dump(_dump(tmp_path), ["lm"], kernel=True)
    assert caught.value.code == "permission_denied"


def test_a_client_without_a_cdb_is_capability_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Discovery finding nothing must surface as a clean capability error, not a
    # crash when a dump command is issued.
    monkeypatch.setattr(windbg_module, "_discover_cdb", lambda: None)
    client = WindbgClient()
    assert client.available is False
    with pytest.raises(WindbgError) as caught:
        client.modules(_dump(tmp_path))
    assert caught.value.code == "capability_unavailable"


# --- timeout mapping --------------------------------------------------------


def test_a_dump_analysis_timeout_names_the_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def slow(*_args: Any, **_kwargs: Any) -> Completed:
        raise TimedOut(60.0, [111, 222])

    monkeypatch.setattr(windbg_module, "run_bounded", slow)
    with pytest.raises(WindbgError) as caught:
        client.modules(_dump(tmp_path))
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [111, 222]


def test_a_live_probe_timeout_reports_the_killed_debugger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A deadline that only reached the launcher would leave cdb attached to the
    # live target, so the killed pids have to travel with the error.
    client = _client(tmp_path, monkeypatch)

    def slow(*_args: Any, **_kwargs: Any) -> Completed:
        raise TimedOut(30.0, [4242])

    monkeypatch.setattr(windbg_module, "run_bounded", slow)
    with pytest.raises(WindbgError) as caught:
        client.attach(4242, allowed_pid=4242)
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [4242]


# --- timeout clamping across transports -------------------------------------
# The tool schema bounds 0 < timeout <= 300 (dump) / <= 120 (live), but the
# agent/OpenAI transports call the service straight from model arguments and skip
# that pydantic check. A non-positive value must be a fail-fast invalid_params,
# not a cdb launch killed on the first loop and mis-reported as a timeout; a huge
# value must be capped so a hostile dump cannot hold a worker past the ceiling.


@pytest.mark.parametrize("bad", [0, -1, -0.5, float("nan")])
def test_a_dump_reader_refuses_a_non_positive_timeout_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: float
) -> None:
    client = _client(tmp_path, monkeypatch)
    launched = _record_run(monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.modules(_dump(tmp_path), timeout=bad)
    assert caught.value.code == "invalid_params"
    assert launched == []


@pytest.mark.parametrize("bad", [0, -1, float("nan")])
def test_a_live_probe_refuses_a_non_positive_timeout_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: float
) -> None:
    client = _client(tmp_path, monkeypatch)
    launched = _record_run(monkeypatch)
    with pytest.raises(WindbgError) as caught:
        client.attach(4242, allowed_pid=4242, timeout=bad)
    assert caught.value.code == "invalid_params"
    assert launched == []


def test_a_dump_reader_timeout_is_capped_at_the_schema_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _record_timeout(monkeypatch)
    client.modules(_dump(tmp_path), timeout=99_999.0)
    assert seen == [300.0]


def test_a_live_probe_timeout_is_capped_at_the_schema_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _record_timeout(monkeypatch)
    client.attach(4242, allowed_pid=4242, timeout=99_999.0)
    assert seen == [120.0]


# --- cdb discovery ----------------------------------------------------------


def test_discovery_prefers_an_explicit_env_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cdb = tmp_path / "sdk" / "cdb.exe"
    cdb.parent.mkdir(parents=True)
    cdb.write_bytes(b"MZ")
    monkeypatch.setenv("HEADLESS_RE_CDB", str(cdb))
    assert windbg_module._discover_cdb() == cdb


def test_discovery_accepts_a_non_store_path_from_which(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cdb = tmp_path / "cdb"
    cdb.write_bytes(b"MZ")
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: str(cdb))
    assert windbg_module._discover_cdb() == cdb


def test_discovery_walks_the_windows_kits_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No env, nothing on PATH: fall through to the SDK Debugging Tools glob.
    kit = tmp_path / "Windows Kits" / "10" / "Debuggers" / "x64"
    kit.mkdir(parents=True)
    cdb = kit / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "x86-empty"))
    found = windbg_module._discover_cdb()
    assert found is not None and found.name == "cdb.exe"


def test_discovery_returns_none_when_nothing_is_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "none"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "none-x86"))
    assert windbg_module._discover_cdb() is None


def test_discovery_skips_a_kits_match_that_is_not_launchable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A glob hit that is not a real file (here a directory named cdb.exe) must
    # be walked over rather than returned, and an exhausted root moves on.
    kit = tmp_path / "Windows Kits" / "10" / "Debuggers" / "x64"
    kit.mkdir(parents=True)
    (kit / "cdb.exe").mkdir()
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "x86-empty"))
    assert windbg_module._discover_cdb() is None
