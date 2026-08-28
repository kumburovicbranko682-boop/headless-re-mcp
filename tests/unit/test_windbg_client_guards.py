"""Input guards, failure arms and discovery fallbacks of the WinDbg client.

test_windbg_client.py pins truncation honesty and the Store-package refusal;
this file drives the remaining fail-closed paths: disasm length/address
validation on both the dump and live wrappers, the live-probe pid guard, the
launch-failure and hard-failure arms of the non-invasive probe, the missing
dump-file guard, and every branch of the cdb discovery chain.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed
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


def _ok_run(monkeypatch: pytest.MonkeyPatch, stdout: bytes = b"session text") -> None:
    monkeypatch.setattr(
        windbg_module,
        "run_bounded",
        lambda *_args, **_kwargs: Completed(0, stdout, b""),
    )


@pytest.mark.parametrize("length", [0, 257, True, "16"])
def test_dump_disasm_rejects_out_of_range_or_non_int_lengths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: Any
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), 0x1000, length=length)
    assert exc.value.code == "invalid_params"


def test_dump_disasm_rejects_a_negative_int_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), -1)
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("address", ["", "   ", "0x10;k", "0x10|k", "0x10&k"])
def test_dump_disasm_rejects_blank_or_metacharacter_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), address)
    assert exc.value.code == "invalid_params"


def test_dump_disasm_hexes_an_int_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(tmp_path, monkeypatch)
    _ok_run(monkeypatch, b"asm listing")

    payload = client.disasm(_dump(tmp_path), 4096, length=8)

    assert payload["address"] == "0x1000"
    assert payload["length"] == 8
    assert payload["disasm"] == "asm listing"


@pytest.mark.parametrize("length", [0, 257, True])
def test_live_disasm_rejects_out_of_range_or_non_int_lengths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: Any
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, 0x1000, allowed_pid=4242, length=length)
    assert exc.value.code == "invalid_params"


def test_live_disasm_rejects_a_negative_int_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, -1, allowed_pid=4242)
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("address", ["", "0x10;k", "0x10|k", "0x10&k"])
def test_live_disasm_rejects_blank_or_metacharacter_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, address, allowed_pid=4242)
    assert exc.value.code == "invalid_params"


def test_live_disasm_accepts_a_trimmed_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    _ok_run(monkeypatch, b"live asm")

    payload = client.live_disasm(4242, "  0x2000  ", allowed_pid=4242)

    assert payload["address"] == "0x2000"
    assert payload["disasm"] == "live asm"


@pytest.mark.parametrize("pid", [0, -5, True])
def test_live_probe_rejects_non_positive_or_non_int_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pid: Any
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.live_threads(pid, allowed_pid=pid)
    assert exc.value.code == "invalid_params"


def test_live_probe_launch_failure_is_a_structured_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def denied(*_args: Any, **_kwargs: Any) -> Completed:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)

    with pytest.raises(WindbgError) as exc:
        client.live_modules(4242, allowed_pid=4242)

    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message
    assert exc.value.details["cdb"] == str(client.cdb)


def test_live_probe_hard_failure_with_no_output_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(
        windbg_module,
        "run_bounded",
        lambda *_args, **_kwargs: Completed(2, b"", b"boom"),
    )

    with pytest.raises(WindbgError) as exc:
        client.live_threads(4242, allowed_pid=4242)

    assert exc.value.code == "backend_error"
    assert exc.value.details["exit_code"] == 2
    assert exc.value.details["stderr"] == "boom"


def test_live_probe_nonzero_exit_with_output_still_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cdb often exits 2 after printing the answer; the text must survive."""
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(
        windbg_module,
        "run_bounded",
        lambda *_args, **_kwargs: Completed(2, b"thread listing", b""),
    )

    payload = client.live_threads(4242, allowed_pid=4242)

    assert payload["threads"] == "thread listing"
    assert payload["pid"] == 4242


def test_dump_run_requires_the_dump_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.modules(tmp_path / "missing.dmp")
    assert exc.value.code == "not_found"
    assert exc.value.details["path"] == str(tmp_path / "missing.dmp")


def test_a_missing_cdb_is_a_capability_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windbg_module, "_discover_cdb", lambda: None)
    client = WindbgClient()
    with pytest.raises(WindbgError) as exc:
        client.threads(_dump(tmp_path))
    assert exc.value.code == "capability_unavailable"
    assert "not installed" in exc.value.message


def test_kernel_dump_analysis_requires_the_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.open_dump(_dump(tmp_path), ["lm"], kernel=True)
    assert exc.value.code == "permission_denied"
    assert "HEADLESS_RE_WINDBG_ALLOW_KERNEL" in exc.value.message


def test_live_probe_refuses_a_pid_other_than_the_session_debuggee(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    with pytest.raises(WindbgError) as exc:
        client.live_threads(4242, allowed_pid=9999)
    assert exc.value.code == "permission_denied"
    assert exc.value.details == {"pid": 4242, "allowed_pid": 9999}


def test_timeouts_surface_the_killed_pids_on_both_run_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.common.bounded_run import TimedOut

    client = _client(tmp_path, monkeypatch)

    def too_slow(*_args: Any, **_kwargs: Any) -> Completed:
        raise TimedOut(30.0, [1234])

    monkeypatch.setattr(windbg_module, "run_bounded", too_slow)

    with pytest.raises(WindbgError) as live_exc:
        client.live_threads(4242, allowed_pid=4242)
    assert live_exc.value.code == "timeout"
    assert live_exc.value.details["killed_pids"] == [1234]

    with pytest.raises(WindbgError) as dump_exc:
        client.modules(_dump(tmp_path))
    assert dump_exc.value.code == "timeout"
    assert dump_exc.value.details["killed_pids"] == [1234]


def _fake_module_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> Path:
    """Point the module's __file__ at a tmp tree so the tools path is tmp-rooted."""
    root = tmp_path / name
    fake = root / "src" / "pkg" / "backends" / "windbg" / "client.py"
    fake.parent.mkdir(parents=True)
    fake.write_text("", encoding="utf-8")
    monkeypatch.setattr(windbg_module, "__file__", str(fake))
    return root


def test_discovery_prefers_the_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_cdb = tmp_path / "custom" / "cdb.exe"
    env_cdb.parent.mkdir(parents=True)
    env_cdb.write_bytes(b"MZ")
    monkeypatch.setenv("HEADLESS_RE_CDB", str(env_cdb))

    assert windbg_module._discover_cdb() == env_cdb


def test_discovery_uses_the_project_tools_runtime_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    root = _fake_module_file(tmp_path, monkeypatch, "repo")
    tools = root / "artifacts" / "tools" / "cdb-amd64" / "cdb.exe"
    tools.parent.mkdir(parents=True)
    tools.write_bytes(b"MZ")

    assert windbg_module._discover_cdb() == tools


def test_discovery_accepts_a_non_store_cdb_from_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    _fake_module_file(tmp_path, monkeypatch, "bare-repo")
    on_path = tmp_path / "sdk" / "cdb.exe"
    on_path.parent.mkdir(parents=True)
    on_path.write_bytes(b"MZ")
    monkeypatch.setattr(shutil, "which", lambda _name: str(on_path))

    assert windbg_module._discover_cdb() == on_path


def test_discovery_falls_back_to_the_windows_kits_glob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    _fake_module_file(tmp_path, monkeypatch, "kits-repo")
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    kit_cdb = tmp_path / "pf" / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdb.exe"
    kit_cdb.parent.mkdir(parents=True)
    kit_cdb.write_bytes(b"MZ")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "no-such-dir"))

    assert windbg_module._discover_cdb() == kit_cdb


def test_discovery_skips_a_store_packaged_kit_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    _fake_module_file(tmp_path, monkeypatch, "store-repo")
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    store_cdb = tmp_path / "pf" / "Windows Kits" / "WindowsApps" / "Debuggers" / "x64" / "cdb.exe"
    store_cdb.parent.mkdir(parents=True)
    store_cdb.write_bytes(b"MZ")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "no-such-dir"))

    assert windbg_module._discover_cdb() is None
