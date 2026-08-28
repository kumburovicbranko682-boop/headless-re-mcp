"""Guard, error-handler, and discovery-fallback paths of the WinDbg client.

Everything here is portable: cdb itself is never launched. Subprocess work
goes through ``run_bounded``, which the tests replace, and ``_discover_cdb``
is driven entirely by environment variables and directories on disk.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _launchable_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WindbgClient:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    return WindbgClient(cdb)


def _dump(tmp_path: Path) -> Path:
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    return dump


# ---------------------------------------------------------------- disasm


@pytest.mark.parametrize("length", [0, 257, True])
def test_disasm_rejects_an_out_of_range_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: object
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), 0x1000, length=length)  # type: ignore[arg-type]

    assert exc.value.code == "invalid_params"


def test_disasm_rejects_a_negative_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), -1)

    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("address", ["", "0x10;k", "0x10|k", "0x10&k"])
def test_disasm_rejects_an_unsafe_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), address)

    assert exc.value.code == "invalid_params"


def test_disasm_turns_an_integer_address_into_the_hex_u_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> Completed:
        seen.append(argv)
        return Completed(0, b"mov eax, eax", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)

    payload = client.disasm(_dump(tmp_path), 0x1000, length=4)

    assert payload["address"] == "0x1000"
    assert payload["length"] == 4
    assert payload["disasm"] == "mov eax, eax"
    assert seen[0][-1] == "u 0x1000 L4; q"


# ----------------------------------------------------------- live_disasm


def test_live_disasm_rejects_an_out_of_range_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, 0x1000, allowed_pid=4242, length=0)

    assert exc.value.code == "invalid_params"


def test_live_disasm_rejects_a_negative_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, -1, allowed_pid=4242)

    assert exc.value.code == "invalid_params"


def test_live_disasm_rejects_an_unsafe_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, "0x10;k", allowed_pid=4242)

    assert exc.value.code == "invalid_params"


def test_live_disasm_accepts_a_symbolic_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> Completed:
        seen.append(argv)
        return Completed(0, b"ret", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)

    payload = client.live_disasm(4242, "ntdll!RtlUserThreadStart", allowed_pid=4242, length=2)

    assert payload["address"] == "ntdll!RtlUserThreadStart"
    assert payload["disasm"] == "ret"
    assert seen[0][1:4] == ["-pv", "-p", "4242"]
    assert seen[0][-1] == "u ntdll!RtlUserThreadStart L2; q"


# ---------------------------------------------------------- _run_process


def test_a_live_probe_rejects_a_non_positive_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.live_modules(0, allowed_pid=0)

    assert exc.value.code == "invalid_params"
    assert "positive" in exc.value.message


def test_a_live_probe_launch_failure_becomes_a_structured_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    def denied(*_args: Any, **_kwargs: Any) -> Completed:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)

    with pytest.raises(WindbgError) as exc:
        client.live_modules(4242, allowed_pid=4242)

    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message


def test_a_live_probe_that_fails_without_output_reports_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    def failing(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(2, b"", b"cdb: cannot attach")

    monkeypatch.setattr(windbg_module, "run_bounded", failing)

    with pytest.raises(WindbgError) as exc:
        client.live_threads(4242, allowed_pid=4242)

    assert exc.value.code == "backend_error"
    assert exc.value.details["exit_code"] == 2
    assert "cannot attach" in str(exc.value.details["stderr"])


# ------------------------------------------------------------- _run_dump


def test_a_dump_analysis_rejects_a_missing_dump_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _launchable_client(tmp_path, monkeypatch)

    with pytest.raises(WindbgError) as exc:
        client.modules(tmp_path / "absent.dmp")

    assert exc.value.code == "not_found"


# --------------------------------------------------------- _discover_cdb


def test_discovery_honours_the_environment_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    override = tmp_path / "cdb.exe"
    override.write_bytes(b"MZ")
    monkeypatch.setenv("HEADLESS_RE_CDB", str(override))

    assert windbg_module._discover_cdb() == override


def test_discovery_prefers_the_verified_project_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The project tools path outranks PATH and the Windows Kits scan."""
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    root = Path(windbg_module.__file__).resolve().parents[4]
    tools = root / "artifacts" / "tools" / "cdb-amd64" / "cdb.exe"
    if tools.is_file():
        assert windbg_module._discover_cdb() == tools
        return
    made_dirs: list[Path] = []
    probe = tools.parent
    while not probe.exists():
        made_dirs.append(probe)
        probe = probe.parent
    tools.parent.mkdir(parents=True, exist_ok=True)
    tools.write_bytes(b"MZ")
    try:
        assert windbg_module._discover_cdb() == tools
    finally:
        tools.unlink()
        for directory in made_dirs:
            directory.rmdir()


def test_discovery_accepts_a_path_hit_outside_a_store_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = tmp_path / "sdk" / "cdb.exe"
    found.parent.mkdir()
    found.write_bytes(b"MZ")
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: str(found))

    assert windbg_module._discover_cdb() == found


def test_discovery_scans_windows_kits_and_skips_store_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Kits glob skips a store-flavoured hit and an empty root entirely."""
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    # First root exists but only holds a store-package match the launchable
    # filter must reject; the second root holds the real debugger.
    store_root = tmp_path / "pf" / "Windows Kits"
    store_hit = store_root / "windowsapps" / "Debuggers" / "x64" / "cdb.exe"
    store_hit.parent.mkdir(parents=True)
    store_hit.write_bytes(b"MZ")
    sdk_root = tmp_path / "pf86" / "Windows Kits"
    sdk_hit = sdk_root / "10" / "Debuggers" / "x64" / "cdb.exe"
    sdk_hit.parent.mkdir(parents=True)
    sdk_hit.write_bytes(b"MZ")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "pf86"))

    assert windbg_module._discover_cdb() == sdk_hit


def test_discovery_moves_past_a_kits_root_without_any_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    empty_root = tmp_path / "pf" / "Windows Kits"
    empty_root.mkdir(parents=True)
    sdk_root = tmp_path / "pf86" / "Windows Kits"
    sdk_hit = sdk_root / "10" / "Debuggers" / "x64" / "cdb.exe"
    sdk_hit.parent.mkdir(parents=True)
    sdk_hit.write_bytes(b"MZ")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "pf86"))

    assert windbg_module._discover_cdb() == sdk_hit
