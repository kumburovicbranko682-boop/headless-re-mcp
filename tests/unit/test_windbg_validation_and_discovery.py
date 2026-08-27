"""WindbgClient must reject bad disasm/live arguments and discover cdb sanely.

The truncation and whitelist suites already pin the happy dump path and the
command allow-list. This module drives the surfaces they leave open:

* the ``disasm`` / ``live_disasm`` argument guards (length range, negative
  numeric address, and shell metacharacters in a string address) and the
  ``u <addr> L<count>`` command they build once the input is clean,
* the live-process error envelopes (bad pid, launch OSError, and a non-zero
  exit that printed nothing) that mirror the dump path's already-tested guards,
* ``_run_dump``'s missing-file check, and
* ``_discover_cdb``'s env override, PATH lookup, and Windows Kits glob.

cdb is not installed here, so a real temp file stands in for the executable and
``run_bounded`` is monkeypatched -- no debugger is ever launched.
"""

from __future__ import annotations

import shutil
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


# --------------------------------------------------------------------------
# disasm argument guards + command shape
# --------------------------------------------------------------------------


def test_disasm_builds_a_whitelisted_u_command_for_a_numeric_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Completed:
        seen["argv"] = argv
        return Completed(0, b"code", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(_cdb(tmp_path)).disasm(_dump(tmp_path), 0x401000, length=8)
    assert payload["address"] == "0x401000"
    assert payload["length"] == 8
    assert seen["argv"][-2:] == ["-c", "u 0x401000 L8; q"]


def test_disasm_accepts_a_clean_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Completed:
        seen["argv"] = argv
        return Completed(0, b"code", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(_cdb(tmp_path)).disasm(_dump(tmp_path), "  401000  ")
    assert payload["address"] == "401000"
    assert seen["argv"][-2:] == ["-c", "u 401000 L16; q"]


@pytest.mark.parametrize("length", [0, 257, -4])
def test_disasm_rejects_an_out_of_range_length(tmp_path: Path, length: int) -> None:
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).disasm(_dump(tmp_path), 0x1000, length=length)
    assert exc.value.code == "invalid_params"


def test_disasm_rejects_a_negative_numeric_address(tmp_path: Path) -> None:
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).disasm(_dump(tmp_path), -1)
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("address", ["", "401000; !process", "401000|k", "401000&q"])
def test_disasm_rejects_a_hostile_string_address(tmp_path: Path, address: str) -> None:
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).disasm(_dump(tmp_path), address)
    assert exc.value.code == "invalid_params"


# --------------------------------------------------------------------------
# live_disasm mirrors the same guards on the process path
# --------------------------------------------------------------------------


def test_live_disasm_builds_a_pv_attach_command_for_a_numeric_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Completed:
        seen["argv"] = argv
        return Completed(0, b"code", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(_cdb(tmp_path)).live_disasm(4242, 0x401000, allowed_pid=4242)
    assert payload["address"] == "0x401000"
    assert seen["argv"][:4] == [str(_cdb(tmp_path)), "-pv", "-p", "4242"]
    assert seen["argv"][-2:] == ["-c", "u 0x401000 L16; q"]


def test_live_disasm_accepts_a_clean_string_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Completed:
        seen["argv"] = argv
        return Completed(0, b"code", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(_cdb(tmp_path)).live_disasm(4242, "  401000  ", allowed_pid=4242)
    assert payload["address"] == "401000"
    assert seen["argv"][-2:] == ["-c", "u 401000 L16; q"]


@pytest.mark.parametrize("length", [0, 257])
def test_live_disasm_rejects_an_out_of_range_length(tmp_path: Path, length: int) -> None:
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).live_disasm(1, 0x1000, allowed_pid=1, length=length)
    assert exc.value.code == "invalid_params"


def test_live_disasm_rejects_a_negative_numeric_address(tmp_path: Path) -> None:
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).live_disasm(1, -1, allowed_pid=1)
    assert exc.value.code == "invalid_params"


def test_live_disasm_rejects_a_hostile_string_address(tmp_path: Path) -> None:
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).live_disasm(1, "x; !process", allowed_pid=1)
    assert exc.value.code == "invalid_params"


# --------------------------------------------------------------------------
# live-process error envelopes
# --------------------------------------------------------------------------


def test_live_probe_rejects_a_non_positive_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).live_threads(0, allowed_pid=0)
    assert exc.value.code == "invalid_params"
    assert "positive integer" in exc.value.message


def test_live_probe_launch_failure_is_a_structured_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(*_args: Any, **_kwargs: Any) -> Completed:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).live_modules(4242, allowed_pid=4242)
    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message


def test_live_probe_that_failed_with_no_output_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(2, b"", b"attach failed")

    monkeypatch.setattr(windbg_module, "run_bounded", failed)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).live_modules(4242, allowed_pid=4242)
    assert exc.value.code == "backend_error"
    assert exc.value.details["exit_code"] == 2


def test_dump_read_reports_a_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    with pytest.raises(WindbgError) as exc:
        WindbgClient(_cdb(tmp_path)).modules(tmp_path / "absent.dmp")
    assert exc.value.code == "not_found"


# --------------------------------------------------------------------------
# _discover_cdb ladder
# --------------------------------------------------------------------------


def test_discover_prefers_the_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cdb = _cdb(tmp_path)
    monkeypatch.setenv("HEADLESS_RE_CDB", str(cdb))
    assert windbg_module._discover_cdb() == cdb


def test_discover_falls_back_to_path_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    found = tmp_path / "cdb"
    found.write_bytes(b"x")
    monkeypatch.setattr(shutil, "which", lambda _name: str(found))
    assert windbg_module._discover_cdb() == found


def test_discover_scans_windows_kits_when_nothing_else_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    kit = tmp_path / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdb.exe"
    kit.parent.mkdir(parents=True)
    kit.write_bytes(b"MZ")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "missing"))
    assert windbg_module._discover_cdb() == kit
