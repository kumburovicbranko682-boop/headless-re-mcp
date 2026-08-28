"""Validation and error-path coverage for the cdb/WinDbg client.

The existing windbg tests cover truncation, the command allow-list, store-path
rejection, and the dump-path launch failure. This file covers the branches that
had no automated verification: the length/address validation in ``disasm`` and
``live_disasm`` (including the integer-address hex conversion), the pid guard
and the process-path launch/exit failures in ``_run_process``, the
dump-not-found guard in ``_run_dump``, and the environment/``which`` accept
paths of ``_discover_cdb``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _cdb(tmp_path: Path) -> Path:
    path = tmp_path / "cdb.exe"
    path.write_bytes(b"MZ")
    return path


def _dump(tmp_path: Path) -> Path:
    path = tmp_path / "crash.dmp"
    path.write_bytes(b"dump")
    return path


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WindbgClient:
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    return WindbgClient(_cdb(tmp_path))


def _run_returning(monkeypatch: pytest.MonkeyPatch, completed: Completed) -> list[list[str]]:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> Completed:
        seen.append(list(argv))
        return completed

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    return seen


# ---------------------------------------------------------------------------
# disasm / live_disasm length validation


@pytest.mark.parametrize("bad_length", [0, 257, -1, 1.0, "16"])
def test_disasm_rejects_a_length_outside_one_to_256(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_length: object
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), 0x401000, length=bad_length)  # type: ignore[arg-type]
    assert exc.value.code == "invalid_params"
    assert "length must be 1..256" in exc.value.message
    assert called == [], "a rejected length must never reach cdb"


@pytest.mark.parametrize("bad_length", [0, 257, "16"])
def test_live_disasm_rejects_a_length_outside_one_to_256(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_length: object
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.live_disasm(
            9,
            0x401000,
            allowed_pid=9,
            length=bad_length,  # type: ignore[arg-type]
        )
    assert exc.value.code == "invalid_params"
    assert called == []


# ---------------------------------------------------------------------------
# disasm / live_disasm address handling


def test_disasm_converts_a_positive_integer_address_to_hex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _run_returning(monkeypatch, Completed(0, b"disasm-text", b""))

    payload = client.disasm(_dump(tmp_path), 0x401000, length=8)

    assert payload["address"] == "0x401000"
    assert payload["length"] == 8
    assert payload["disasm"] == "disasm-text"
    assert seen[-1][-2:] == ["-c", "u 0x401000 L8; q"]


def test_disasm_rejects_a_negative_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), -1)
    assert exc.value.code == "invalid_params"
    assert "non-negative" in exc.value.message


@pytest.mark.parametrize("bad_address", ["", "   ", "0x401000; !process", "a|b", "a&b"])
def test_disasm_rejects_a_string_address_with_separators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_address: str
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.disasm(_dump(tmp_path), bad_address)
    assert exc.value.code == "invalid_params"
    assert "invalid disasm address" in exc.value.message
    assert called == []


def test_live_disasm_converts_a_positive_integer_address_to_hex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _run_returning(monkeypatch, Completed(0, b"live-disasm", b""))

    payload = client.live_disasm(4242, 0x7FF612340000, allowed_pid=4242, length=32)

    assert payload["pid"] == 4242
    assert payload["address"] == "0x7ff612340000"
    assert payload["disasm"] == "live-disasm"
    assert seen[-1][-2:] == ["-c", "u 0x7ff612340000 L32; q"]


def test_live_disasm_passes_a_clean_string_address_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    seen = _run_returning(monkeypatch, Completed(0, b"live-text", b""))

    payload = client.live_disasm(4242, "  0x401000  ", allowed_pid=4242, length=4)

    assert payload["address"] == "0x401000", "the address must be stripped, not rejected"
    assert payload["disasm"] == "live-text"
    assert seen[-1][-2:] == ["-c", "u 0x401000 L4; q"]


def test_live_disasm_rejects_a_negative_integer_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, -5, allowed_pid=4242)
    assert exc.value.code == "invalid_params"


def test_live_disasm_rejects_a_string_address_with_separators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.live_disasm(4242, "0x401000|calc", allowed_pid=4242)
    assert exc.value.code == "invalid_params"
    assert called == []


# ---------------------------------------------------------------------------
# _run_process guards and failures


@pytest.mark.parametrize("bad_pid", [0, -1, 4242.0, "4242"])
def test_live_probe_rejects_a_non_positive_or_non_integer_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_pid: object
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.live_modules(bad_pid, allowed_pid=bad_pid)  # type: ignore[arg-type]
    assert exc.value.code == "invalid_params"
    assert "pid must be a positive integer" in exc.value.message
    assert called == []


def test_live_probe_of_a_process_launch_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def denied(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module, "run_bounded", denied)
    with pytest.raises(WindbgError) as exc:
        client.live_threads(4242, allowed_pid=4242)
    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message
    assert exc.value.details["cdb"] == str(client.cdb)


def test_live_probe_nonzero_exit_with_no_output_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    _run_returning(monkeypatch, Completed(3, b"", b"cdb: fatal\n"))
    with pytest.raises(WindbgError) as exc:
        client.live_modules(4242, allowed_pid=4242)
    assert exc.value.code == "backend_error"
    assert exc.value.details["exit_code"] == 3
    assert "fatal" in str(exc.value.details["stderr"])


def test_live_probe_exit_one_with_output_is_tolerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cdb often exits 1 after a clean quit; output present means success."""
    client = _client(tmp_path, monkeypatch)
    _run_returning(monkeypatch, Completed(1, b"module list here", b""))

    payload = client.live_modules(4242, allowed_pid=4242)

    assert payload["modules"] == "module list here"
    assert "truncated" not in payload


def test_live_probe_nonzero_exit_that_still_produced_output_is_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A nonzero exit is only fatal when there is nothing to show for it."""
    client = _client(tmp_path, monkeypatch)
    _run_returning(monkeypatch, Completed(7, b"partial threads", b"warn"))

    payload = client.live_threads(4242, allowed_pid=4242)

    assert payload["threads"] == "partial threads"


def test_live_probe_of_a_foreign_pid_is_permission_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.live_modules(5, allowed_pid=6)
    assert exc.value.code == "permission_denied"
    assert exc.value.details["pid"] == 5
    assert exc.value.details["allowed_pid"] == 6
    assert called == [], "a foreign pid must never reach cdb"


def test_live_probe_timeout_reports_the_pids_that_were_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def timed_out(*_args: Any, **_kwargs: Any) -> Any:
        raise TimedOut(30.0, [4242, 4243])

    monkeypatch.setattr(windbg_module, "run_bounded", timed_out)
    with pytest.raises(WindbgError) as exc:
        client.live_threads(4242, allowed_pid=4242)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4242, 4243]


# ---------------------------------------------------------------------------
# _run_dump guard


def test_dump_analysis_of_a_missing_file_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.modules(tmp_path / "does-not-exist.dmp")
    assert exc.value.code == "not_found"
    assert str(exc.value.details["path"]).endswith("does-not-exist.dmp")
    assert called == [], "a missing dump must never reach cdb"


def test_dump_analysis_timeout_is_a_structured_timeout_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)

    def timed_out(*_args: Any, **_kwargs: Any) -> Any:
        raise TimedOut(60.0, [])

    monkeypatch.setattr(windbg_module, "run_bounded", timed_out)
    with pytest.raises(WindbgError) as exc:
        client.modules(_dump(tmp_path))
    assert exc.value.code == "timeout"
    assert exc.value.details["timeout"] == 60.0


# ---------------------------------------------------------------------------
# Capability guards


def test_kernel_dump_analysis_requires_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(tmp_path, monkeypatch)
    called = _run_returning(monkeypatch, Completed(0, b"", b""))
    with pytest.raises(WindbgError) as exc:
        client.open_dump(_dump(tmp_path), ["lm"], kernel=True)
    assert exc.value.code == "permission_denied"
    assert "ALLOW_KERNEL" in exc.value.message
    assert called == [], "a refused kernel request must never reach cdb"


def test_kernel_dump_analysis_runs_when_explicitly_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    client = WindbgClient(_cdb(tmp_path), allow_kernel=True)
    _run_returning(monkeypatch, Completed(0, b"kernel modules", b""))

    payload = client.open_dump(_dump(tmp_path), ["lm"], kernel=True)

    assert payload["output"] == "kernel modules"


def test_a_client_with_no_cdb_reports_the_tool_uninstalled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module, "_discover_cdb", lambda: None)
    client = WindbgClient()
    assert client.available is False
    with pytest.raises(WindbgError) as exc:
        client.modules(_dump(tmp_path))
    assert exc.value.code == "capability_unavailable"
    assert "not installed" in exc.value.message


# ---------------------------------------------------------------------------
# _discover_cdb accept paths


def test_discover_prefers_an_explicit_env_var_pointing_at_a_real_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cdb = _cdb(tmp_path)
    monkeypatch.setenv("HEADLESS_RE_CDB", str(cdb))

    assert windbg_module._discover_cdb() == cdb


def test_discover_accepts_a_which_result_that_is_not_a_store_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    on_path = tmp_path / "bin" / "cdb"
    on_path.parent.mkdir(parents=True)
    on_path.write_bytes(b"MZ")
    monkeypatch.setattr(
        "headless_re_mcp.backends.windbg.client.shutil.which",
        lambda _name: str(on_path),
    )

    discovered = windbg_module._discover_cdb()

    assert discovered == on_path
