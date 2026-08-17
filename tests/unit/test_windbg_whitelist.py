"""cdb -c must not accept a composed tail after an allowed token."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.windbg.client import (
    WindbgClient,
    WindbgError,
    _require_allowed_cmd,
)


def test_allowed_lm_passes_the_whitelist() -> None:
    _require_allowed_cmd("lm")


def test_allowed_u_with_address_passes_the_whitelist() -> None:
    _require_allowed_cmd("u 0x401000 L16")


def test_semicolon_tail_is_rejected_as_invalid_params() -> None:
    """A head token of lm used to let lm; something through to cdb -c."""
    with pytest.raises(WindbgError) as exc:
        _require_allowed_cmd("lm; something")
    assert exc.value.code == "invalid_params"


def test_newline_pipe_cr_and_amp_tails_are_rejected_as_invalid_params() -> None:
    for payload in ("k\n.shell calc", "k\r.shell calc", "lm|findstr kernel", "lm&k"):
        with pytest.raises(WindbgError) as exc:
            _require_allowed_cmd(payload)
        assert exc.value.code == "invalid_params"


def test_run_dump_does_not_pass_a_semicolon_tail_to_cdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """lm; something must die before argv / run_bounded is built."""
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    called: list[Any] = []

    def capture(*args: Any, **kwargs: Any) -> Completed:
        called.append((args, kwargs))
        return Completed(0, b"", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", capture)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    with pytest.raises(WindbgError) as exc:
        WindbgClient(cdb).open_dump(dump, ["lm; something"])

    assert exc.value.code == "invalid_params"
    assert called == []


def test_run_process_does_not_pass_a_semicolon_tail_to_cdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    called: list[Any] = []

    def capture(*args: Any, **kwargs: Any) -> Completed:
        called.append((args, kwargs))
        return Completed(0, b"", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", capture)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    with pytest.raises(WindbgError) as exc:
        WindbgClient(cdb)._run_process(
            4242, ["k; .shell calc"], allowed_pid=4242, timeout=1.0
        )

    assert exc.value.code == "invalid_params"
    assert called == []


def test_allowed_lm_still_reaches_cdb_as_a_single_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Completed:
        seen["argv"] = argv
        return Completed(0, b"ok", b"")

    monkeypatch.setattr(windbg_module, "run_bounded", fake_run)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)

    payload = WindbgClient(cdb).modules(dump)

    assert payload["modules"] == "ok"
    assert seen["argv"][-2:] == ["-c", "lm; q"]
