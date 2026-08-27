"""The rebuild memory-guard and bound dump-read helpers in service_unpack.

These are the pre-allocation guard that keeps a multi-gigabyte dump from
taking the whole process (and every open session) down, and the reader that
binds the guard to the same file handle it will read.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.service_unpack import (
    _read_dump_for_rebuild,
    _refuse_rebuild_that_will_not_fit,
)
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError


def test_a_dump_that_fits_is_not_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"x" * 1024)
    monkeypatch.setattr(
        service_unpack, "rebuild_would_exhaust_memory", lambda size: (False, 0, 1 << 40)
    )

    assert _refuse_rebuild_that_will_not_fit(dump) is None


def test_a_dump_too_large_for_free_memory_is_refused_with_the_numbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The refusal must carry the estimate and the free figure so an operator
    # can act (dump a narrower range or free memory) instead of just seeing a
    # size. The estimate/available are reported in the message and the details.
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"x" * (64 * 1048576))
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, size * 3, 16 * 1048576),
    )

    refusal = _refuse_rebuild_that_will_not_fit(dump)

    assert refusal is not None and refusal.error is not None
    assert refusal.error.code == "dump_too_large"
    assert refusal.error.details["dump_bytes"] == 64 * 1048576
    assert refusal.error.details["estimated_peak_bytes"] == 64 * 1048576 * 3
    assert refusal.error.details["available_bytes"] == 16 * 1048576


def test_a_vanished_dump_declines_to_judge_rather_than_crash(tmp_path: Path) -> None:
    # With no observed size passed, the guard stats the path itself; a file
    # that has gone missing yields None (let the later read report it) instead
    # of raising out of a guard whose whole job is to prevent a crash.
    missing = tmp_path / "gone.bin"

    assert _refuse_rebuild_that_will_not_fit(missing) is None


def test_an_available_of_none_renders_as_zero_in_the_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When free memory cannot be read the estimator still reports too_big with
    # available=None; the message must not crash formatting it and shows 0 MB.
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"x" * 4096)
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, 999, None),
    )

    refusal = _refuse_rebuild_that_will_not_fit(dump, observed_size=256 * 1048576)

    assert refusal is not None and refusal.error is not None
    assert "0 MB\n is free" not in refusal.error.message  # single-line message
    assert "only 0 MB is free" in refusal.error.message
    assert refusal.error.details["available_bytes"] is None


def test_the_reader_returns_the_payload_when_the_dump_fits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"ABCD" * 16)
    monkeypatch.setattr(
        service_unpack, "rebuild_would_exhaust_memory", lambda size: (False, 0, 1 << 40)
    )

    payload, refusal = _read_dump_for_rebuild(dump)

    assert refusal is None
    assert payload == b"ABCD" * 16


def test_the_reader_passes_the_refusal_through_without_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"x" * 2048)
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, size * 4, 0),
    )

    payload, refusal = _read_dump_for_rebuild(dump)

    assert payload is None
    assert refusal is not None and refusal.error is not None
    assert refusal.error.code == "dump_too_large"


def test_a_dump_that_shrinks_mid_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The guard and the read share one handle, but fstat can still report a
    # size the subsequent read cannot satisfy if the file is truncated under
    # us. A short read means a torn dump, which must not be rebuilt.
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"x" * 32)
    monkeypatch.setattr(
        service_unpack, "rebuild_would_exhaust_memory", lambda size: (False, 0, 1 << 40)
    )

    real_fstat = os.fstat

    def oversized_fstat(fd: int) -> os.stat_result:
        real = real_fstat(fd)
        return os.stat_result(
            (
                real.st_mode,
                real.st_ino,
                real.st_dev,
                real.st_nlink,
                real.st_uid,
                real.st_gid,
                real.st_size + 999,
                real.st_atime,
                real.st_mtime,
                real.st_ctime,
            )
        )

    # service_unpack calls the module-level os.fstat; patching the shared os
    # module object reaches it without relying on a re-export.
    monkeypatch.setattr(os, "fstat", oversized_fstat)

    with pytest.raises(PeRebuildError, match="changed size"):
        _read_dump_for_rebuild(dump)
