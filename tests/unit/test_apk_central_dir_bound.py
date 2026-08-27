"""Session creation refuses archives that declare an oversized central directory.

zipfile materialises one ZipInfo per central-directory entry the moment the
archive is opened, before namelist() is ever called, and CPython reads exactly
as many directory bytes as the end-of-central-directory record declares. A
crafted package could therefore cost hundreds of megabytes at session creation,
before any tool ran and before the derived-set caps could apply. The declared
size is now checked first, through the same stdlib helper ZipFile itself
trusts, so the parse never starts.

The hostile archives here are hand-packed end-of-central-directory records: a
few dozen bytes that *declare* a gigantic directory. That is exactly the field
the parser budgets from, so the refusal can be asserted against the real cap
without materialising anything.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core import session as session_module
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.session import (
    _MAX_APK_CENTRAL_DIR_BYTES,
    _central_directory_size,
    _is_android_package,
    classify_target,
    describe_apk,
)


def _write_apk(path: Path, *, extra_entries: int = 0) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("classes.dex", b"dex")
        for index in range(extra_entries):
            archive.writestr(f"assets/a{index:05d}", b"")


def _write_lying_eocd(path: Path, declared_size: int) -> None:
    """A 22-byte end-of-central-directory record and nothing else."""
    path.write_bytes(
        struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, declared_size, 0, 0)
    )


def _write_zip64_eocd(path: Path, declared_size: int) -> None:
    """A well-formed ZIP64 end-of-central-directory chain declaring ``declared_size``.

    Python 3.12+ verifies that the declared directory ends exactly where the
    ZIP64 record starts, so the file has to carry that many placeholder bytes;
    the declared size is still the figure the parser budgets from.
    """
    eocd64 = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, declared_size, 0)
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, declared_size, 1)
    eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    path.write_bytes(b"\x00" * declared_size + eocd64 + locator + eocd)


def test_a_declared_oversized_directory_is_refused_before_the_parse(
    tmp_path: Path,
) -> None:
    target = tmp_path / "evil.apk"
    _write_lying_eocd(target, 2**31)

    assert _central_directory_size(target) == 2**31
    assert not _is_android_package(target)
    with pytest.raises(ValueError, match="central directory"):
        describe_apk(target)


def test_a_zip64_declared_size_is_measured_not_skipped(tmp_path: Path) -> None:
    """The 64-bit field must be read; failing open on ZIP64 would be the evasion."""
    target = tmp_path / "evil64.apk"
    declared = _MAX_APK_CENTRAL_DIR_BYTES + 2**20
    _write_zip64_eocd(target, declared)

    assert _central_directory_size(target) == declared
    assert not _is_android_package(target)
    with pytest.raises(ValueError, match="central directory"):
        describe_apk(target)


def test_an_oversized_real_directory_routes_to_the_pe_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Suffix-less so classification has to look at the content, and with enough
    # entries that the genuine central directory crosses a lowered cap.
    target = tmp_path / "sample"
    _write_apk(target, extra_entries=200)
    assert classify_target(target) is TargetKind.APK

    size = _central_directory_size(target)
    assert size is not None and size > 4096
    monkeypatch.setattr(session_module, "_MAX_APK_CENTRAL_DIR_BYTES", 4096)
    assert classify_target(target) is TargetKind.PE
    with pytest.raises(ValueError, match="central directory"):
        describe_apk(target)


def test_a_real_package_is_measured_and_still_described(tmp_path: Path) -> None:
    small = tmp_path / "small.apk"
    _write_apk(small)
    larger = tmp_path / "larger.apk"
    _write_apk(larger, extra_entries=50)

    small_size = _central_directory_size(small)
    larger_size = _central_directory_size(larger)
    assert small_size is not None and 0 < small_size < 4096
    assert larger_size is not None and larger_size > small_size
    assert small_size < _MAX_APK_CENTRAL_DIR_BYTES

    described = describe_apk(small)
    assert described["apk"]["entry_count"] == 2
    assert described["apk"]["dex_count"] == 1


def test_archives_the_stdlib_cannot_measure_fail_open(tmp_path: Path) -> None:
    """No guess when the record is unreadable: zipfile's own error names it."""
    not_a_zip = tmp_path / "notes.apk"
    not_a_zip.write_bytes(b"x" * 100)
    empty = tmp_path / "empty.apk"
    empty.write_bytes(b"")

    assert _central_directory_size(not_a_zip) is None
    assert _central_directory_size(empty) is None
    with pytest.raises(ValueError, match="not a readable Android package"):
        describe_apk(not_a_zip)
