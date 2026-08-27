"""The XVLKC unpacker adapter's fail-closed contract, driven with a fake CLI.

XVLKC is an optional, user-configured tool the adapter shells out to. The
adapter's whole job is to be safe around it: run only a whitelisted argv on a
work copy, never overwrite the original input, cap output, and publish exactly
one newest PE or fail closed. None of that ran on a hosted platform because the
real tool is Windows-only, so the module sat at 30%. A tiny POSIX shell script
stands in for the CLI and drives the success and refusal paths for real; the
PE sniffing and newest-output selection are unit-tested directly.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.xvlkc import (
    XvlkcError,
    XvlkcErrorCode,
    _collect_newest_pe,
    _is_pe_file,
    probe_xvlkc,
    run_xvlkc,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="the fake CLI is a /bin/sh script")


def _pe_bytes(tag: bytes = b"\x00") -> bytes:
    """A minimal but valid MZ/PE image: MZ, e_lfanew at 0x3C, PE\\0\\0 there."""
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    image[0x44:0x45] = tag
    return bytes(image)


def _write_pe(path: Path, tag: bytes = b"\x00") -> Path:
    path.write_bytes(_pe_bytes(tag))
    return path


def _cli(tmp_path: Path, body: str, name: str = "fake_xvlkc") -> Path:
    script = tmp_path / name
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(0o755)
    return script


# --------------------------------------------------------------------------
# PE sniffing.
# --------------------------------------------------------------------------


def test_is_pe_file_accepts_a_valid_image_and_rejects_others(tmp_path: Path) -> None:
    good = _write_pe(tmp_path / "good.exe")
    assert _is_pe_file(good) is True

    not_mz = tmp_path / "plain.bin"
    not_mz.write_bytes(b"ZZ" + b"\0" * 0x60)
    assert _is_pe_file(not_mz) is False

    short = tmp_path / "short.bin"
    short.write_bytes(b"MZ")
    assert _is_pe_file(short) is False

    assert _is_pe_file(tmp_path / "missing.exe") is False


def test_is_pe_file_rejects_a_bogus_pe_offset(tmp_path: Path) -> None:
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x10)  # points before the header end
    bad = tmp_path / "bad_offset.exe"
    bad.write_bytes(image)
    assert _is_pe_file(bad) is False


# --------------------------------------------------------------------------
# newest-PE selection.
# --------------------------------------------------------------------------


def test_collect_newest_pe_skips_the_work_input_and_picks_the_newest(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    older = _write_pe(work / "older.exe")
    newer = _write_pe(work / "newer.exe")
    os.utime(older, (1_000, 1_000))
    os.utime(newer, (2_000, 2_000))

    assert _collect_newest_pe(work, work_input) == newer


def test_collect_newest_pe_fails_closed_when_nothing_is_produced(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    (work / "log.txt").write_bytes(b"not a pe")

    with pytest.raises(XvlkcError) as caught:
        _collect_newest_pe(work, work_input)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_MISSING


def test_collect_newest_pe_refuses_an_ambiguous_tie(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    one = _write_pe(work / "one.exe")
    two = _write_pe(work / "two.exe")
    os.utime(one, (5_000, 5_000))
    os.utime(two, (5_000, 5_000))

    with pytest.raises(XvlkcError) as caught:
        _collect_newest_pe(work, work_input)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_AMBIGUOUS


# --------------------------------------------------------------------------
# run_xvlkc argument/precondition refusals (cross-platform).
# --------------------------------------------------------------------------


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    src = _write_pe(tmp_path / "in.exe")
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(
            tmp_path / "nope",
            src,
            tmp_path / "out.exe",
            input_sha256=file_sha256(src),
        )
    assert caught.value.code == XvlkcErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_an_input_that_is_not_a_regular_file(tmp_path: Path) -> None:
    exe = _cli(tmp_path, "exit 0\n") if os.name != "nt" else (tmp_path / "exe")
    if os.name == "nt":
        exe.write_bytes(b"MZ")
    a_directory = tmp_path / "adir"
    a_directory.mkdir()
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, a_directory, tmp_path / "out.exe", input_sha256="0" * 64)
    assert caught.value.code == XvlkcErrorCode.INPUT_NOT_FOUND


def test_run_refuses_input_over_the_size_cap(tmp_path: Path) -> None:
    exe = _cli(tmp_path, "exit 0\n")
    src = _write_pe(tmp_path / "in.exe")
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(
            exe,
            src,
            tmp_path / "out.exe",
            input_sha256=file_sha256(src),
            max_file_size=8,
        )
    assert caught.value.code == XvlkcErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_preexisting_output(tmp_path: Path) -> None:
    exe = _cli(tmp_path, "exit 0\n")
    src = _write_pe(tmp_path / "in.exe")
    dest = _write_pe(tmp_path / "out.exe")
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, dest, input_sha256=file_sha256(src))
    assert caught.value.code == XvlkcErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_changed_input_digest(tmp_path: Path) -> None:
    exe = _cli(tmp_path, "exit 0\n")
    src = _write_pe(tmp_path / "in.exe")
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256="0" * 64)
    assert caught.value.code == XvlkcErrorCode.INPUT_MUTATED


# --------------------------------------------------------------------------
# run_xvlkc end to end against the fake CLI (POSIX).
# --------------------------------------------------------------------------


@posix_only
def test_run_publishes_the_newest_pe_and_preserves_the_input(tmp_path: Path) -> None:
    # The CLI copies a valid PE template beside its work-copy argument, exits 0.
    template = _write_pe(tmp_path / "template.exe", tag=b"\x02")
    exe = _cli(
        tmp_path,
        f'dir=$(dirname "$1")\ncp "{template}" "$dir/unpacked.exe"\necho "xvlkc done"\n',
    )
    src = _write_pe(tmp_path / "in.exe", tag=b"\x01")
    before = file_sha256(src)
    dest = tmp_path / "out" / "result.exe"

    result = run_xvlkc(exe, src, dest, input_sha256=before)

    assert result.returncode == 0
    assert Path(result.output_path).is_file()
    assert result.input_sha256 == before
    assert result.output_sha256 == file_sha256(dest)
    assert "xvlkc done" in result.stdout
    assert result.to_dict()["source"] == "xvlkc"
    assert result.to_dict()["claims_universal_unpack"] is False
    # The original input is byte-for-byte untouched.
    assert file_sha256(src) == before


@posix_only
def test_run_maps_a_nonzero_exit_to_process_failed_and_cleans_up(tmp_path: Path) -> None:
    exe = _cli(tmp_path, 'echo "boom" >&2\nexit 7\n')
    src = _write_pe(tmp_path / "in.exe")
    dest = tmp_path / "out.exe"

    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, dest, input_sha256=file_sha256(src))
    assert caught.value.code == XvlkcErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 7
    assert "boom" in caught.value.stderr
    assert not dest.exists()  # a failed run leaves no partial output


@posix_only
def test_run_fails_closed_when_the_cli_makes_no_pe(tmp_path: Path) -> None:
    exe = _cli(tmp_path, 'dir=$(dirname "$1")\necho "notpe" > "$dir/log.txt"\nexit 0\n')
    src = _write_pe(tmp_path / "in.exe")
    dest = tmp_path / "out.exe"

    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, dest, input_sha256=file_sha256(src))
    assert caught.value.code == XvlkcErrorCode.OUTPUT_MISSING
    assert not dest.exists()


@posix_only
def test_run_maps_a_non_executable_tool_to_a_structured_error(tmp_path: Path) -> None:
    # A file that exists but cannot exec: the launch failure must surface as a
    # structured XvlkcError, not an unhandled OSError.
    exe = tmp_path / "not_exec"
    exe.write_bytes(_pe_bytes())  # present, but no +x bit
    exe.chmod(0o644)
    src = _write_pe(tmp_path / "in.exe")

    with pytest.raises(XvlkcError):
        run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=file_sha256(src))


# --------------------------------------------------------------------------
# probe_xvlkc.
# --------------------------------------------------------------------------


def test_probe_reports_absent_when_the_executable_is_missing(tmp_path: Path) -> None:
    ok, text = probe_xvlkc(tmp_path / "missing")
    assert ok is False and text == ""


@posix_only
def test_probe_recognises_usage_output(tmp_path: Path) -> None:
    exe = _cli(tmp_path, 'echo "Usage: xvlkc <input>"\nexit 1\n')
    ok, text = probe_xvlkc(exe, timeout=5)
    assert ok is True
    assert "Usage" in text


@posix_only
def test_probe_accepts_a_clean_exit_with_output(tmp_path: Path) -> None:
    exe = _cli(tmp_path, 'echo "ready"\nexit 0\n')
    ok, text = probe_xvlkc(exe, timeout=5)
    assert ok is True
    assert "ready" in text


@posix_only
def test_probe_falls_back_to_any_output_on_an_unrecognised_exit(tmp_path: Path) -> None:
    # No known token, and an exit code outside the accepted set: the probe
    # still reports present when the tool wrote something, keyed on output.
    exe = _cli(tmp_path, 'echo "zzz opaque banner"\nexit 2\n')
    ok, text = probe_xvlkc(exe, timeout=5)
    assert ok is True
    assert "opaque" in text
