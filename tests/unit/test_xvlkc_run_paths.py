"""``run_xvlkc`` end-to-end paths driven by stand-in CLI scripts.

The service tests stub the runner, so the adapter's own guard rails -- PE
sniffing, newest-PE discovery with fail-closed ambiguity, work-copy
isolation, input immutability after the run, exit-code translation with
redacted argv -- had no executable checks. Each test drives the real
function with a tiny POSIX shell script standing in for XVLKC, which is
invoked as ``exe <work_input>`` (the work copy is ``$1``).
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.unpack import xvlkc
from headless_re_mcp.unpack.xvlkc import (
    XvlkcError,
    XvlkcErrorCode,
    _collect_newest_pe,
    _is_pe_file,
    probe_xvlkc,
    run_xvlkc,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="stand-in XVLKC scripts are POSIX shell")

# MZ header, e_lfanew at 0x3C pointing at 0x40, "PE\0\0" signature there.
_MINIMAL_PE = b"MZ" + b"\0" * 58 + (0x40).to_bytes(4, "little") + b"PE\0\0"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _script(tmp_path: Path, body: str) -> Path:
    exe = tmp_path / "fake-xvlkc.sh"
    exe.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return exe


def _sample(tmp_path: Path) -> Path:
    src = tmp_path / "packed.exe"
    src.write_bytes(_MINIMAL_PE)
    return src


class TestIsPeFile:
    def test_a_minimal_pe_is_recognized(self, tmp_path: Path) -> None:
        path = tmp_path / "ok.bin"
        path.write_bytes(_MINIMAL_PE)
        assert _is_pe_file(path) is True

    def test_a_short_file_is_not_a_pe(self, tmp_path: Path) -> None:
        path = tmp_path / "short.bin"
        path.write_bytes(b"MZ")
        assert _is_pe_file(path) is False

    def test_a_non_mz_header_is_not_a_pe(self, tmp_path: Path) -> None:
        path = tmp_path / "elf.bin"
        path.write_bytes(b"\x7fELF" + b"\0" * 0x40)
        assert _is_pe_file(path) is False

    def test_an_e_lfanew_inside_the_dos_header_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "loop.bin"
        path.write_bytes(b"MZ" + b"\0" * 58 + (0x10).to_bytes(4, "little"))
        assert _is_pe_file(path) is False

    def test_a_wrong_signature_at_e_lfanew_is_not_a_pe(self, tmp_path: Path) -> None:
        path = tmp_path / "ne.bin"
        path.write_bytes(b"MZ" + b"\0" * 58 + (0x40).to_bytes(4, "little") + b"NE\0\0")
        assert _is_pe_file(path) is False

    def test_an_e_lfanew_past_the_end_of_file_is_not_a_pe(self, tmp_path: Path) -> None:
        path = tmp_path / "trunc.bin"
        path.write_bytes(b"MZ" + b"\0" * 58 + (0x1000).to_bytes(4, "little"))
        assert _is_pe_file(path) is False

    def test_an_unreadable_path_is_not_a_pe(self, tmp_path: Path) -> None:
        assert _is_pe_file(tmp_path) is False  # a directory raises OSError on open


class TestCollectNewestPe:
    def test_no_pe_beside_the_work_copy_is_output_missing(self, tmp_path: Path) -> None:
        work_input = tmp_path / "in.exe"
        work_input.write_bytes(_MINIMAL_PE)
        (tmp_path / "notes.txt").write_text("not a pe", encoding="utf-8")
        with pytest.raises(XvlkcError) as exc:
            _collect_newest_pe(tmp_path, work_input)
        assert exc.value.code == XvlkcErrorCode.OUTPUT_MISSING

    def test_the_single_newest_pe_wins_even_in_a_subdirectory(self, tmp_path: Path) -> None:
        work_input = tmp_path / "in.exe"
        work_input.write_bytes(_MINIMAL_PE)
        older = tmp_path / "older.bin"
        older.write_bytes(_MINIMAL_PE)
        os.utime(older, (1_000_000, 1_000_000))
        nested = tmp_path / "dump"
        nested.mkdir()
        newest = nested / "unpacked.bin"
        newest.write_bytes(_MINIMAL_PE)
        os.utime(newest, (2_000_000, 2_000_000))

        assert _collect_newest_pe(tmp_path, work_input) == newest

    def test_two_pes_sharing_the_newest_mtime_fail_closed(self, tmp_path: Path) -> None:
        work_input = tmp_path / "in.exe"
        work_input.write_bytes(_MINIMAL_PE)
        for name in ("a.bin", "b.bin"):
            path = tmp_path / name
            path.write_bytes(_MINIMAL_PE)
            os.utime(path, (2_000_000, 2_000_000))
        with pytest.raises(XvlkcError) as exc:
            _collect_newest_pe(tmp_path, work_input)
        assert exc.value.code == XvlkcErrorCode.OUTPUT_AMBIGUOUS
        assert len(exc.value.details["candidates"]) == 2


class TestRunXvlkcGuards:
    def test_a_missing_executable_is_a_structured_error(self, tmp_path: Path) -> None:
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(
                tmp_path / "absent-xvlkc", src, tmp_path / "out.exe", input_sha256=_sha256(src)
            )
        assert exc.value.code == XvlkcErrorCode.EXECUTABLE_NOT_FOUND

    def test_a_directory_input_is_input_not_found(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        source_dir = tmp_path / "not-a-file"
        source_dir.mkdir()
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, source_dir, tmp_path / "out.exe", input_sha256="0" * 64)
        assert exc.value.code == XvlkcErrorCode.INPUT_NOT_FOUND

    def test_an_oversized_input_is_refused_before_launch(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src), max_file_size=1)
        assert exc.value.code == XvlkcErrorCode.INPUT_TOO_LARGE

    def test_an_existing_output_path_is_never_overwritten(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        out = tmp_path / "out.exe"
        out.write_bytes(b"precious earlier result")
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, out, input_sha256=_sha256(src))
        assert exc.value.code == XvlkcErrorCode.INVALID_ARGUMENT
        assert out.read_bytes() == b"precious earlier result"

    def test_a_stale_input_hash_refuses_to_run(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256="0" * 64)
        assert exc.value.code == XvlkcErrorCode.INPUT_MUTATED
        assert exc.value.details == {"expected": "0" * 64, "actual": _sha256(src)}


class TestRunXvlkcOutcomes:
    def test_a_clean_run_publishes_the_produced_pe(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'cp "$1" "$(dirname "$1")/unpacked.bin"\necho done')
        src = _sample(tmp_path)
        out = tmp_path / "unpacked" / "out.exe"

        result = run_xvlkc(exe, src, out, input_sha256=_sha256(src), timeout=30)

        assert out.is_file()
        assert result.output_sha256 == _sha256(out)
        assert result.input_sha256 == _sha256(src)
        assert "done" in result.stdout
        payload = result.to_dict()
        assert payload["source"] == "xvlkc"
        assert payload["claims_universal_unpack"] is False
        assert payload["output_path"] == str(out.resolve())

    def test_success_without_a_pe_output_is_output_missing(self, tmp_path: Path) -> None:
        # A text report is not an unpacked binary; discovery must stay closed.
        exe = _script(tmp_path, 'echo report > "$(dirname "$1")/log.txt"\nexit 0')
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == XvlkcErrorCode.OUTPUT_MISSING

    def test_a_run_that_rewrites_the_original_is_input_mutated(self, tmp_path: Path) -> None:
        src = _sample(tmp_path)
        exe = _script(tmp_path, f'printf tampered >> "{src}"')
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == XvlkcErrorCode.INPUT_MUTATED
        assert exc.value.returncode == 0

    def test_an_output_flood_is_output_limit(self, tmp_path: Path) -> None:
        # Must exceed the 64 KiB read chunk or the reader stays blocked; sleep
        # keeps the process alive so the limit, not a clean exit, ends the run.
        exe = _script(tmp_path, "head -c 200000 /dev/zero\nsleep 30")
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(
                exe,
                src,
                tmp_path / "out.exe",
                input_sha256=_sha256(src),
                timeout=30,
                max_output_size=512,
            )
        assert exc.value.code == XvlkcErrorCode.OUTPUT_LIMIT

    def test_a_nonzero_exit_is_process_failed_with_redacted_argv(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo boom >&2\nexit 7")
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == XvlkcErrorCode.PROCESS_FAILED
        assert exc.value.returncode == 7
        assert exc.value.retryable is True
        assert "boom" in exc.value.stderr
        assert exc.value.details["argv"] == ["xvlkc", "<input>"]


class TestRunXvlkcCaptureFailures:
    def test_a_caller_cancel_propagates_as_cancellation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cancel is not a tool failure and must not be remapped."""

        def _cancelled(*_args: object, **_kwargs: object) -> object:
            raise BoundedCancelled()

        monkeypatch.setattr(xvlkc, "_capture_process", _cancelled)
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(BoundedCancelled):
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))

    def test_a_capture_error_is_remapped_with_its_code_and_streams(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _failing(*_args: object, **_kwargs: object) -> object:
            raise De4dotError(
                "timeout",
                "de4dot timed out after 1s",
                stdout="partial out",
                stderr="partial err",
                returncode=-9,
                retryable=True,
            )

        monkeypatch.setattr(xvlkc, "_capture_process", _failing)
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(XvlkcError) as exc:
            run_xvlkc(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == "timeout"
        assert exc.value.stdout == "partial out"
        assert exc.value.stderr == "partial err"
        assert exc.value.returncode == -9
        assert exc.value.retryable is True


class TestProbeXvlkc:
    def test_a_missing_binary_probes_false(self, tmp_path: Path) -> None:
        assert probe_xvlkc(tmp_path / "absent") == (False, "")

    def test_a_usage_banner_is_ready_regardless_of_exit_code(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'echo "usage: xvlkc <file>"\nexit 2')
        ok, text = probe_xvlkc(exe, timeout=10)
        assert ok is True
        assert "usage" in text

    def test_token_free_output_with_a_clean_exit_is_ready(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo hello-there\nexit 0")
        ok, text = probe_xvlkc(exe, timeout=10)
        assert ok is True
        assert text == "hello-there"

    def test_token_free_output_with_an_odd_exit_still_counts(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo zzz\nexit 7")
        assert probe_xvlkc(exe, timeout=10) == (True, "zzz")

    def test_a_silent_odd_exit_probes_false(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 7")
        assert probe_xvlkc(exe, timeout=10) == (False, "")

    def test_a_hung_binary_probes_false(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "sleep 30")
        assert probe_xvlkc(exe, timeout=0.3) == (False, "")

    def test_an_unexecutable_file_probes_false(self, tmp_path: Path) -> None:
        exe = tmp_path / "no-exec-bit"
        exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        assert probe_xvlkc(exe, timeout=5) == (False, "")
