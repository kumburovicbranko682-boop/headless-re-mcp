"""``run_net_reactor_slayer`` end-to-end paths driven by stand-in CLI scripts.

The service tests stub the runner, and the adapter's own tests only cover
cancel propagation and error remapping, so the guard rails -- work-copy
isolation, *_Slayed discovery and its fallbacks, input immutability after
the run, exit-code translation with redacted argv -- had no executable
checks. Each test drives the real function with a tiny POSIX shell script
standing in for NETReactorSlayer, which is invoked as
``exe <work_input> --no-pause True`` (the work copy is ``$1``).
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="stand-in NETReactorSlayer scripts are POSIX shell"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _script(tmp_path: Path, body: str) -> Path:
    exe = tmp_path / "fake-nrs.sh"
    exe.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return exe


def _sample(tmp_path: Path) -> Path:
    src = tmp_path / "input.exe"
    src.write_bytes(b"MZ reactor-protected payload")
    return src


class TestRunNetReactorSlayerGuards:
    def test_a_missing_executable_is_a_structured_error(self, tmp_path: Path) -> None:
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(
                tmp_path / "absent-nrs", src, tmp_path / "out.exe", input_sha256=_sha256(src)
            )
        assert exc.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND

    def test_a_directory_input_is_input_not_found(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        source_dir = tmp_path / "not-a-file"
        source_dir.mkdir()
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, source_dir, tmp_path / "out.exe", input_sha256="0" * 64)
        assert exc.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND

    def test_an_oversized_input_is_refused_before_launch(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(
                exe, src, tmp_path / "out.exe", input_sha256=_sha256(src), max_file_size=1
            )
        assert exc.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE
        assert exc.value.details["size"] == src.stat().st_size

    def test_an_existing_output_path_is_never_overwritten(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        out = tmp_path / "out.exe"
        out.write_bytes(b"precious earlier result")
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, src, out, input_sha256=_sha256(src))
        assert exc.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT
        assert out.read_bytes() == b"precious earlier result"

    def test_a_stale_input_hash_refuses_to_run(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, src, tmp_path / "out.exe", input_sha256="0" * 64)
        assert exc.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED
        assert exc.value.details == {"expected": "0" * 64, "actual": _sha256(src)}


class TestRunNetReactorSlayerOutcomes:
    def test_a_clean_run_publishes_the_slayed_copy(self, tmp_path: Path) -> None:
        # The tool works on a temp copy ($1) and writes {stem}_Slayed{suffix}
        # beside it; the adapter must publish that file to output_path.
        exe = _script(
            tmp_path,
            'cp "$1" "$(dirname "$1")/input_Slayed.exe"\necho slayed "$2" "$3"',
        )
        src = _sample(tmp_path)
        out = tmp_path / "deob" / "out.exe"

        result = run_net_reactor_slayer(exe, src, out, input_sha256=_sha256(src), timeout=30)

        assert out.is_file()
        assert result.output_sha256 == _sha256(out)
        assert result.input_sha256 == _sha256(src)
        assert "slayed --no-pause True" in result.stdout
        payload = result.to_dict()
        assert payload["source"] == "net_reactor_slayer"
        assert payload["claims_universal_unpack"] is False
        assert payload["target"] == "authorized_reactor_samples_only"
        # The original input stayed where it was, untouched.
        assert _sha256(src) == result.input_sha256

    def test_an_oddly_named_slayed_file_is_still_found(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'cp "$1" "$(dirname "$1")/renamed_Slayed_v2.bin"')
        src = _sample(tmp_path)
        out = tmp_path / "out.exe"
        result = run_net_reactor_slayer(exe, src, out, input_sha256=_sha256(src))
        assert result.output_sha256 == _sha256(out)

    def test_two_slayed_candidates_are_output_missing_not_a_guess(self, tmp_path: Path) -> None:
        exe = _script(
            tmp_path,
            'cp "$1" "$(dirname "$1")/a_Slayed.bin"\ncp "$1" "$(dirname "$1")/b_Slayed.bin"',
        )
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING

    def test_success_without_a_slayed_file_is_output_missing(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo pretending\nexit 0")
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING
        assert exc.value.returncode == 0

    def test_a_run_that_rewrites_the_original_is_input_mutated(self, tmp_path: Path) -> None:
        src = _sample(tmp_path)
        # The tool only sees the work copy; reaching back to the original is
        # exactly what the post-run hash check must catch.
        exe = _script(tmp_path, f'printf tampered >> "{src}"')
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED
        assert exc.value.returncode == 0

    def test_an_output_flood_is_output_limit(self, tmp_path: Path) -> None:
        # Must exceed the 64 KiB read chunk or the reader stays blocked; sleep
        # keeps the process alive so the limit, not a clean exit, ends the run.
        exe = _script(tmp_path, "head -c 200000 /dev/zero\nsleep 30")
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(
                exe,
                src,
                tmp_path / "out.exe",
                input_sha256=_sha256(src),
                timeout=30,
                max_output_size=512,
            )
        assert exc.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT

    def test_a_nonzero_exit_is_process_failed_with_redacted_argv(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo boom >&2\nexit 5")
        src = _sample(tmp_path)
        with pytest.raises(NetReactorSlayerError) as exc:
            run_net_reactor_slayer(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
        assert exc.value.returncode == 5
        assert exc.value.retryable is True
        assert "boom" in exc.value.stderr
        assert exc.value.details["argv"] == [
            "NETReactorSlayer",
            "<input>",
            "--no-pause",
            "True",
        ]


class TestProbeNetReactorSlayer:
    def test_a_missing_binary_probes_false(self, tmp_path: Path) -> None:
        assert probe_net_reactor_slayer(tmp_path / "absent") == (False, "")

    def test_the_tool_name_in_the_banner_is_ready(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'echo "NETReactorSlayer 6.4"\nexit 0')
        ok, text = probe_net_reactor_slayer(exe, timeout=10)
        assert ok is True
        assert "NETReactorSlayer" in text

    def test_a_usage_print_with_exit_one_is_ready(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'echo "usage: tool <file>"\nexit 1')
        ok, text = probe_net_reactor_slayer(exe, timeout=10)
        assert ok is True
        assert "usage" in text

    def test_unrecognized_output_still_counts_as_a_response(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo hello-world\nexit 0")
        ok, text = probe_net_reactor_slayer(exe, timeout=10)
        assert ok is True
        assert text == "hello-world"

    def test_a_silent_clean_exit_probes_false(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        assert probe_net_reactor_slayer(exe, timeout=10) == (False, "")

    def test_a_hung_binary_probes_false(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "sleep 30")
        assert probe_net_reactor_slayer(exe, timeout=0.3) == (False, "")

    def test_an_unexecutable_file_probes_false(self, tmp_path: Path) -> None:
        exe = tmp_path / "no-exec-bit"
        exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        assert probe_net_reactor_slayer(exe, timeout=5) == (False, "")
