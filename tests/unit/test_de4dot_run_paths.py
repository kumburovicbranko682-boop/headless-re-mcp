"""``run_de4dot`` end-to-end paths driven by stand-in CLI scripts.

The service tests stub ``run_de4dot`` entirely, so the adapter's own guard
rails -- input immutability, output-limit unlink, exit-code translation,
missing-output detection -- had no executable checks. Each test here drives
the real function with a tiny shell script standing in for de4dot, plus a
few direct probes of the capture helpers the function is built on.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.dotnet import de4dot
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    probe_de4dot_version,
    run_de4dot,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="stand-in de4dot scripts are POSIX shell")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _script(tmp_path: Path, body: str) -> Path:
    """A fake de4dot invoked as ``exe -f <input> -o <output>``.

    Inside the script ``$2`` is the input assembly and ``$4`` the output path.
    """
    exe = tmp_path / "fake-de4dot.sh"
    exe.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return exe


def _sample(tmp_path: Path) -> Path:
    src = tmp_path / "input.exe"
    src.write_bytes(b"MZ fake assembly payload")
    return src


class TestRunDe4dotGuards:
    """Precondition failures must be structured errors, not raw OSErrors."""

    def test_a_missing_executable_is_a_structured_error(self, tmp_path: Path) -> None:
        src = _sample(tmp_path)
        with pytest.raises(De4dotError) as exc:
            run_de4dot(
                tmp_path / "absent-de4dot",
                src,
                tmp_path / "out.exe",
                input_sha256=_sha256(src),
            )
        assert exc.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND
        assert "absent-de4dot" in str(exc.value.details.get("executable"))

    def test_a_directory_input_is_input_not_found(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        source_dir = tmp_path / "not-a-file"
        source_dir.mkdir()
        with pytest.raises(De4dotError) as exc:
            run_de4dot(exe, source_dir, tmp_path / "out.exe", input_sha256="0" * 64)
        assert exc.value.code == De4dotErrorCode.INPUT_NOT_FOUND

    def test_an_oversized_input_is_refused_before_launch(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(De4dotError) as exc:
            run_de4dot(
                exe,
                src,
                tmp_path / "out.exe",
                input_sha256=_sha256(src),
                max_file_size=1,
            )
        assert exc.value.code == De4dotErrorCode.INPUT_TOO_LARGE
        assert exc.value.details["max_file_size"] == 1
        assert exc.value.details["size"] == src.stat().st_size

    def test_an_existing_output_path_is_never_overwritten(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        out = tmp_path / "out.exe"
        out.write_bytes(b"precious earlier result")
        with pytest.raises(De4dotError) as exc:
            run_de4dot(exe, src, out, input_sha256=_sha256(src))
        assert exc.value.code == De4dotErrorCode.INVALID_ARGUMENT
        assert out.read_bytes() == b"precious earlier result"

    def test_a_stale_input_hash_refuses_to_run(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "exit 0")
        src = _sample(tmp_path)
        with pytest.raises(De4dotError) as exc:
            run_de4dot(exe, src, tmp_path / "out.exe", input_sha256="0" * 64)
        assert exc.value.code == De4dotErrorCode.INPUT_MUTATED
        assert exc.value.details == {"expected": "0" * 64, "actual": _sha256(src)}


class TestRunDe4dotOutcomes:
    def test_a_clean_run_reports_both_hashes(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'cp "$2" "$4"\necho cleaned')
        src = _sample(tmp_path)
        out = tmp_path / "deob" / "out.exe"

        result = run_de4dot(exe, src, out, input_sha256=_sha256(src), timeout=30)

        assert result.returncode == 0
        assert result.input_sha256 == _sha256(src)
        assert result.output_sha256 == _sha256(out)
        assert "cleaned" in result.stdout
        payload = result.to_dict()
        assert payload["source"] == "de4dot"
        assert payload["claims_universal_unpack"] is False
        assert payload["output_path"] == str(out.resolve())
        assert payload["duration_ms"] >= 0

    def test_a_run_that_rewrites_the_input_is_input_mutated(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'cp "$2" "$4"\nprintf tampered >> "$2"')
        src = _sample(tmp_path)
        with pytest.raises(De4dotError) as exc:
            run_de4dot(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == De4dotErrorCode.INPUT_MUTATED
        assert exc.value.returncode == 0

    def test_an_output_flood_unlinks_the_partial_result(self, tmp_path: Path) -> None:
        # The reader blocks in BufferedReader.read(64 KiB) until a full chunk
        # or EOF, so the flood must exceed _READ_CHUNK_SIZE for the limit to
        # fire while the process is still alive; sleep keeps it alive so the
        # limit event, not a clean exit, ends the wait loop.
        assert de4dot._READ_CHUNK_SIZE < 200_000
        exe = _script(tmp_path, 'cp "$2" "$4"\nhead -c 200000 /dev/zero\nsleep 30')
        src = _sample(tmp_path)
        out = tmp_path / "out.exe"
        with pytest.raises(De4dotError) as exc:
            run_de4dot(
                exe,
                src,
                out,
                input_sha256=_sha256(src),
                timeout=30,
                max_output_size=512,
            )
        assert exc.value.code == De4dotErrorCode.OUTPUT_LIMIT
        assert not out.exists(), "partial output must not survive an output flood"

    def test_a_nonzero_exit_is_process_failed_and_removes_output(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'cp "$2" "$4"\necho boom >&2\nexit 3')
        src = _sample(tmp_path)
        out = tmp_path / "out.exe"
        with pytest.raises(De4dotError) as exc:
            run_de4dot(exe, src, out, input_sha256=_sha256(src))
        assert exc.value.code == De4dotErrorCode.PROCESS_FAILED
        assert exc.value.returncode == 3
        assert exc.value.retryable is True
        assert "boom" in exc.value.stderr
        # argv in details must be redacted placeholders, never real paths.
        assert exc.value.details["argv"] == ["de4dot", "-f", "<input>", "-o", "<output>"]
        assert not out.exists(), "failed run must not leave a half-written output"

    def test_success_without_an_output_file_is_output_missing(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo pretending\nexit 0")
        src = _sample(tmp_path)
        with pytest.raises(De4dotError) as exc:
            run_de4dot(exe, src, tmp_path / "out.exe", input_sha256=_sha256(src))
        assert exc.value.code == De4dotErrorCode.OUTPUT_MISSING
        assert exc.value.returncode == 0


class _FakePipe:
    def __init__(self, items: list[Any]) -> None:
        self._items = list(items)
        self.closed = False

    def read(self, _size: int) -> bytes:
        item = self._items.pop(0)
        if isinstance(item, Exception):
            raise item
        assert isinstance(item, bytes)
        return item

    def close(self) -> None:
        self.closed = True


class TestCapturedStream:
    def test_overflow_stops_reading_and_flags_the_stream(self) -> None:
        stream = de4dot._CapturedStream(max_size=15)
        event = Event()
        pipe = _FakePipe([b"a" * 10, b"b" * 10, b""])

        stream.read_from(pipe, event)

        assert stream.exceeded is True
        assert event.is_set()
        # The chunk that crossed the bound is dropped, not half-kept.
        assert stream.text() == "a" * 10
        assert pipe.closed is True

    def test_a_reader_error_keeps_what_was_already_read(self) -> None:
        stream = de4dot._CapturedStream(max_size=1024)
        event = Event()
        pipe = _FakePipe([b"partial", OSError("pipe torn down")])

        stream.read_from(pipe, event)

        assert stream.exceeded is False
        assert not event.is_set()
        assert stream.text() == "partial"
        assert pipe.closed is True


class TestCaptureProcessPipes:
    def test_missing_pipes_fail_instead_of_hanging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A Popen without pipes must be a structured failure, not a wedge."""
        fake_process = SimpleNamespace(
            pid=None,
            stdout=None,
            stderr=None,
            poll=lambda: 0,
            kill=lambda: None,
            wait=lambda timeout=None: 0,
        )
        monkeypatch.setattr(de4dot.subprocess, "Popen", lambda argv, **_kw: fake_process)
        with pytest.raises(De4dotError) as exc:
            de4dot._capture_process(["whatever"], timeout=1.0, max_output_size=64)
        assert exc.value.code == De4dotErrorCode.PROCESS_FAILED
        assert "stdout/stderr pipes" in str(exc.value)


class TestProbeDe4dotVersion:
    def test_a_missing_binary_probes_false(self, tmp_path: Path) -> None:
        assert probe_de4dot_version(tmp_path / "absent") == (False, "")

    def test_a_banner_with_the_tool_name_is_ready(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, 'echo "de4dot v3.1 deobfuscator"\nexit 0')
        ok, text = probe_de4dot_version(exe, timeout=10)
        assert ok is True
        assert "de4dot" in text

    def test_a_help_style_exit_code_counts_without_the_name(self, tmp_path: Path) -> None:
        exe = _script(tmp_path, "echo usage\nexit 1")
        ok, text = probe_de4dot_version(exe, timeout=10)
        assert ok is True
        assert "usage" in text

    def test_a_hung_binary_probes_false_without_retrying_more_flags(self, tmp_path: Path) -> None:
        """One timed-out attempt must end the probe, not try -h and --help too."""
        exe = _script(tmp_path, "sleep 30")
        ok, text = probe_de4dot_version(exe, timeout=0.3)
        assert (ok, text) == (False, "")

    def test_an_unexecutable_file_probes_false(self, tmp_path: Path) -> None:
        exe = tmp_path / "no-exec-bit"
        exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        assert probe_de4dot_version(exe, timeout=5) == (False, "")
