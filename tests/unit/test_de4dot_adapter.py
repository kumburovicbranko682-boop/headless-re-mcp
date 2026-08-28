"""Fail-closed contract for the bounded de4dot CLI adapter.

The shared ``_capture_process`` is exercised through the cross-adapter capture
tests; this file pins ``run_de4dot`` itself -- the argv whitelist, the
never-overwrite-input rule, the before/after digest checks, and the way it
retires a partial output whenever the tool floods, fails, or leaves nothing
behind. Validation errors are raised before anything runs, so they hold on every
platform; the checks that need a real child drive a scripted fake CLI and are
POSIX-only (the fake is a ``#!/usr/bin/env python3`` script).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    De4dotResult,
    probe_de4dot_version,
    run_de4dot,
)

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="the fake CLI is a POSIX shebang script")


def _fake_cli(tmp_path: Path, body: str, *, name: str = "de4dot") -> Path:
    script = tmp_path / name
    script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


_PARSE = (
    "import sys\n"
    "args = sys.argv[1:]\n"
    "inp = args[args.index('-f') + 1]\n"
    "out = args[args.index('-o') + 1]\n"
)


def _input(tmp_path: Path, data: bytes = b"MZmanaged-assembly") -> Path:
    src = tmp_path / "sample.dll"
    src.write_bytes(data)
    return src


# ---------------------------------------------------------------------------
# Validation (no child process; cross-platform)
# ---------------------------------------------------------------------------


def test_missing_executable_is_refused(tmp_path: Path) -> None:
    src = _input(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(
            tmp_path / "nope",
            src,
            tmp_path / "out.dll",
            input_sha256=file_sha256(src),
        )
    assert caught.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_a_directory_input_is_reported_as_not_found(tmp_path: Path) -> None:
    exe = tmp_path / "de4dot"
    exe.write_text("", encoding="utf-8")
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, directory, tmp_path / "out.dll", input_sha256="0" * 64)
    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_a_missing_input_is_a_structured_refusal_not_a_raw_oserror(tmp_path: Path) -> None:
    # resolve(strict=True) used to raise FileNotFoundError before the
    # not-a-file branch could run, so a path that does not exist escaped as a
    # raw OSError (leaking the absolute path) instead of INPUT_NOT_FOUND.
    exe = tmp_path / "de4dot"
    exe.write_text("", encoding="utf-8")
    missing = tmp_path / "nope.dll"
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, missing, tmp_path / "out.dll", input_sha256="0" * 64)
    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND
    assert caught.value.details.get("input_path") == str(missing)


def test_input_larger_than_the_cap_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "de4dot"
    exe.write_text("", encoding="utf-8")
    src = _input(tmp_path, b"0123456789")
    with pytest.raises(De4dotError) as caught:
        run_de4dot(
            exe,
            src,
            tmp_path / "out.dll",
            input_sha256=file_sha256(src),
            max_file_size=4,
        )
    assert caught.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_a_preexisting_output_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "de4dot"
    exe.write_text("", encoding="utf-8")
    src = _input(tmp_path)
    out = tmp_path / "out.dll"
    out.write_bytes(b"already here")
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, src, out, input_sha256=file_sha256(src))
    assert caught.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_a_digest_that_changed_before_the_run_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "de4dot"
    exe.write_text("", encoding="utf-8")
    src = _input(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, src, tmp_path / "out.dll", input_sha256="f" * 64)
    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED
    assert caught.value.details["expected"] == "f" * 64


# ---------------------------------------------------------------------------
# Real-run honesty checks (POSIX fake CLI)
# ---------------------------------------------------------------------------


@_POSIX_ONLY
def test_a_clean_run_returns_a_result_with_both_digests(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, _PARSE + "open(out, 'wb').write(b'DEOBFUSCATED')\n")
    src = _input(tmp_path)
    out = tmp_path / "clean" / "out.dll"

    result = run_de4dot(exe, src, out, input_sha256=file_sha256(src))

    assert isinstance(result, De4dotResult)
    assert result.returncode == 0
    assert Path(result.output_path) == out.resolve()
    assert result.input_sha256 == file_sha256(src)
    assert result.output_sha256 == file_sha256(out)
    payload = result.to_dict()
    assert payload["source"] == "de4dot"
    assert payload["claims_universal_unpack"] is False


@_POSIX_ONLY
def test_a_tool_that_mutates_the_input_is_caught(tmp_path: Path) -> None:
    exe = _fake_cli(
        tmp_path,
        _PARSE + "open(out, 'wb').write(b'x')\n" + "open(inp, 'ab').write(b'TAMPER')\n",
    )
    src = _input(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, src, tmp_path / "out.dll", input_sha256=file_sha256(src))
    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


@_POSIX_ONLY
def test_a_stdout_flood_retires_the_partial_output(tmp_path: Path) -> None:
    exe = _fake_cli(
        tmp_path,
        _PARSE
        + "open(out, 'wb').write(b'partial')\n"
        + "sys.stdout.write('A' * 100000)\n"
        + "sys.stdout.flush()\n",
    )
    src = _input(tmp_path)
    out = tmp_path / "flood" / "out.dll"
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, src, out, input_sha256=file_sha256(src), max_output_size=8)
    assert caught.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert not out.exists(), "the partial output must be deleted on an overflow"


@_POSIX_ONLY
def test_a_nonzero_exit_is_process_failed_and_deletes_output(tmp_path: Path) -> None:
    exe = _fake_cli(
        tmp_path,
        _PARSE
        + "open(out, 'wb').write(b'junk')\n"
        + "sys.stderr.write('boom')\n"
        + "sys.exit(3)\n",
    )
    src = _input(tmp_path)
    out = tmp_path / "fail" / "out.dll"
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, src, out, input_sha256=file_sha256(src))
    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 3
    assert caught.value.retryable is True
    assert not out.exists()


@_POSIX_ONLY
def test_a_success_with_no_output_file_is_output_missing(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, _PARSE + "sys.exit(0)\n")
    src = _input(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, src, tmp_path / "gone" / "out.dll", input_sha256=file_sha256(src))
    assert caught.value.code == De4dotErrorCode.OUTPUT_MISSING


# ---------------------------------------------------------------------------
# probe_de4dot_version
# ---------------------------------------------------------------------------


def test_probe_reports_missing_when_the_executable_is_absent(tmp_path: Path) -> None:
    ok, text = probe_de4dot_version(tmp_path / "nope", timeout=2.0)
    assert ok is False
    assert text == ""


@_POSIX_ONLY
def test_probe_reports_ready_when_the_banner_names_de4dot(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, "print('de4dot v3.1.41592 build')\n")
    ok, text = probe_de4dot_version(exe, timeout=5.0)
    assert ok is True
    assert "de4dot" in text.casefold()


@_POSIX_ONLY
def test_probe_accepts_a_clean_exit_without_a_banner(tmp_path: Path) -> None:
    # de4dot builds vary; a 0/1 exit is treated as present even with no banner.
    exe = _fake_cli(tmp_path, "print('usage: tool -f input -o output')\n")
    ok, _text = probe_de4dot_version(exe, timeout=5.0)
    assert ok is True


@_POSIX_ONLY
def test_probe_refuses_a_non_executable_file(tmp_path: Path) -> None:
    # The file exists but cannot be launched; each argv attempt raises OSError,
    # so the probe exhausts its forms and reports absent rather than crashing.
    exe = tmp_path / "de4dot"
    exe.write_text("not runnable\n", encoding="utf-8")
    exe.chmod(0o644)
    ok, text = probe_de4dot_version(exe, timeout=2.0)
    assert ok is False
    assert text == ""


@_POSIX_ONLY
def test_probe_refuses_when_no_argv_form_looks_like_de4dot(tmp_path: Path) -> None:
    # Exit 2 with no banner on every form: not a 0/1 exit and no "de4dot"
    # string, so the loop runs out and the probe stays fail-closed.
    exe = _fake_cli(tmp_path, "import sys\nsys.stderr.write('unknown option\\n')\nsys.exit(2)\n")
    ok, text = probe_de4dot_version(exe, timeout=5.0)
    assert ok is False
    assert text == ""
