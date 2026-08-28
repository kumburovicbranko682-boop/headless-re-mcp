"""Fail-closed contract for the bounded NETReactorSlayer CLI adapter.

The service-level tests drive ``dotnet.deobfuscate`` with a mocked runner, so
``run_net_reactor_slayer`` itself -- the argv whitelist, the work-copy isolation,
the before/after digest checks, and the ``*_Slayed`` publication -- is otherwise
unexercised. This pins it directly. Validation errors raise before anything
runs, so they hold on every platform; the checks that need a real child drive a
scripted fake CLI and are POSIX-only (the fake is a ``#!/usr/bin/env python3``
script). The tool receives ``<work_input> --no-pause True`` and writes its result
beside the work copy, which the adapter copies to ``output_path``.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import headless_re_mcp.core.session as session_mod
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    NetReactorSlayerResult,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="the fake CLI is a POSIX shebang script")


def _fake_cli(tmp_path: Path, body: str, *, name: str = "nrs") -> Path:
    script = tmp_path / name
    script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


# The tool is invoked as ``<exe> <work_input> --no-pause True``; argv[1] is the
# copied assembly and the result is written beside it.
_HEAD = "import sys\nfrom pathlib import Path\ninp = Path(sys.argv[1])\n"
_WRITE_SLAYED = (
    "slayed = inp.with_name(inp.stem + '_Slayed' + inp.suffix)\n"
    "slayed.write_bytes(b'SLAYED-OUTPUT')\n"
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
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            tmp_path / "nope", src, tmp_path / "out.dll", input_sha256=file_sha256(src)
        )
    assert caught.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_a_directory_input_is_reported_as_not_found(tmp_path: Path) -> None:
    exe = tmp_path / "nrs"
    exe.write_text("", encoding="utf-8")
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, directory, tmp_path / "out.dll", input_sha256="0" * 64)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_input_larger_than_the_cap_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "nrs"
    exe.write_text("", encoding="utf-8")
    src = _input(tmp_path, b"0123456789")
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            exe,
            src,
            tmp_path / "out.dll",
            input_sha256=file_sha256(src),
            max_file_size=4,
        )
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_a_preexisting_output_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "nrs"
    exe.write_text("", encoding="utf-8")
    src = _input(tmp_path)
    out = tmp_path / "out.dll"
    out.write_bytes(b"already here")
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, src, out, input_sha256=file_sha256(src))
    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_a_digest_that_changed_before_the_run_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "nrs"
    exe.write_text("", encoding="utf-8")
    src = _input(tmp_path)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, src, tmp_path / "out.dll", input_sha256="f" * 64)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


# ---------------------------------------------------------------------------
# Real-run honesty checks (POSIX fake CLI)
# ---------------------------------------------------------------------------


@_POSIX_ONLY
def test_a_clean_run_publishes_the_slayed_output(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, _HEAD + _WRITE_SLAYED)
    src = _input(tmp_path)
    out = tmp_path / "clean" / "out.dll"

    result = run_net_reactor_slayer(exe, src, out, input_sha256=file_sha256(src))

    assert isinstance(result, NetReactorSlayerResult)
    assert result.returncode == 0
    assert Path(result.output_path) == out.resolve()
    assert out.read_bytes() == b"SLAYED-OUTPUT"
    assert result.input_sha256 == file_sha256(src)
    payload = result.to_dict()
    assert payload["source"] == "net_reactor_slayer"
    assert payload["claims_universal_unpack"] is False
    assert payload["target"] == "authorized_reactor_samples_only"


@_POSIX_ONLY
def test_a_differently_named_slayed_file_is_accepted_by_glob(tmp_path: Path) -> None:
    # Some builds name the result differently; a single *_Slayed* file in the
    # work dir is still accepted.
    exe = _fake_cli(
        tmp_path,
        _HEAD
        + "alt = inp.with_name(inp.stem + '_Slayed_v2' + inp.suffix)\n"
        + "alt.write_bytes(b'ALT-SLAYED')\n",
    )
    src = _input(tmp_path)
    out = tmp_path / "glob" / "out.dll"

    result = run_net_reactor_slayer(exe, src, out, input_sha256=file_sha256(src))
    assert out.read_bytes() == b"ALT-SLAYED"
    assert result.output_sha256 == file_sha256(out)


@_POSIX_ONLY
def test_no_slayed_output_is_output_missing(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, _HEAD + "sys.exit(0)\n")
    src = _input(tmp_path)
    out = tmp_path / "missing" / "out.dll"
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, src, out, input_sha256=file_sha256(src))
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING
    assert not out.exists()


@_POSIX_ONLY
def test_an_ambiguous_pair_of_slayed_files_is_output_missing(tmp_path: Path) -> None:
    # More than one candidate is not a confident result; refuse rather than
    # publish an arbitrary one.
    exe = _fake_cli(
        tmp_path,
        _HEAD
        + "inp.with_name('a_Slayed.dll').write_bytes(b'1')\n"
        + "inp.with_name('b_Slayed.dll').write_bytes(b'2')\n",
    )
    src = _input(tmp_path)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            exe, src, tmp_path / "amb" / "out.dll", input_sha256=file_sha256(src)
        )
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


@_POSIX_ONLY
def test_a_stdout_flood_is_output_limit(tmp_path: Path) -> None:
    exe = _fake_cli(
        tmp_path,
        _HEAD + _WRITE_SLAYED + "sys.stdout.write('A' * 100000)\nsys.stdout.flush()\n",
    )
    src = _input(tmp_path)
    out = tmp_path / "flood" / "out.dll"
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, src, out, input_sha256=file_sha256(src), max_output_size=8)
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT
    assert not out.exists(), "no output is published when the tool floods"


@_POSIX_ONLY
def test_a_nonzero_exit_is_process_failed(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, _HEAD + "sys.stderr.write('boom')\nsys.exit(4)\n")
    src = _input(tmp_path)
    out = tmp_path / "fail" / "out.dll"
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, src, out, input_sha256=file_sha256(src))
    assert caught.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 4
    assert caught.value.retryable is True
    assert not out.exists()


@_POSIX_ONLY
def test_a_tool_that_mutates_the_original_is_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The post-run read of the original must catch a tool that reached back to it.

    The tool only ever sees the work copy, so a genuine mutation of the original
    cannot be produced through argv. Simulate one at the digest seam: the second
    read of the source returns a different hash, as if the original changed
    underneath the run.
    """
    exe = _fake_cli(tmp_path, _HEAD + _WRITE_SLAYED)
    src = _input(tmp_path)
    real_sha = session_mod.file_sha256
    source_reads = {"n": 0}

    def spy(path: Path, *args: object, **kwargs: object) -> str:
        if Path(path) == src.resolve():
            source_reads["n"] += 1
            if source_reads["n"] >= 2:
                return "0" * 64
        return real_sha(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_mod, "file_sha256", spy)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            exe, src, tmp_path / "mut" / "out.dll", input_sha256=file_sha256(src)
        )
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


# ---------------------------------------------------------------------------
# probe_net_reactor_slayer
# ---------------------------------------------------------------------------


def test_probe_reports_missing_when_the_executable_is_absent(tmp_path: Path) -> None:
    ok, text = probe_net_reactor_slayer(tmp_path / "nope", timeout=2.0)
    assert ok is False
    assert text == ""


@_POSIX_ONLY
def test_probe_reports_ready_on_a_named_banner(tmp_path: Path) -> None:
    exe = _fake_cli(tmp_path, "print('NETReactorSlayer 1.0 by SychicBoy')\n")
    ok, text = probe_net_reactor_slayer(exe, timeout=5.0)
    assert ok is True
    assert "netreactorslayer" in text.casefold()


@_POSIX_ONLY
def test_probe_accepts_usage_text_with_a_tolerated_exit(tmp_path: Path) -> None:
    # No product marker, but usage text plus a 0/1/-1 exit is treated as present.
    exe = _fake_cli(tmp_path, "import sys\nprint('Usage: tool <file>')\nsys.exit(1)\n")
    ok, _text = probe_net_reactor_slayer(exe, timeout=5.0)
    assert ok is True


@_POSIX_ONLY
def test_probe_returns_any_output_as_a_last_resort(tmp_path: Path) -> None:
    # Output with neither a marker nor usage still counts as "something ran".
    exe = _fake_cli(tmp_path, "import sys\nprint('unexpected chatter')\nsys.exit(2)\n")
    ok, text = probe_net_reactor_slayer(exe, timeout=5.0)
    assert ok is True
    assert "unexpected chatter" in text


@_POSIX_ONLY
def test_probe_refuses_a_non_executable_file(tmp_path: Path) -> None:
    exe = tmp_path / "nrs"
    exe.write_text("not runnable\n", encoding="utf-8")
    exe.chmod(0o644)
    ok, text = probe_net_reactor_slayer(exe, timeout=2.0)
    assert ok is False
    assert text == ""
