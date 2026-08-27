"""The de4dot ``_capture_process`` family must reject a bad deadline first.

de4dot, VMPDump, Scylla, XVLKC and NETReactorSlayer all share
``de4dot._capture_process``, whose poll loop derives ``deadline = monotonic() +
timeout``. A NaN or inf timeout makes ``remaining <= 0`` never true and the
loop fall to a fixed 0.05s sleep forever, so the deadline is silently disabled
and a wedged tool holds a worker until cancellation or the output cap -- the
same class of gap die/upx/exeinfope already guard at their own entry points.

Each ``run_*`` entry now validates the timeout as its first statement, so a
bad value is rejected with ``invalid_argument`` before any path resolution or
process spawn, while a valid value falls through to the executable check. These
tests pin both halves for every adapter in the family.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.dotnet.de4dot import De4dotError, run_de4dot
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    run_net_reactor_slayer,
)
from headless_re_mcp.unpack.scylla import ScyllaError, run_scylla
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError, run_vmp_dumper
from headless_re_mcp.unpack.xvlkc import XvlkcError, run_xvlkc

# (run function, its bounded error type). Every entry shares the positional
# (executable, input_path, output_path) shape plus keyword input_sha256/timeout.
_ADAPTERS: list[tuple[Callable[..., Any], type[Exception]]] = [
    (run_de4dot, De4dotError),
    (run_scylla, ScyllaError),
    (run_xvlkc, XvlkcError),
    (run_net_reactor_slayer, NetReactorSlayerError),
    (run_vmp_dumper, VmpDumperError),
]

# A NaN/inf value disables the deadline outright; 0/negative make the loop kill
# on the first iteration and report a misleading timeout; True is a bool that
# must never be read as the integer 1.
_BAD_TIMEOUTS = [float("nan"), math.inf, -math.inf, 0.0, -1.0, True]


def _invoke(
    run: Callable[..., Any], *, executable: Path, source: Path, out: Path, timeout: Any
) -> None:
    run(
        executable,
        source,
        out,
        input_sha256="0" * 64,
        timeout=timeout,
    )


@pytest.mark.parametrize("run,error", _ADAPTERS)
@pytest.mark.parametrize("timeout", _BAD_TIMEOUTS)
def test_bad_timeout_is_refused_before_touching_the_filesystem(
    run: Callable[..., Any],
    error: type[Exception],
    timeout: Any,
    tmp_path: Path,
) -> None:
    # A real input file exists, so reaching path resolution would not raise; the
    # only thing that can fail here is the timeout guard, and it must.
    source = tmp_path / "sample.bin"
    source.write_bytes(b"MZ" + b"\0" * 128)
    missing_exe = tmp_path / "does-not-exist-tool"
    out = tmp_path / "out.bin"
    with pytest.raises(error) as caught:
        _invoke(run, executable=missing_exe, source=source, out=out, timeout=timeout)
    assert caught.value.code == "invalid_argument"  # type: ignore[attr-defined]
    # Nothing was spawned and no output was published.
    assert not out.exists()


@pytest.mark.parametrize("run,error", _ADAPTERS)
def test_a_valid_timeout_still_reaches_the_executable_check(
    run: Callable[..., Any],
    error: type[Exception],
    tmp_path: Path,
) -> None:
    # Same missing executable, but a valid deadline: the guard is a tightening,
    # so the call proceeds past it and fails on the executable instead.
    source = tmp_path / "sample.bin"
    source.write_bytes(b"MZ" + b"\0" * 128)
    missing_exe = tmp_path / "does-not-exist-tool"
    out = tmp_path / "out.bin"
    with pytest.raises(error) as caught:
        _invoke(run, executable=missing_exe, source=source, out=out, timeout=30.0)
    assert caught.value.code == "executable_not_found"  # type: ignore[attr-defined]
