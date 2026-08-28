"""Regression tests: a missing input path must raise the adapter's structured
INPUT_NOT_FOUND error rather than leaking a raw FileNotFoundError.

Each adapter resolves the input path and then checks ``is_file()`` to raise a
named INPUT_NOT_FOUND error. Using ``Path.resolve(strict=True)`` made that check
dead code for a genuinely missing file: resolve() faulted first with a raw
FileNotFoundError. These tests pin the structured behaviour.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.de4dot import De4dotError, run_de4dot
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    run_net_reactor_slayer,
)
from headless_re_mcp.unpack.scylla import ScyllaError, run_scylla
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError, run_vmp_dumper
from headless_re_mcp.unpack.xvlkc import XvlkcError, run_xvlkc

_ADAPTERS: list[tuple[str, Callable[..., object], type[Exception]]] = [
    ("xvlkc", run_xvlkc, XvlkcError),
    ("scylla", run_scylla, ScyllaError),
    ("vmp_dumper", run_vmp_dumper, VmpDumperError),
    ("de4dot", run_de4dot, De4dotError),
    ("net_reactor_slayer", run_net_reactor_slayer, NetReactorSlayerError),
]


@pytest.mark.parametrize(
    ("name", "run_fn", "error_cls"),
    _ADAPTERS,
    ids=[name for name, _, _ in _ADAPTERS],
)
def test_missing_input_raises_input_not_found(
    name: str,
    run_fn: Callable[..., object],
    error_cls: type[Exception],
    tmp_path: Path,
) -> None:
    # A real executable file so we get past the EXECUTABLE_NOT_FOUND gate and
    # reach the input check; the input path deliberately does not exist.
    executable = tmp_path / "tool.exe"
    executable.write_bytes(b"MZ")
    missing_input = tmp_path / "does-not-exist.bin"
    output = tmp_path / "out.bin"

    with pytest.raises(error_cls) as excinfo:
        run_fn(
            executable,
            missing_input,
            output,
            input_sha256="0" * 64,
        )
    assert excinfo.value.code == "input_not_found"  # type: ignore[attr-defined]
