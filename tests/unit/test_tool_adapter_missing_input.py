"""Regression: tool adapters must report a missing input as a structured error.

Each ``run_*`` adapter resolved the input with ``Path.resolve(strict=True)``,
so a nonexistent input path raised a raw ``FileNotFoundError`` before the
adapter's own ``INPUT_NOT_FOUND`` check could run -- callers saw an unsanitized
exception instead of the adapter's error contract. A directory input (which
exists) reached the structured error, so this gap was invisible until a truly
missing path was tried. These assert the structured code for a missing path.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.de4dot import De4dotError, De4dotErrorCode, run_de4dot
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    run_net_reactor_slayer,
)
from headless_re_mcp.unpack.scylla import ScyllaError, ScyllaErrorCode, run_scylla
from headless_re_mcp.unpack.vmp_dumper import (
    VmpDumperError,
    VmpDumperErrorCode,
    run_vmp_dumper,
)


def _tool(tmp_path: Path) -> Path:
    exe = tmp_path / "tool"
    exe.write_bytes(b"fake")
    os.chmod(exe, 0o755)
    return exe


def test_scylla_reports_missing_input_as_structured(tmp_path: Path) -> None:
    with pytest.raises(ScyllaError) as caught:
        run_scylla(
            _tool(tmp_path),
            tmp_path / "missing.exe",
            tmp_path / "out.exe",
            input_sha256="0" * 64,
        )
    assert caught.value.code == ScyllaErrorCode.INPUT_NOT_FOUND


def test_de4dot_reports_missing_input_as_structured(tmp_path: Path) -> None:
    with pytest.raises(De4dotError) as caught:
        run_de4dot(
            _tool(tmp_path),
            tmp_path / "missing.dll",
            tmp_path / "out.dll",
            input_sha256="0" * 64,
        )
    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_net_reactor_slayer_reports_missing_input_as_structured(tmp_path: Path) -> None:
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            _tool(tmp_path),
            tmp_path / "missing.dll",
            tmp_path / "out.dll",
            input_sha256="0" * 64,
        )
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_vmp_dumper_reports_missing_input_as_structured(tmp_path: Path) -> None:
    # A live pid is provided so the missing-input check (which precedes the
    # debuggee-required check) is the one that fires.
    with pytest.raises(VmpDumperError) as caught:
        run_vmp_dumper(
            _tool(tmp_path),
            tmp_path / "missing.exe",
            tmp_path / "out.exe",
            input_sha256="0" * 64,
            pid=4321,
        )
    assert caught.value.code == VmpDumperErrorCode.INPUT_NOT_FOUND
