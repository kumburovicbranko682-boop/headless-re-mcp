"""Tool adapters must refuse non-positive numeric bounds up front.

A non-positive timeout otherwise yields an immediate false 'timeout', and a
non-positive output bound trips the output limit on the first byte. Each adapter
now validates its caller-supplied bounds before touching the filesystem or
spawning anything, mirroring the UPX / XVLKC hardening.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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

_FILE_ADAPTERS = [
    pytest.param(run_scylla, ScyllaError, ScyllaErrorCode, {}, id="scylla"),
    pytest.param(run_de4dot, De4dotError, De4dotErrorCode, {}, id="de4dot"),
    pytest.param(
        run_net_reactor_slayer,
        NetReactorSlayerError,
        NetReactorSlayerErrorCode,
        {},
        id="net_reactor_slayer",
    ),
]


@pytest.mark.parametrize("runfn, error, codes, extra", _FILE_ADAPTERS)
@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": -1.0}, "timeout"),
        ({"max_file_size": 0}, "max_file_size"),
        ({"max_output_size": -5}, "max_output_size"),
    ],
)
def test_file_adapters_reject_non_positive_bounds(
    tmp_path: Path,
    runfn: Any,
    error: type[Exception],
    codes: Any,
    extra: dict[str, Any],
    kwargs: dict[str, Any],
    needle: str,
) -> None:
    with pytest.raises(error) as caught:
        runfn(
            tmp_path / "tool",
            tmp_path / "in",
            tmp_path / "out",
            input_sha256="0" * 64,
            **extra,
            **kwargs,
        )
    assert caught.value.code == codes.INVALID_ARGUMENT
    assert needle in str(caught.value)


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": -2.0}, "timeout"),
        ({"max_output_size": 0}, "max_output_size"),
        ({"max_output_size": -1}, "max_output_size"),
    ],
)
def test_vmp_dumper_rejects_non_positive_bounds(
    tmp_path: Path, kwargs: dict[str, Any], needle: str
) -> None:
    with pytest.raises(VmpDumperError) as caught:
        run_vmp_dumper(
            tmp_path / "tool",
            tmp_path / "in",
            tmp_path / "out",
            input_sha256="0" * 64,
            pid=4321,
            **kwargs,
        )
    assert caught.value.code == VmpDumperErrorCode.INVALID_ARGUMENT
    assert needle in str(caught.value)
