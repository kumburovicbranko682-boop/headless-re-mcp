"""External unpackers get their schema's 600s ceiling, not the 300s detect cap.

dotnet.deobfuscate / dotnet.reactor.unpack and unpack.xvlkc.unpack /
unpack.vmp.dump / unpack.scylla.rebuild all declare ``timeout <= 600`` in their
schema -- see tools.limits.ExternalToolTimeout, "external unpackers legitimately
outlast a debugger operation". Their service methods, however, routed the value
through ``_detection_timeout``, which rejects anything over 300 with a
ValueError the envelope reports as ``invalid_request``. A caller that read the
schema and asked for a legal 301..600 second deadline got a parameter error for
a value the schema promised. ``_external_tool_timeout`` keeps the service
ceiling equal to the tool schema; the UPX and detection tools stay at 300.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import (
    AnalysisService,
    _detection_timeout,
    _external_tool_timeout,
)
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.core import build_dotnet_tools
from headless_re_mcp.tools.unpack import build_unpack_tools
from headless_re_mcp.unpack.xvlkc import XvlkcResult

# NaN/inf disable a deadline outright; 0/negative kill on the first loop; True
# is a bool that must never read as the integer 1.
_BAD = [float("nan"), math.inf, -math.inf, 0.0, -1.0, True]


def test_detection_ceiling_is_unchanged() -> None:
    assert _detection_timeout(300.0) == 300.0
    with pytest.raises(ValueError):
        _detection_timeout(300.1)
    for bad in _BAD:
        with pytest.raises(ValueError):
            _detection_timeout(bad)


def test_external_tool_ceiling_accepts_up_to_600() -> None:
    # The regression these fix: 301..600 was rejected by the 300s detect cap.
    assert _external_tool_timeout(300.1) == 300.1
    assert _external_tool_timeout(450.0) == 450.0
    assert _external_tool_timeout(600.0) == 600.0
    with pytest.raises(ValueError):
        _external_tool_timeout(600.1)
    for bad in _BAD:
        with pytest.raises(ValueError):
            _external_tool_timeout(bad)


def _timeout_max(builder: Callable[[Any], Any], name: str) -> float:
    handler = next(b.handler for b in builder(object()) if b.name == name)
    maximum = input_schema_for(handler)["properties"]["timeout"]["maximum"]
    return float(maximum)


@pytest.mark.parametrize("name", ["dotnet.deobfuscate", "dotnet.reactor.unpack"])
def test_dotnet_schema_ceiling_matches_the_service(name: str) -> None:
    ceiling = _timeout_max(build_dotnet_tools, name)
    assert ceiling == 600.0
    # The service must accept the largest value the schema advertises.
    assert _external_tool_timeout(ceiling) == ceiling


@pytest.mark.parametrize(
    "name", ["unpack.xvlkc.unpack", "unpack.vmp.dump", "unpack.scylla.rebuild"]
)
def test_unpack_external_schema_ceiling_matches_the_service(name: str) -> None:
    ceiling = _timeout_max(build_unpack_tools, name)
    assert ceiling == 600.0
    assert _external_tool_timeout(ceiling) == ceiling


@pytest.mark.parametrize("name", ["unpack.upx.test", "unpack.upx.unpack"])
def test_upx_stays_on_the_detection_ceiling(name: str) -> None:
    # UPX is quick and declares le=300; it must keep the detection ceiling.
    ceiling = _timeout_max(build_unpack_tools, name)
    assert ceiling == 300.0
    assert _detection_timeout(ceiling) == ceiling


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _xvlkc_service(tmp_path: Path, runner: Callable[..., Any]) -> AnalysisService:
    exe = tmp_path / "xvlkc.exe"
    exe.write_bytes(b"fake")
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            xvlkc=exe,
        ),
        xvlkc_runner=runner,
    )


def test_xvlkc_service_accepts_a_timeout_above_the_detection_cap(tmp_path: Path) -> None:
    """A 450s deadline (legal per the le=600 schema) must reach the runner."""
    seen: dict[str, float] = {}

    def runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
    ) -> XvlkcResult:
        del executable, max_file_size, max_output_size
        seen["timeout"] = timeout
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(input_path.read_bytes())
        return XvlkcResult(
            executable="xvlkc",
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="ok",
            stderr="",
            duration_ms=1,
        )

    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _xvlkc_service(tmp_path, runner)
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        service.unpack_xvlkc_unpack(session_id, timeout=450.0)
        # The only way the runner ran is that _external_tool_timeout accepted
        # 450; the 300s cap would have raised before this point.
        assert seen.get("timeout") == 450.0
    finally:
        service.close_all()


def test_xvlkc_service_still_rejects_a_timeout_above_the_schema_ceiling(
    tmp_path: Path,
) -> None:
    """701s is past the le=600 schema: rejected as invalid_request, no run."""

    def runner(*args: Any, **kwargs: Any) -> XvlkcResult:
        raise AssertionError("runner must not be reached for an illegal timeout")

    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _xvlkc_service(tmp_path, runner)
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        result = service.unpack_xvlkc_unpack(session_id, timeout=701.0)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()
