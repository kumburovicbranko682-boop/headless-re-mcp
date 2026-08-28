"""A .NET deobfuscate/unpack timeout must stay retryable through the service.

de4dot and NETReactorSlayer mark a timeout (and a process failure) ``retryable``
in their own error classes, exactly like every other bounded backend. The
service converted those errors into ``RpcError`` without passing the flag along,
so ``RpcError``'s ``retryable=False`` default made a .NET tool timeout reach the
caller -- and the workflow failure record, which reads ``exc.retryable`` -- as
non-retryable, discarding the backend's own classification. These pin that the
flag now survives the conversion, and that a deterministic failure stays false.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.de4dot import De4dotError, De4dotErrorCode
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
)
from tests.unit.test_dotnet_de4dot import _write_verified_clr_pe


def _settings(tmp_path: Path, **tools: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        **tools,
    )


def test_a_de4dot_timeout_stays_retryable_through_the_service(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")

    def timing_out(*_args: Any, **_kwargs: Any) -> Any:
        raise De4dotError(
            De4dotErrorCode.TIMEOUT, "de4dot timed out after 120s", retryable=True
        )

    service = AnalysisService(_settings(tmp_path, de4dot=de4dot), de4dot_runner=timing_out)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.dotnet_deobfuscate(session_id)
    finally:
        service.close_all()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


def test_a_deterministic_de4dot_failure_stays_non_retryable(tmp_path: Path) -> None:
    # A process failure is deterministic: the backend leaves retryable False, and
    # the conversion must not invent retryability out of RpcError's default.
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")

    def failing(*_args: Any, **_kwargs: Any) -> Any:
        raise De4dotError(De4dotErrorCode.PROCESS_FAILED, "de4dot exited 1")

    service = AnalysisService(_settings(tmp_path, de4dot=de4dot), de4dot_runner=failing)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.dotnet_deobfuscate(session_id)
    finally:
        service.close_all()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "process_failed"
    assert result.error.retryable is False


def test_a_net_reactor_slayer_timeout_stays_retryable_through_the_service(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    nrs = tmp_path / "NETReactorSlayer.CLI.exe"
    nrs.write_bytes(b"placeholder")

    def timing_out(*_args: Any, **_kwargs: Any) -> Any:
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.TIMEOUT,
            "NETReactorSlayer timed out after 120s",
            retryable=True,
        )

    service = AnalysisService(
        _settings(tmp_path, net_reactor_slayer=nrs),
        net_reactor_slayer_runner=timing_out,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.dotnet_reactor_unpack(session_id)
    finally:
        service.close_all()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True
