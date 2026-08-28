"""Edge-path coverage for core/service_dotnet.py.

Targets the validation guards and error-mapping arms of the .NET service
mixin: unconfigured CLIs, inputs mutated after session creation, adapter
errors, and CLR inspection failures surfaced through every wrapper.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_dotnet_de4dot import _write_verified_clr_pe
from test_dotnet_il_truncation_honesty import _write_clr_with_one_method
from test_service_helpers_paths import _write_pe

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_dotnet
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError


def _service(
    tmp_path: Path,
    *,
    de4dot: Path | None = None,
    net_reactor_slayer: Path | None = None,
    de4dot_runner: Any = None,
    net_reactor_slayer_runner: Any = None,
) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=de4dot,
            net_reactor_slayer=net_reactor_slayer,
        ),
        de4dot_runner=de4dot_runner,
        net_reactor_slayer_runner=net_reactor_slayer_runner,
    )


def _session(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _mutate(path: Path) -> None:
    """Flip a padding byte so the hash changes but the CLR image still verifies."""
    image = bytearray(path.read_bytes())
    image[-1] ^= 0xFF
    path.write_bytes(image)


# --- dotnet_inspect ---


def test_inspect_rejects_a_non_boolean_require_verified(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    flag: Any = "yes"
    result = service.dotnet_inspect(session_id, require_verified=flag)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_inspect_surfaces_a_clr_error_for_a_native_pe(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    result = service.dotnet_inspect(session_id, require_verified=True)

    assert not result.ok and result.error is not None
    assert result.error.code != "internal_error"


# --- dotnet_deobfuscate ---


def test_deobfuscate_requires_a_configured_de4dot(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    result = service.dotnet_deobfuscate(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_deobfuscate_refuses_an_input_mutated_after_creation(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")
    service = _service(tmp_path, de4dot=de4dot)
    session_id = _session(service, binary)
    _mutate(binary)

    result = service.dotnet_deobfuscate(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "input_changed"
    assert result.error.details["session_id"] == session_id


def test_deobfuscate_maps_a_de4dot_error(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")

    def broken_runner(*args: Any, **kwargs: Any) -> Any:
        raise De4dotError("process_failed", "de4dot fell over", details={"exit": 3})

    service = _service(tmp_path, de4dot=de4dot, de4dot_runner=broken_runner)
    session_id = _session(service, binary)

    result = service.dotnet_deobfuscate(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "process_failed"
    assert result.error.details == {"exit": 3}


# --- dotnet_reactor_unpack ---


def test_reactor_unpack_requires_a_configured_cli(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    result = service.dotnet_reactor_unpack(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_reactor_unpack_refuses_an_input_mutated_after_creation(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    slayer = tmp_path / "nrs.exe"
    slayer.write_bytes(b"placeholder")
    service = _service(tmp_path, net_reactor_slayer=slayer)
    session_id = _session(service, binary)
    _mutate(binary)

    result = service.dotnet_reactor_unpack(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "input_changed"


def test_reactor_unpack_maps_a_slayer_error(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    slayer = tmp_path / "nrs.exe"
    slayer.write_bytes(b"placeholder")

    def broken_runner(*args: Any, **kwargs: Any) -> Any:
        raise NetReactorSlayerError("timeout", "slayer hung", details={"seconds": 5})

    service = _service(
        tmp_path, net_reactor_slayer=slayer, net_reactor_slayer_runner=broken_runner
    )
    session_id = _session(service, binary)

    result = service.dotnet_reactor_unpack(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "timeout"
    assert result.error.details == {"seconds": 5}


# --- metadata wrappers ---


def test_enumerate_surfaces_a_clr_error_for_a_native_pe(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    result = service.dotnet_enumerate(session_id, "types")

    assert not result.ok and result.error is not None


def test_il_disassembles_a_method_and_surfaces_clr_errors(tmp_path: Path) -> None:
    managed = tmp_path / "one-method.exe"
    il = b"\x00" * 7 + b"\x2a"
    _write_clr_with_one_method(managed, code_size=len(il), il=il)
    service = _service(tmp_path)
    session_id = _session(service, managed)

    disassembled = service.dotnet_il(session_id, 0x06000001)

    assert disassembled.ok and disassembled.data is not None, disassembled.error
    assert disassembled.data["instructions"][-1]["mnemonic"] == "ret"

    plain = tmp_path / "plain.exe"
    _write_pe(plain)
    plain_id = _session(service, plain)

    failed = service.dotnet_il(plain_id, 0x06000001)

    assert not failed.ok and failed.error is not None


def test_xrefs_surfaces_a_clr_error_for_a_native_pe(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    result = service.dotnet_xrefs(session_id)

    assert not result.ok and result.error is not None


def test_metadata_wrappers_wrap_an_unexpected_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("metadata reader fell over")

    monkeypatch.setattr(service_dotnet, "enumerate_metadata", explode)
    monkeypatch.setattr(service_dotnet, "disassemble_method_il", explode)
    monkeypatch.setattr(service_dotnet, "list_memberref_xrefs", explode)

    for result in (
        service.dotnet_enumerate(session_id, "types"),
        service.dotnet_il(session_id, 0x06000001),
        service.dotnet_xrefs(session_id),
    ):
        assert not result.ok and result.error is not None
        assert "fell over" in result.error.message


# --- dotnet_verify ---


def test_verify_surfaces_a_clr_error_for_a_junk_artifact(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)
    junk_dir = service.settings.artifact_root.expanduser().resolve() / "dotnet" / session_id
    junk_dir.mkdir(parents=True, exist_ok=True)
    junk = junk_dir / "junk.exe"
    junk.write_bytes(b"this is not a portable executable")

    result = service.dotnet_verify(session_id, str(junk))

    assert not result.ok and result.error is not None


def test_verify_maps_a_clr_inspection_refusal(tmp_path: Path) -> None:
    """A well-formed native PE fails verification with a typed CLR error."""
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    session_id = _session(service, binary)
    native_dir = (
        service.settings.artifact_root.expanduser().resolve() / "dotnet" / session_id
    )
    native_dir.mkdir(parents=True, exist_ok=True)
    native = native_dir / "native.exe"
    _write_pe(native)

    result = service.dotnet_verify(session_id, str(native))

    assert not result.ok and result.error is not None
    assert result.error.code != "internal_error"
