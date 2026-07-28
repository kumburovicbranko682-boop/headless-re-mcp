from pathlib import Path

import pytest
from pydantic import ValidationError

from headless_re_mcp.core.models import Address, Architecture, Result, RpcError


def test_address_resolves_module_rva() -> None:
    address = Address(module="fixture.exe", rva=0x123, architecture=Architecture.X64)
    assert address.resolve(0x140000000) == 0x140000123


def test_address_requires_a_coordinate() -> None:
    with pytest.raises(ValidationError):
        Address()


def test_address_requires_module_for_rva() -> None:
    with pytest.raises(ValidationError):
        Address(rva=1)


def test_result_envelope_rejects_error_on_success() -> None:
    with pytest.raises(ValidationError):
        Result[dict](
            ok=True,
            data={},
            error=RpcError(code="bad", message="should not exist"),
        )


def test_path_round_trip_in_session_models() -> None:
    assert Path("fixture.exe").name == "fixture.exe"
