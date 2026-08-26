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


def test_result_envelope_requires_an_error_when_it_failed() -> None:
    """A failed result with no error reads as success to every caller."""
    with pytest.raises(ValidationError):
        Result[dict](ok=False, data=None, error=None)


def test_rpc_error_message_is_clipped_so_hostile_input_cannot_bloat_it() -> None:
    """A huge caller-controlled string used to sit in message and details twice.

    The model clips the message, so a 200k-char session id echoed into an error
    can no longer produce a ~400 KB envelope.
    """
    huge = "A" * 5000
    error = RpcError(code="bad", message=huge)

    assert len(error.message) < len(huge)
    assert error.message.startswith("A" * 2048)
    assert error.message.endswith("...(5000 chars)")


def test_a_message_at_the_limit_is_left_untouched() -> None:
    exact = "B" * 2048
    assert RpcError(code="bad", message=exact).message == exact


def test_rpc_error_clips_string_details_but_leaves_other_types_alone() -> None:
    error = RpcError(
        code="bad",
        message="short",
        details={"blob": "C" * 4000, "count": 7, "nested": {"keep": "me"}},
    )

    blob = error.details["blob"]
    assert isinstance(blob, str)
    assert len(blob) < 4000
    assert blob.endswith("...(4000 chars)")
    # Non-string details are structural, not caller text, so they pass through.
    assert error.details["count"] == 7
    assert error.details["nested"] == {"keep": "me"}


def test_path_round_trip_in_session_models() -> None:
    assert Path("fixture.exe").name == "fixture.exe"
