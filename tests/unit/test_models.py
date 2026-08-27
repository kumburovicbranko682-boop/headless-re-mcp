from pathlib import Path

import pytest
from pydantic import ValidationError

from headless_re_mcp.core.models import (
    Address,
    Architecture,
    ModuleSelector,
    Result,
    RpcError,
)


def test_address_resolves_module_rva() -> None:
    address = Address(module="fixture.exe", rva=0x123, architecture=Architecture.X64)
    assert address.resolve(0x140000000) == 0x140000123


def test_address_resolve_returns_a_va_directly() -> None:
    # A VA is already absolute, so resolve never needs a module base.
    assert Address(va=0x401000).resolve() == 0x401000
    assert Address(va=0x401000).resolve(module_base=0xDEAD) == 0x401000


def test_address_resolve_needs_a_base_for_an_rva() -> None:
    address = Address(module="fixture.exe", rva=0x1000)
    with pytest.raises(ValueError, match="module_base is required"):
        address.resolve()


def test_address_requires_a_coordinate() -> None:
    with pytest.raises(ValidationError):
        Address()


def test_address_requires_module_for_rva() -> None:
    with pytest.raises(ValidationError):
        Address(rva=1)


def test_module_selector_requires_at_least_one_locator() -> None:
    with pytest.raises(ValidationError, match="requires base, path, or name"):
        ModuleSelector()


def test_module_selector_leaves_an_absent_text_field_as_none() -> None:
    # base identifies the module; an explicitly-null path passes through the
    # nonblank validator as None rather than tripping the blank check.
    selector = ModuleSelector(base=0x400000, path=None)
    assert selector.base == 0x400000
    assert selector.path is None


def test_module_selector_refuses_blank_text() -> None:
    with pytest.raises(ValidationError, match="must not be blank"):
        ModuleSelector(name="   ")


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
