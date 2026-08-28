"""Input bounds for FridaClient.memory_read's address and size.

The frida.memory.read tool schema types address/size as integers, but the agent
and OpenAI-bridge transports call the handler straight from model arguments with
no pydantic coercion. size was already validated; address was not, so a float
(inf from a JSON 1e400), null, or non-hex string reached ``int(address)`` inside
the read and raised OverflowError/TypeError/ValueError -- none of them a
FridaError, so frida_memory_read's ``except BaseException`` filed an
internal_error incident for a bad pointer. Both bounds run before _attach_local,
so the frida native runtime (which cannot run in CI) is never reached.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client() -> FridaClient:
    # _available/_frida make _require pass; the address/size guards fire before
    # _attach_local, so a non-callable frida stand-in is enough.
    client = FridaClient()
    client._available = True
    client._frida = object()
    return client


@pytest.mark.parametrize(
    "bad",
    [float("inf"), float("nan"), None, "0x1000", {}, [], True, -1, 1 << 64],
    ids=["inf", "nan", "none", "hex-string", "dict", "list", "bool", "negative", "over-64-bit"],
)
def test_memory_read_rejects_a_bad_address_before_attaching(bad: Any) -> None:
    with pytest.raises(FridaError) as caught:
        _client().memory_read(1, bad, 16, allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "address" in caught.value.message


@pytest.mark.parametrize(
    "bad",
    [0, -1, 256 * 1024 + 1, float("inf"), None, "16", True],
    ids=["zero", "negative", "over-max", "inf", "none", "string", "bool"],
)
def test_memory_read_still_rejects_a_bad_size(bad: Any) -> None:
    with pytest.raises(FridaError) as caught:
        _client().memory_read(1, 0x401000, bad, allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "size" in caught.value.message


def test_memory_read_accepts_a_valid_address_and_size_past_the_guards() -> None:
    # A valid pointer/size clears both guards and reaches _attach_local; the
    # stand-in frida has no attach, so the failure is a backend_error rather than
    # the invalid_params a rejected argument would give.
    with pytest.raises(FridaError) as caught:
        _client().memory_read(1, 0x401000, 16, allowed_pid=1)
    assert caught.value.code != "invalid_params"


def test_memory_read_enforces_the_pid_allow_list_first() -> None:
    # The permission boundary precedes the argument bounds: a disallowed pid is
    # refused even with an otherwise-hostile address.
    with pytest.raises(FridaError) as caught:
        _client().memory_read(1, float("inf"), 16, allowed_pid=2)  # type: ignore[arg-type]
    assert caught.value.code == "permission_denied"
