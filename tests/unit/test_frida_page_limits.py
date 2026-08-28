"""Page-limit bounds for frida modules/exports/applications.

Each took ``max(1, min(int(limit), max))``. A negative or huge limit clamps
cleanly, but the tool schemas type limit as an integer while the agent and
OpenAI-bridge transports call the handler with no pydantic coercion, so a float
(inf from a JSON 1e400), nan, null, or non-numeric string reached ``int(limit)``
and raised OverflowError/ValueError/TypeError -- none a FridaError, so the
service filed an internal_error incident for a bad page size. The clamp now runs
before the attach/device side effects, so these all exercise on Linux without
the frida native runtime.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client() -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    return client


_BAD_LIMITS = [float("inf"), float("nan"), None, "abc", {}, [], True]
_BAD_IDS = ["inf", "nan", "none", "non-numeric", "dict", "list", "bool"]


@pytest.mark.parametrize("bad", _BAD_LIMITS, ids=_BAD_IDS)
def test_modules_rejects_a_bad_limit_before_attaching(bad: Any) -> None:
    with pytest.raises(FridaError) as caught:
        _client().modules(1, allowed_pid=1, limit=bad)
    assert caught.value.code == "invalid_params"
    assert "limit" in caught.value.message


@pytest.mark.parametrize("bad", _BAD_LIMITS, ids=_BAD_IDS)
def test_exports_rejects_a_bad_limit_before_attaching(bad: Any) -> None:
    with pytest.raises(FridaError) as caught:
        _client().exports(1, "libc.so", allowed_pid=1, limit=bad)
    assert caught.value.code == "invalid_params"
    assert "limit" in caught.value.message


@pytest.mark.parametrize("bad", _BAD_LIMITS, ids=_BAD_IDS)
def test_applications_rejects_a_bad_limit_before_resolving_a_device(bad: Any) -> None:
    with pytest.raises(FridaError) as caught:
        _client().applications(None, limit=bad)
    assert caught.value.code == "invalid_params"
    assert "limit" in caught.value.message


@pytest.mark.parametrize(
    "good", [64, "64", 2.9, -5, 10**9], ids=["int", "str", "float", "neg", "huge"]
)
def test_modules_clamps_a_valid_or_clampable_limit_and_proceeds(good: Any) -> None:
    # A clampable limit clears the guard and reaches _attach_local; the stand-in
    # frida has no attach, so the failure is backend_error, never invalid_params.
    with pytest.raises(FridaError) as caught:
        _client().modules(1, allowed_pid=1, limit=good)
    assert caught.value.code != "invalid_params"


def test_exports_still_requires_a_module_name_before_the_limit() -> None:
    # module_name is checked ahead of the limit clamp; a blank name is refused
    # even though the limit is fine.
    with pytest.raises(FridaError) as caught:
        _client().exports(1, "   ", allowed_pid=1, limit=64)
    assert caught.value.code == "invalid_params"
    assert "module_name" in caught.value.message
