"""A non-PE timeout must reach the caller as retryable, like every other timeout.

``_failure`` marks the generic ``TimedOut``, the stdlib ``TimeoutError`` and a
DIE/Exeinfo scan timeout as ``retryable=True`` -- the whole codebase agrees a
timeout is a transient bound worth retrying, and unattended callers branch on
that flag (see ``test_result_failure_mapping``). The non-PE backends were the
exception: their error classes carry no ``retryable`` field, and each service
mixin's ``_as_rpc`` built an ``XdbgRpcError`` with the constructor default
``retryable=False``. So a slow ``web``/``frida``/``device``/``proxy`` call
raised ``timeout`` and surfaced as a *permanent* failure -- an agent that skips
deterministic errors would refuse to retry a call that would likely have
succeeded on a second try.

These pin the fix at both layers: the shared ``backend_error_as_rpc`` derives
the flag from the code, and every one of the six converters routes through it
so no single site can quietly revert to the flag-dropping constructor call.
"""

from __future__ import annotations

from headless_re_mcp.core import (
    service_apk,
    service_device,
    service_frida,
    service_jsre,
    service_proxy,
    service_web,
)
from headless_re_mcp.core.results import (
    _RETRYABLE_BACKEND_CODES,
    _failure,
    backend_error_as_rpc,
)

# The canonical non-PE vocabulary (pinned exactly by test_non_pe_error_taxonomy).
# Duplicated here as data, not imported from that test, so the two guards fail
# independently: this one asserts which of these codes are retryable.
_CANONICAL_NON_PE_CODES = frozenset(
    {
        "backend_error",
        "capability_unavailable",
        "invalid_params",
        "invalid_state",
        "not_found",
        "permission_denied",
        "timeout",
        "too_large",
    }
)

# The six converters that carry a non-PE backend error into the envelope. Keyed
# by backend so a failure names the site that regressed.
_CONVERTERS = {
    "web": service_web._as_rpc,
    "proxy": service_proxy._as_rpc,
    "jsre": service_jsre._as_rpc,
    "frida": service_frida._as_rpc,
    "device": service_device._as_rpc,
    "apk": service_apk._as_rpc,
}


class _FakeBackendError(RuntimeError):
    """Stand-in with the code/message/details shape every non-PE error class
    exposes, so the converters can be exercised without each backend's ctor."""

    def __init__(self, code: str) -> None:
        super().__init__(f"{code} happened")
        self.code = code
        self.message = f"{code} happened"
        self.details = {"where": "unit"}


def test_the_retryable_backend_codes_are_exactly_the_timeout_family() -> None:
    """Guard the rule itself: only ``timeout`` is retryable among non-PE codes.

    A refactor that widened this set (say, making ``backend_error`` retryable)
    would have an unattended caller spin on a deterministic fault; one that
    emptied it would silently undo the whole fix. Both are caught here, and the
    set stays a subset of the canonical vocabulary so a typo cannot sneak in.
    """
    assert sorted(_RETRYABLE_BACKEND_CODES) == ["timeout"]
    assert _RETRYABLE_BACKEND_CODES <= _CANONICAL_NON_PE_CODES


def test_helper_marks_only_timeout_retryable_across_the_vocabulary() -> None:
    """``backend_error_as_rpc`` maps timeout -> retryable and every other
    canonical code -> not, preserving code/message/details untouched."""
    for code in sorted(_CANONICAL_NON_PE_CODES):
        rpc = backend_error_as_rpc(_FakeBackendError(code))
        assert rpc.code == code
        assert rpc.retryable is (code == "timeout"), code
        assert rpc.details == {"where": "unit"}


def test_every_converter_makes_a_backend_timeout_retryable_end_to_end() -> None:
    """Each of the six ``_as_rpc`` sites, run through ``_failure``, yields a
    retryable timeout envelope -- the load-bearing path the caller actually sees.

    A converter reverted to the bare ``XdbgRpcError(exc.code, exc.message,
    details=...)`` drops the flag back to False and trips exactly the backend
    that regressed, because the site is named in the assertion.
    """
    for backend, convert in _CONVERTERS.items():
        result = _failure(convert(_FakeBackendError("timeout")))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "timeout", backend
        assert result.error.retryable is True, backend


def test_every_converter_keeps_a_deterministic_code_non_retryable() -> None:
    """The mirror image: a deterministic failure (bad params) stays
    retryable=False through every converter, so widening the rule at one site is
    caught too."""
    for backend, convert in _CONVERTERS.items():
        result = _failure(convert(_FakeBackendError("invalid_params")))
        assert result.error is not None
        assert result.error.code == "invalid_params", backend
        assert result.error.retryable is False, backend
