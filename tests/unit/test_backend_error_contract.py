"""The shared error contract every non-PE backend depends on.

Each non-PE backend (Android: adb/apk/jadx/apktool/frida; Web: web/proxy/jsre;
radare2/Ghidra) raises its own typed error carrying a ``code``, a ``message``
and a ``details`` mapping. The service layer funnels each one through the same
two-step mapping -- ``_as_rpc`` wraps it into an ``XdbgRpcError``, then
``_failure`` renders that into the canonical ``Result`` envelope -- so a caller
on any track reads the same ``ok/error.code/error.message/error.details`` shape.

Nothing pinned that end to end. A refactor that renamed a backend error field,
changed one ``_as_rpc`` helper to drop ``details``, or reshaped the ``_failure``
branch would silently degrade one track's error reporting into an opaque
``internal_error`` with a logged incident. These tests pin the contract for
every backend at once, the same way the ``_dump`` envelope guard is pinned
across every tool module.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbError
from headless_re_mcp.backends.apk.client import ApkError
from headless_re_mcp.backends.apktool.client import ApktoolError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.jadx.client import JadxError
from headless_re_mcp.backends.jsre.client import JsReError
from headless_re_mcp.backends.proxy.client import ProxyError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.backends.web.client import WebError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.results import _failure

# Every non-PE backend's typed error class. The list is the contract: a new
# backend that grows its own error type belongs here so its mapping is pinned.
_BACKEND_ERRORS = [
    AdbError,
    ApkError,
    ApktoolError,
    FridaError,
    GhidraError,
    JadxError,
    JsReError,
    ProxyError,
    R2Error,
    WebError,
]


@pytest.mark.parametrize("error_cls", _BACKEND_ERRORS, ids=lambda c: c.__name__)
def test_every_backend_error_shares_the_code_message_details_shape(
    error_cls: type[Exception],
) -> None:
    exc = error_cls("some_code", "human message", path="/x", n=7)
    assert exc.code == "some_code"
    assert exc.message == "human message"
    assert exc.details == {"path": "/x", "n": 7}
    # The message is also the exception's str() so a bare log line is not empty.
    assert str(exc) == "human message"


@pytest.mark.parametrize("error_cls", _BACKEND_ERRORS, ids=lambda c: c.__name__)
def test_a_backend_error_without_details_carries_an_empty_mapping(
    error_cls: type[Exception],
) -> None:
    exc = error_cls("empty", "no details here")
    assert exc.details == {}


def _canonical_wrap(exc: Any) -> XdbgRpcError:
    """The exact mapping every service ``_as_rpc`` performs."""
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


@pytest.mark.parametrize("error_cls", _BACKEND_ERRORS, ids=lambda c: c.__name__)
def test_the_failure_envelope_carries_code_message_and_details(
    error_cls: type[Exception],
) -> None:
    exc = error_cls("invalid_params", "bad input", field="serial")
    result = _failure(_canonical_wrap(exc), session_id="sess-1")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert result.error.message == "bad input"
    # The backend's own details survive alongside the caller-supplied context.
    assert result.error.details["field"] == "serial"
    assert result.error.details["session_id"] == "sess-1"


def test_backend_details_win_over_caller_context_on_a_key_clash() -> None:
    """``_failure`` merges ``{**caller, **exc.details}`` -- the backend is truth.

    If a backend reports ``session_id`` in its own details (a frida spawn naming
    the pid's session, say), that value must not be shadowed by the route's
    generic session_id, or the envelope would point the caller at the wrong
    session.
    """
    exc = WebError("backend_error", "navigation failed", session_id="real-session")
    result = _failure(_canonical_wrap(exc), session_id="route-session")
    assert result.error is not None
    assert result.error.details["session_id"] == "real-session"


# Each service module that owns an ``_as_rpc`` helper, and a backend error it is
# declared to accept. service_ext inlines the same wrap for r2/Ghidra instead.
def _service_as_rpc_helpers() -> list[tuple[str, Any, type[Exception]]]:
    from headless_re_mcp.core import (
        service_apk,
        service_device,
        service_frida,
        service_jsre,
        service_proxy,
        service_web,
    )

    return [
        ("service_frida", service_frida._as_rpc, FridaError),
        ("service_device", service_device._as_rpc, AdbError),
        ("service_apk", service_apk._as_rpc, ApkError),
        ("service_web", service_web._as_rpc, WebError),
        ("service_proxy", service_proxy._as_rpc, ProxyError),
        ("service_jsre", service_jsre._as_rpc, JsReError),
    ]


@pytest.mark.parametrize(
    ("name", "as_rpc", "error_cls"),
    _service_as_rpc_helpers(),
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_each_service_as_rpc_maps_faithfully(
    name: str, as_rpc: Any, error_cls: type[Exception]
) -> None:
    exc = error_cls("too_large", "payload exceeds limit", size=99, max_bytes=10)
    rpc = as_rpc(exc)
    assert isinstance(rpc, XdbgRpcError)
    assert rpc.code == "too_large"
    assert str(rpc) == "payload exceeds limit"
    assert rpc.details == {"size": 99, "max_bytes": 10}
    # And the wrapped error renders into the same faithful envelope.
    result = _failure(rpc)
    assert result.error is not None
    assert result.error.code == "too_large"
    assert result.error.details["size"] == 99


def test_service_frida_and_proxy_as_rpc_also_accept_adb_errors() -> None:
    """frida and proxy run device operations, so both map AdbError too.

    Their type hints say ``FridaError | AdbError`` / ``ProxyError | AdbError``;
    an ADB failure raised while a frida server is pushed, or while a proxy CA is
    installed on a device, must map with the same fidelity as the native error.
    """
    from headless_re_mcp.core import service_frida, service_proxy

    adb = AdbError("device_offline", "device went away", serial="emulator-5554")
    for as_rpc in (service_frida._as_rpc, service_proxy._as_rpc):
        rpc = as_rpc(adb)
        assert rpc.code == "device_offline"
        assert rpc.details == {"serial": "emulator-5554"}
