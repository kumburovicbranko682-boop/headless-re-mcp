"""A backend timeout must reach the caller as retryable, like a native one.

Every backend error (adb, apk, frida, ghidra, jsre, proxy, radare2, web) is
turned into the RPC envelope error by a per-line ``_as_rpc`` helper or by an
inline conversion in ``service_ext``. Those all minted ``XdbgRpcError`` with the
constructor default ``retryable=False``, so a backend ``timeout`` -- the one code
every bounded backend can raise -- reached the caller (and the workflow failure
record, which reads ``exc.retryable``) as *non*-retryable, while an identical
native ``TimedOut`` was marked retryable in ``_failure``. These guard the shared
``_rpc_from_backend`` policy and that every ``_as_rpc`` helper routes through it,
so the one contract stays consistent across the Android / Web / portable-static
lines.
"""

from __future__ import annotations

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.backends.web import WebError
from headless_re_mcp.core.results import _RETRYABLE_BACKEND_CODES, _rpc_from_backend
from headless_re_mcp.core.service_apk import _as_rpc as apk_as_rpc
from headless_re_mcp.core.service_device import _as_rpc as device_as_rpc
from headless_re_mcp.core.service_frida import _as_rpc as frida_as_rpc
from headless_re_mcp.core.service_jsre import _as_rpc as jsre_as_rpc
from headless_re_mcp.core.service_proxy import _as_rpc as proxy_as_rpc
from headless_re_mcp.core.service_web import _as_rpc as web_as_rpc


def test_only_timeout_is_a_retryable_backend_code() -> None:
    """timeout is the sole transient backend code; nothing deterministic joins it.

    A wider set would retry a corrupt file or a bad argument on a loop, which is
    why capability_unavailable / not_found / invalid_params / too_large /
    backend_error stay non-retryable.
    """
    assert frozenset({"timeout"}) == _RETRYABLE_BACKEND_CODES


def test_rpc_from_backend_marks_timeout_retryable_and_others_not() -> None:
    timed_out = _rpc_from_backend(WebError("timeout", "navigation timed out", url="x"))
    assert timed_out.code == "timeout"
    assert timed_out.retryable is True
    # The message and details still travel; only retryable is newly derived.
    assert str(timed_out) == "navigation timed out"
    assert timed_out.details == {"url": "x"}

    for code in (
        "capability_unavailable",
        "not_found",
        "invalid_params",
        "too_large",
        "backend_error",
    ):
        rpc = _rpc_from_backend(WebError(code, "nope"))
        assert rpc.code == code
        assert rpc.retryable is False, code


def test_every_backend_as_rpc_helper_derives_retryable_from_the_code() -> None:
    """Each per-line _as_rpc must route through the shared policy, not the default.

    Constructed rather than provoked through a real backend so the assertion is
    about the conversion, not about which op happens to time out. A timeout from
    any of these lines is retryable; a capability_unavailable from any is not.
    """
    cases = (
        (web_as_rpc, WebError),
        (proxy_as_rpc, ProxyError),
        (proxy_as_rpc, AdbError),
        (frida_as_rpc, FridaError),
        (frida_as_rpc, AdbError),
        (apk_as_rpc, ApkError),
        (jsre_as_rpc, JsReError),
        (device_as_rpc, AdbError),
    )
    for as_rpc, error_type in cases:
        label = f"{as_rpc.__module__}:{error_type.__name__}"
        timed_out = as_rpc(error_type("timeout", "timed out"))  # type: ignore[arg-type]
        assert timed_out.retryable is True, label
        unavailable = as_rpc(error_type("capability_unavailable", "not configured"))  # type: ignore[arg-type]
        assert unavailable.retryable is False, label
