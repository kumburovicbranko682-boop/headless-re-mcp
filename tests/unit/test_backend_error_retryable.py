"""A backend timeout must reach the caller as retryable, like a native one.

Every backend error (adb, apk, frida, ghidra, jsre, proxy, radare2, web, windbg)
is turned into the RPC envelope error by a per-line ``_as_rpc`` helper or by an
inline conversion in ``service_ext``. Those all minted ``XdbgRpcError`` with the
constructor default ``retryable=False``, so a backend ``timeout`` -- the one code
every bounded backend can raise -- reached the caller (and the workflow failure
record, which reads ``exc.retryable``) as *non*-retryable, while an identical
native ``TimedOut`` was marked retryable in ``_failure``. These guard the shared
``_rpc_from_backend`` policy and that every ``_as_rpc`` helper routes through it,
so the one contract stays consistent across the Android / Web / portable-static
lines. windbg has no ``_as_rpc`` helper -- ``service_ext`` converts its errors
inline -- so a service-level test pins that its inline sites route through the
same policy rather than the raw ``XdbgRpcError`` they carried before.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.jsre import JsReError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.backends.web import WebError
from headless_re_mcp.backends.windbg.client import WindbgError
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

    # windbg carries the same code/message/details shape and rides the same
    # policy even though it has no _as_rpc helper of its own.
    windbg_timeout = _rpc_from_backend(WindbgError("timeout", "cdb timed out", timeout=60.0))
    assert windbg_timeout.code == "timeout"
    assert windbg_timeout.retryable is True
    assert windbg_timeout.details == {"timeout": 60.0}
    assert _rpc_from_backend(WindbgError("backend_error", "cdb failed")).retryable is False


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


@pytest.mark.parametrize(
    ("code", "expected_retryable"),
    [("timeout", True), ("backend_error", False)],
)
def test_windbg_service_routes_inline_conversion_through_the_policy(
    tmp_path: Path, monkeypatch: Any, code: str, expected_retryable: bool
) -> None:
    """service_ext converts windbg errors inline; that path must derive retryable.

    windbg has no _as_rpc helper -- the eight service_ext windbg endpoints minted
    XdbgRpcError(exc.code, ...) directly, so a cdb timeout reached the caller as
    non-retryable while every other backend timeout (which now routes through
    _rpc_from_backend) was retryable. This drives a real service call with a fake
    client that raises, and asserts the envelope error carries the derived flag.
    """
    import headless_re_mcp.core.service_ext as service_ext_module
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    class _RaisingClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def threads(self, dump: Path, *, timeout: float = 60.0) -> dict[str, Any]:
            del dump
            raise WindbgError(code, "cdb failed", timeout=timeout, killed_pids=[4242])

    monkeypatch.setattr(service_ext_module, "WindbgClient", _RaisingClient)
    monkeypatch.setattr(service_ext_module, "is_windows_host", lambda: True)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        result = service.windbg_threads("crash.dmp")
    finally:
        service.close_all()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == code
    assert result.error.retryable is expected_retryable
    assert result.error.details.get("killed_pids") == [4242]
