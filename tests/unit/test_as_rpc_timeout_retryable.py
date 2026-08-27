"""Backend->RPC translation must forward the transient-timeout signal.

The web, frida, proxy, device (adb) and apk (jadx/apktool) service layers each
convert their backend error into an ``XdbgRpcError`` through a module-level
``_as_rpc``. Those backends all raise a ``"timeout"`` code when a browser, a
device probe, mitmproxy, a replay, or a JVM outruns its deadline, but none of
the error classes carries a ``retryable`` flag, and ``XdbgRpcError`` defaults it
to False. Every ``_as_rpc`` therefore has to derive it from the code the way
``service_jsre`` (and the upx/die/de4dot siblings) already do -- otherwise a
transient stall reaches the caller as a permanent failure and an unattended
agent that retries on the flag gives up on what a second run typically clears.
A timeout is the one transient case; launch/parse/not-found failures stay
non-retryable.
"""

from __future__ import annotations

from headless_re_mcp.backends.adb.client import AdbError
from headless_re_mcp.backends.apktool.client import ApktoolError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.jadx.client import JadxError
from headless_re_mcp.backends.proxy.client import ProxyError
from headless_re_mcp.backends.web.client import WebError


def test_web_as_rpc_marks_only_a_timeout_retryable() -> None:
    from headless_re_mcp.core.service_web import _as_rpc

    assert _as_rpc(WebError("timeout", "browser did not respond")).retryable is True
    assert _as_rpc(WebError("backend_error", "cdp failed")).retryable is False
    assert _as_rpc(WebError("invalid_params", "bad url")).retryable is False


def test_frida_as_rpc_marks_only_a_timeout_retryable() -> None:
    from headless_re_mcp.core.service_frida import _as_rpc

    assert _as_rpc(FridaError("timeout", "frida did not respond")).retryable is True
    assert _as_rpc(AdbError("timeout", "adb timed out")).retryable is True
    assert _as_rpc(FridaError("invalid_params", "bad address")).retryable is False
    assert _as_rpc(AdbError("not_found", "device unavailable")).retryable is False


def test_proxy_as_rpc_marks_only_a_timeout_retryable() -> None:
    from headless_re_mcp.core.service_proxy import _as_rpc

    assert _as_rpc(ProxyError("timeout", "mitmproxy not listening")).retryable is True
    assert _as_rpc(AdbError("timeout", "adb timed out")).retryable is True
    assert _as_rpc(ProxyError("backend_error", "replay failed")).retryable is False


def test_device_as_rpc_marks_only_a_timeout_retryable() -> None:
    from headless_re_mcp.core.service_device import _as_rpc

    assert _as_rpc(AdbError("timeout", "adb timed out")).retryable is True
    assert _as_rpc(AdbError("not_found", "apk not found")).retryable is False
    assert _as_rpc(AdbError("too_large", "file exceeds cap")).retryable is False


def test_apk_as_rpc_marks_only_a_timeout_retryable() -> None:
    from headless_re_mcp.core.service_apk import _as_rpc

    # jadx/apktool timeouts run through run_bounded and are transient; an
    # androguard ApkError never uses the code and stays non-retryable.
    assert _as_rpc(JadxError("timeout", "jadx timed out")).retryable is True
    assert _as_rpc(ApktoolError("timeout", "apktool timed out")).retryable is True
    assert _as_rpc(JadxError("invalid_params", "not a zip")).retryable is False
    assert _as_rpc(ApktoolError("backend_error", "apktool failed")).retryable is False
