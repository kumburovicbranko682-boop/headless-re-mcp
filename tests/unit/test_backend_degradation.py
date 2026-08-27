"""Every optional non-PE backend degrades to capability_unavailable, not a crash.

Each backend here wraps an optional dependency -- Playwright (web), mitmproxy
(proxy), the frida Python module, jadx, and androguard (apk static). The
contract when that dependency is absent is a clean ``capability_unavailable``
error the agent can route on and degrade around, never an ImportError,
AttributeError or a partial result from calling into a ``None``. The behaviour
already lives in each backend's availability guard, but only adb, apktool,
apksigner, the jsre CLIs, r2 and windbg had it pinned; these five had the guard
in source with no test to keep it there. A refactor of an availability check
could silently turn a missing dependency back into a hard crash, which for an
unattended run is the difference between "skip this line" and a wedged mission.

Each case forces the unavailable state rather than skipping when the dependency
happens to be installed, so the degradation path is exercised in every
environment (the [web] extras install Playwright and mitmproxy here, so a
skip-if-available test would never run).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError
from headless_re_mcp.backends.web.client import WebBackend, WebError


def test_web_backend_without_playwright_degrades() -> None:
    backend = WebBackend()
    backend._available = False  # force the missing-playwright path
    with pytest.raises(WebError) as caught:
        backend.open("s1", "http://example.com")
    assert caught.value.code == "capability_unavailable"


def test_proxy_backend_without_mitmproxy_degrades() -> None:
    backend = ProxyBackend()
    backend._available = False  # force the missing-mitmproxy path
    with pytest.raises(ProxyError) as caught:
        backend.start("s1")
    assert caught.value.code == "capability_unavailable"


def test_frida_client_without_module_degrades() -> None:
    client = FridaClient()
    # Force the missing-module path regardless of whether frida is importable.
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "capability_unavailable"


def test_jadx_client_without_executable_degrades(tmp_path: Path) -> None:
    # No executable configured -> available is False; the guard must fire before
    # the apk-not-found check so a missing tool is not misreported as a bad path.
    client = JadxClient(executable=None)
    with pytest.raises(JadxError) as caught:
        client.export_sources(tmp_path / "nonexistent.apk", tmp_path / "out")
    assert caught.value.code == "capability_unavailable"


def test_apk_client_without_androguard_degrades(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = False  # force the missing-androguard path
    with pytest.raises(ApkError) as caught:
        client.open(tmp_path / "nonexistent.apk")
    assert caught.value.code == "capability_unavailable"
