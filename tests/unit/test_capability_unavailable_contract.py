"""Every optional non-PE backend degrades to ``capability_unavailable``.

The non-PE tracks are all optional: a host without radare2, without a JRE for
jadx/apktool, without Ghidra, without the frida/adbutils/androguard/playwright/
mitmproxy Python modules, or without Node's webcrack and wabt still boots and
stays ready. ``doctor`` reports each as missing rather than blocking, and the
promise the whole design leans on is "missing only degrades" -- a call into an
absent backend must come back as a clean ``capability_unavailable`` envelope,
never an ``AttributeError`` on a ``None`` module or an opaque ``internal_error``
incident that reads like a server defect.

Each backend enforces this itself as the first thing its entry points do, but
nothing pinned that they all still do it, or that a newly added backend joins
the contract. That is the same blind spot the timeout-clamp audit found in
Ghidra: a per-backend habit with no family-level guard. This test constructs
every non-PE backend in its tool-absent state -- exactly the state doctor
reports on a bare host -- and asserts the representative entry point refuses
with ``capability_unavailable`` instead of crashing. A backend that grows an
entry point which touches the missing tool before the guard, or a new backend
added without the guard, fails here.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.backends.jsre.client import JsClient, JsReError, WasmClient
from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.web.client import WebBackend, WebError


class _Case(NamedTuple):
    error_cls: type[Exception]
    call: Callable[[], Any]


CASE_NAMES = (
    "radare2",
    "jadx",
    "apktool",
    "webcrack",
    "wabt",
    "ghidra",
    "frida",
    "adb",
    "apk",
    "web",
    "proxy",
)


def _cases(tmp_path: Path) -> dict[str, _Case]:
    """Build each backend in its tool-absent state with a representative call.

    CLI backends are unavailable when their executable does not resolve to a
    file; module backends when their cached ``_available`` flag is False -- the
    exact state the constructor lands in when the import fails. Both are set
    deterministically so the contract holds regardless of what happens to be
    installed on the test host.
    """
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ")

    r2 = R2Client(executable=tmp_path / "nonexistent-r2")
    jadx = JadxClient(executable=tmp_path / "nonexistent-jadx")
    apktool = ApktoolClient(apktool=None)

    webcrack = JsClient()
    webcrack.executable = None
    wasm = WasmClient()
    wasm._wasm2wat = None
    wasm._objdump = None

    ghidra = GhidraClient(home=None)

    frida = FridaClient()
    frida._available = False
    frida._frida = None

    adb = AdbBackend()
    adb._available = False
    adb._adbutils = None

    apk = ApkClient()
    apk._available = False

    web = WebBackend()
    web._available = False

    proxy = ProxyBackend()
    proxy._available = False

    return {
        "radare2": _Case(R2Error, lambda: r2.run(target, ["i"], timeout=30.0)),
        "jadx": _Case(
            JadxError, lambda: jadx.export_sources(target, tmp_path / "jadx_out", timeout=30.0)
        ),
        "apktool": _Case(
            ApktoolError, lambda: apktool.decode(target, tmp_path / "apktool_out", timeout=30.0)
        ),
        "webcrack": _Case(JsReError, lambda: webcrack.deobfuscate(target, timeout=30.0)),
        "wabt": _Case(JsReError, lambda: wasm.wat(target, timeout=30.0)),
        "ghidra": _Case(
            GhidraError, lambda: ghidra.analyze_binary(target, tmp_path / "proj", timeout=30.0)
        ),
        "frida": _Case(FridaError, lambda: frida.attach(1, allowed_pid=1)),
        "adb": _Case(AdbError, lambda: adb.list_devices()),
        "apk": _Case(ApkError, lambda: apk.open(target)),
        "web": _Case(WebError, lambda: web.open("sess-1", "http://example.test")),
        "proxy": _Case(ProxyError, lambda: proxy.start("sess-1")),
    }


@pytest.mark.parametrize("name", CASE_NAMES)
def test_an_absent_backend_refuses_with_capability_unavailable(
    name: str, tmp_path: Path
) -> None:
    case = _cases(tmp_path)[name]
    with pytest.raises(case.error_cls) as caught:
        case.call()
    assert caught.value.code == "capability_unavailable"
    # A bare log line must not be empty: the message doubles as str(exc).
    assert str(caught.value).strip()
