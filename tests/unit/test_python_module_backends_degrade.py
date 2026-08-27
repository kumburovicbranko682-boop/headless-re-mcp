"""Python-module backends must degrade to capability_unavailable, deterministically.

The shell-out degradation contract (test_nonpe_degradation_contract) forces
"backend absent" by stubbing shutil.which, and explicitly defers the backends
that are Python imports -- androguard, adbutils, playwright, mitmproxy, frida
-- to per-backend tests. Frida has one that forces the absent state; the
adbutils one, though, skips whenever adbutils is importable, which on CI is
always (the android extra installs it), so its degradation branch never
actually runs there -- and androguard / playwright / mitmproxy had no
module-absent test at all. A refactor that dropped any of these availability
gates would let an AttributeError on the None module handle escape and be
filed as an internal_error incident ("file a bug") instead of the honest
"install this package".

Each client caches availability on the instance, so overriding that flag --
the same forcing the frida test uses -- reaches the exact production branch
("already probed, absent") without uninstalling anything, which makes these
run identically on a bare machine and on a fully provisioned CI host.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.web import WebBackend, WebError


def test_apk_ops_report_capability_unavailable_when_androguard_is_absent(
    tmp_path: Path,
) -> None:
    """Both parse families (_apk for manifest facts, _parsed for DEX analysis)
    call _require independently, so one op from each must take the gate."""
    client = ApkClient()
    client._available = False
    client._androguard = None

    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK\x03\x04")

    ops: list[tuple[str, Callable[[], object]]] = [
        ("open", lambda: client.open(apk)),
        ("classes", lambda: client.classes(apk)),
    ]
    for label, call in ops:
        with pytest.raises(ApkError) as caught:
            call()
        assert caught.value.code == "capability_unavailable", label
        assert "androguard" in caught.value.message, label


def test_apk_missing_file_is_not_found(tmp_path: Path) -> None:
    """_require checks the path after the availability gate and before any
    androguard import, so forcing the gate open exercises the exact production
    branch whether or not androguard is installed on this host."""
    client = ApkClient()
    client._available = True

    with pytest.raises(ApkError) as caught:
        client.open(tmp_path / "no-such.apk")
    assert caught.value.code == "not_found"
    assert str(caught.value.details.get("path", "")).endswith("no-such.apk")


def test_adb_ops_report_capability_unavailable_when_adbutils_is_absent() -> None:
    """Every device.* op funnels through _client(); with adbutils forced absent
    the gate must fire there, before any endpoint resolution or server spawn."""
    backend = AdbBackend()
    backend._available = False
    backend._adbutils = None

    with pytest.raises(AdbError) as caught:
        backend.list_devices()
    assert caught.value.code == "capability_unavailable"
    assert "adbutils" in caught.value.message


def test_web_open_reports_capability_unavailable_when_playwright_is_absent() -> None:
    """open is the only web entry point that reaches _check_available; the read
    tools reject a never-opened session as invalid_state first (pinned in
    test_web_backends), so the absent-module report must come from open."""
    backend = WebBackend()
    backend._available = False

    with pytest.raises(WebError) as caught:
        backend.open("s", "http://127.0.0.1/")
    assert caught.value.code == "capability_unavailable"
    assert "playwright" in caught.value.message


def test_proxy_start_reports_capability_unavailable_when_mitmproxy_is_absent() -> None:
    backend = ProxyBackend()
    backend._available = False

    with pytest.raises(ProxyError) as caught:
        backend.start("s")
    assert caught.value.code == "capability_unavailable"
    assert "mitmproxy" in caught.value.message
