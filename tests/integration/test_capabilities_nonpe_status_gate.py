"""Live gate: capabilities.search reports the *correct* status for non-PE backends.

``capabilities.search`` derives each backend's status by copying the value of a
named doctor probe (the capability's ``status_probe``). Two things already guard
that mapping, and both miss the failure this gate covers:

* the unit tests stub ``run_doctor`` with only the PE probes, so a non-PE
  capability's status is never computed from a real install; and
* ``test_capabilities_catalog`` only checks that each ``status_probe`` *exists*
  as some probe -- not that it is the *right* probe.

So a capability keyed on a real-but-wrong probe (say ``wasm.wabt`` reading the
``webcrack`` probe) would pass every existing test while reporting the wrong
tool's availability. This gate installs specific non-PE backends and asserts
``capabilities.search`` marks each ``detected`` exactly when *its own* backend is
present -- a mis-keyed ``status_probe`` makes the two disagree and fails here.
Skips honestly (skip != pass) when no optional non-PE backend is installed.
"""

from __future__ import annotations

import importlib.util
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _which(*names: str) -> bool:
    return any(shutil.which(name) for name in names)


def _module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


# cap_id -> "is this backend really usable on the host?", expressed against the
# actual tool the capability needs. The candidate lists mirror run_doctor()'s
# probes exactly, so this agrees with doctor's detection unless the capability's
# status_probe is keyed to the wrong probe -- which is the regression to catch.
_NONPE_GROUND_TRUTH: dict[str, Callable[[], bool]] = {
    "r2.pipe": lambda: _which("r2", "rizin"),
    "wasm.wabt": lambda: _which("wasm2wat"),
    "jsre.webcrack": lambda: _which("webcrack"),
    "apk.androguard": lambda: _module("androguard"),
    "apk.jadx": lambda: _which("jadx", "jadx.bat"),
    "apk.apktool": lambda: _which("apktool", "apktool.bat"),
    "device.adb": lambda: _module("adbutils"),
    "frida.session": lambda: _module("frida"),
    "frida.device": lambda: _module("frida"),
    "web.cdp": lambda: _module("playwright"),
    "proxy.mitmproxy": lambda: _module("mitmproxy"),
}


@pytest.mark.integration
def test_capabilities_status_matches_installed_nonpe_backends(tmp_path: Path) -> None:
    # No configured tool paths, so both doctor and the ground truth below detect
    # purely from PATH / importability and cannot disagree over a configured
    # override.
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path,
    )
    service = AnalysisService(settings)
    try:
        result = service.capabilities_search()
        assert result.ok, result.error
        caps = {item["id"]: item for item in result.data["capabilities"]}

        detected_any = False
        for cap_id, is_present in _NONPE_GROUND_TRUTH.items():
            assert cap_id in caps, f"capabilities.search dropped {cap_id}"
            status = caps[cap_id]["status"]
            if is_present():
                assert status == "detected", (
                    f"{cap_id} backend is installed but capabilities.search said {status}"
                )
                detected_any = True
            else:
                assert status == "missing", (
                    f"{cap_id} backend is absent but capabilities.search said {status}"
                )

        if not detected_any:
            pytest.skip(
                "no optional non-PE backend installed — status gate not run (skip != pass)"
            )
    finally:
        service.close_all()
