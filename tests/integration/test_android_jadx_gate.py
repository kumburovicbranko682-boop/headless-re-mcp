"""Android jadx gate: proof that jadx decompiles a real DEX back to Java.

The Android RE gate only ever asked jadx to degrade cleanly -- ``apk.decompile``
and ``apk.export_sources`` have never been proven to actually decompile anything
here. This gate closes that hole with no Android SDK: it reuses the hand-encoded,
valid ``classes.dex`` the androguard static gate builds (class
``Lcom/gate/sample/Gate;`` with two direct methods, ``gateCaller``
invoke-static'ing ``gateSecret``), runs jadx over the APK through the real service
surface, and asserts the *decompiled Java*, not merely that a call returned:

  * ``apk.export_sources`` writes a source tree that includes ``Gate.java`` and
    reports a clean run (no ``tool_failed``);
  * ``apk.decompile`` returns Java for that one class in which the package, the
    class, both methods, and -- critically -- ``gateCaller``'s call to
    ``gateSecret()`` all survive the DEX -> Java round trip;
  * ``apk.decompile`` on a class the DEX does not define is a clean ``not_found``.

skip != pass: with jadx (a JRE plus the jadx CLI) absent the gate skips loudly.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from test_android_static_gate import (
    _DEX_CALLER,
    _DEX_CLASS,
    _DEX_METHOD,
    _PACKAGE,
    _build_valid_apk,
)

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _jadx_executable() -> Path | None:
    """Resolve jadx the way config does: env override, then PATH."""
    env = os.environ.get("HEADLESS_RE_JADX")
    if env and Path(env).is_file():
        return Path(env)
    found = shutil.which("jadx") or shutil.which("jadx.bat")
    return Path(found) if found else None


def _service(tmp_path: Path, jadx: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        jadx=jadx,
    )
    return AnalysisService(settings)


@pytest.mark.integration
def test_jadx_exports_a_source_tree_for_the_apk(tmp_path: Path) -> None:
    jadx = _jadx_executable()
    if jadx is None:
        pytest.skip("jadx not installed — Android jadx Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    assert classify_target(apk) is TargetKind.APK

    service = _service(tmp_path, jadx)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id)
        assert exported.ok, exported.error
        data = exported.data
        assert data["java_file_count"] >= 1
        # A clean run: jadx must not have reported a partial/failed decompile.
        assert data.get("tool_failed") is not True, data
        assert any(
            f.replace("\\", "/").endswith("com/gate/sample/Gate.java") for f in data["java_files"]
        ), data["java_files"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_jadx_decompiles_the_class_with_the_call_edge(tmp_path: Path) -> None:
    jadx = _jadx_executable()
    if jadx is None:
        pytest.skip("jadx not installed — Android jadx Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    service = _service(tmp_path, jadx)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.apk_decompile(session_id, _DEX_CLASS)
        assert result.ok, result.error
        source = result.data["source"]
        assert f"package {_PACKAGE};" in source
        assert "class Gate" in source
        assert _DEX_METHOD in source
        assert _DEX_CALLER in source
        # The invoke-static edge must survive DEX -> Java decompilation:
        # gateCaller's body calls gateSecret().
        assert f"{_DEX_METHOD}();" in source
    finally:
        service.close_all()


@pytest.mark.integration
def test_jadx_decompile_unknown_class_is_not_found(tmp_path: Path) -> None:
    """A class the DEX does not define must be a clean not_found, not a crash."""
    jadx = _jadx_executable()
    if jadx is None:
        pytest.skip("jadx not installed — Android jadx Gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "gate.apk")
    service = _service(tmp_path, jadx)
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        missing = service.apk_decompile(session_id, "Lcom/gate/sample/DoesNotExist;")
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "not_found"
    finally:
        service.close_all()
