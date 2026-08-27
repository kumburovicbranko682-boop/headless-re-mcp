"""Live jadx gate: the decompiler recovers the Java the DEX was built from.

The APK static gate proves androguard reads the manifest and DEX; this proves
the *other* Android tooling line -- jadx (``apk.export_sources`` /
``apk.decompile``) -- actually turns that DEX back into Java. That path is a
bounded subprocess into a per-session artifact dir, and it had no live coverage
at all: a break in argv assembly, the sources-root escape guard, or the
class-name-to-path mapping would only have surfaced on a real machine.

Deterministic and self-contained: ``fixtures/android/apk_fixture.py`` builds a
valid APK in pure Python whose one class ``com.headlessre.gate.Gate`` has
``entry()`` call ``leaf()`` via invoke-static, so the recovered source must show
that call -- not merely a non-empty file. skip != pass when jadx (or its JRE)
is not installed.
"""

from __future__ import annotations

import importlib.util
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_BUILDER = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "apk_fixture.py"


def _load_fixture_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("apk_fixture", _FIXTURE_BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.integration
def test_jadx_decompiles_generated_apk_and_preserves_the_call(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    if not JadxClient(settings.jadx).available:
        pytest.skip("jadx not installed — jadx decompile Gate not run (skip != pass)")
    fx = _load_fixture_builder()
    apk = fx.build_apk(tmp_path / "gate.apk")

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        listed = exported.data["java_files"]
        assert any(name.endswith("com/headlessre/gate/Gate.java") for name in listed), listed

        # Both the dotted and smali spellings must resolve to the same class.
        for spelling in (fx.CLASS_DOTTED, fx.CLASS_SMALI):
            decompiled = service.apk_decompile(session_id, spelling)
            assert decompiled.ok, decompiled.error
            source = decompiled.data["source"]
            assert f"package {fx.PACKAGE};" in source
            assert "class Gate" in source
            # entry() calls leaf() via invoke-static in the DEX; the decompiled
            # Java must show that call, proving real bytecode round-tripped.
            assert fx.METHOD_ENTRY in source
            assert f"{fx.METHOD_LEAF}();" in source
    finally:
        service.close_all()
