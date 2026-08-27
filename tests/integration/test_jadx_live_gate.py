"""jadx live decompile gate: real APK -> real Java. skip != pass when jadx absent.

Everything else about jadx is covered by unit tests with a fake tree on disk;
nothing runs the jadx CLI. This gate builds a real (hand-assembled) APK, drives
the actual ``JadxClient`` against the configured jadx binary, and asserts the
decompiled Java -- so the subprocess launch, output-tree listing, dotted/smali
class-path resolution, source read-back and the not_found path are all proven
against the real tool rather than a mock. jadx needs a JRE; with neither jadx
nor the JRE present the gate skips loudly rather than passing silently.
"""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx import JadxClient, JadxError

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUILDER = _PROJECT_ROOT / "fixtures" / "android" / "build_min_apk.py"
_SKIP_NO_JADX = "jadx not configured (HEADLESS_RE_JADX/PATH) — live gate not run (skip != pass)"


def _load_builder() -> object:
    spec = importlib.util.spec_from_file_location("_jadx_min_apk_builder", _BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _discover_jadx() -> Path | None:
    import os

    candidate = os.environ.get("HEADLESS_RE_JADX")
    if candidate and Path(candidate).is_file():
        return Path(candidate)
    for name in ("jadx", "jadx.bat"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _build_apk(tmp_path: Path) -> Path:
    builder = _load_builder()
    apk = tmp_path / "gate.apk"
    builder.build_apk(apk)  # type: ignore[attr-defined]
    assert apk.is_file() and apk.stat().st_size > 0
    return apk


@pytest.mark.integration
def test_jadx_export_sources_and_decompile_real_class(tmp_path: Path) -> None:
    jadx = _discover_jadx()
    if jadx is None:
        pytest.skip(_SKIP_NO_JADX)
    client = JadxClient(jadx)
    if not client.available:
        pytest.skip(f"jadx path is not a file: {jadx} — live gate not run (skip != pass)")

    apk = _build_apk(tmp_path)

    # export_sources: the whole tree lands on disk and the summary names it.
    export = client.export_sources(apk, tmp_path / "out_export", timeout=180.0)
    assert export["java_file_count"] >= 1, export
    assert export["sources_dir"], export
    assert any(
        name.replace("\\", "/").endswith("com/example/gate/Secret.java")
        for name in export["java_files"]
    ), export["java_files"]
    # A clean decompile of this one-class APK must not be flagged as partial.
    assert "tool_failed" not in export, export

    # decompile: the dotted name resolves and the Java is the real thing.
    dotted = client.decompile(
        apk, tmp_path / "out_dotted", "com.example.gate.Secret", timeout=180.0
    )
    src = dotted["source"]
    assert dotted["class_name"] == "com.example.gate.Secret"
    assert dotted["truncated"] is False
    assert "class Secret" in src, src
    assert "decrypt" in src and "caller" in src, src
    # The string literal the DEX references survives the round trip through jadx.
    assert "gate-secret-string" in src, src

    # The smali form of the same class resolves to the same source.
    smali = client.decompile(
        apk, tmp_path / "out_smali", "Lcom/example/gate/Secret;", timeout=180.0
    )
    assert "class Secret" in smali["source"], smali["source"]


@pytest.mark.integration
def test_jadx_decompile_unknown_class_is_not_found(tmp_path: Path) -> None:
    jadx = _discover_jadx()
    if jadx is None:
        pytest.skip(_SKIP_NO_JADX)
    client = JadxClient(jadx)
    if not client.available:
        pytest.skip(f"jadx path is not a file: {jadx} — live gate not run (skip != pass)")

    apk = _build_apk(tmp_path)
    with pytest.raises(JadxError) as excinfo:
        client.decompile(
            apk, tmp_path / "out_missing", "com.example.gate.NoSuchClass", timeout=180.0
        )
    assert excinfo.value.code == "not_found", excinfo.value.code
