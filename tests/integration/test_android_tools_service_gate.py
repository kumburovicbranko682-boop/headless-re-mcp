"""Android service gate: jadx and apktool through the service work-dir lifecycle.

The android tools / jadx-apk gates drive JadxClient and ApktoolClient directly,
and the service endpoints wrapping them (apk.decompile / apk.export_sources /
apk.decode / apk.repack) are exercised only by unit tests with mocked clients.
What the service adds on top is exactly what those mocks cannot prove:

- output is routed into the session-keyed work tree under the artifact root
  (``<root>/jadx/<session>`` and ``<root>/apktool/<session>``), not wherever
  the backend felt like writing,
- successes are recorded on the session timeline,
- repack's decoded_dir must stay inside the session artifact tree -- a real
  containment boundary (_require_session_path), refused as invalid_params,
- backend not_found crosses _as_rpc intact through the envelope,
- close_session reclaims the session's work trees (_forget_session_work_dirs:
  jadx and apktool output is unregistered, so close is the moment it becomes
  reclaimable), and later calls answer with a structured envelope.

The fixture APK is assembled by apktool's smali assembler; the framework-free
manifest keeps its bundled aapt2 SDK-free. Each half skips honestly when its
CLI is missing (apktool needs a JRE; jadx too). skip != pass.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.headlessre.gate"
_MARKER = "H3adl3ss-RE-svc-tools-4b7"

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
# The MetaInfo header is what apktool reads back; a framework-free manifest
# keeps aapt2 from needing an installed android.jar for android:* attributes.
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"

_SMALI = f""".class public Lcom/headlessre/gate/Secret;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static reveal()Ljava/lang/String;
    .registers 1
    const-string v0, "{_MARKER}"
    return-object v0
.end method
"""


def _build_apk(client: ApktoolClient, tmp_path: Path) -> Path:
    skeleton = tmp_path / "skeleton"
    smali_dir = skeleton / "smali" / "com" / "headlessre" / "gate"
    smali_dir.mkdir(parents=True)
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "Secret.smali").write_text(_SMALI, encoding="utf-8")
    out = tmp_path / "out.apk"
    built = client.build(skeleton, out)
    assert Path(built["apk"]).is_file()
    return out


def _events(service: AnalysisService, session_id: str) -> set[object]:
    timeline = service.timeline_list(session_id)
    assert timeline.ok and timeline.data is not None, timeline.error
    return {entry.get("event") for entry in timeline.data["events"]}


@pytest.mark.integration
def test_android_jadx_service_decompiles_into_the_session_tree(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    if not JadxClient(executable=settings.jadx).available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX / PATH) — skip != pass")

    apk = _build_apk(apktool, tmp_path)
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])
        session_tree = settings.artifact_root.expanduser().resolve() / "jadx" / session_id

        # Decompile through the service: real source, written into the
        # session-keyed tree the service chose, not a caller-supplied path.
        decompiled = service.apk_decompile(session_id, _PACKAGE + ".Secret")
        assert decompiled.ok and decompiled.data is not None, decompiled.error
        assert decompiled.data["class_name"] == _PACKAGE + ".Secret"
        assert _MARKER in str(decompiled.data["source"])
        emitted = Path(str(decompiled.data["path"])).resolve()
        assert session_tree in emitted.parents, (emitted, session_tree)

        # Whole-APK export lands in the same session tree.
        exported = service.apk_export_sources(session_id)
        assert exported.ok and exported.data is not None, exported.error
        assert exported.data["java_file_count"] >= 1, exported.data
        sources_dir = Path(str(exported.data["sources_dir"])).resolve()
        assert session_tree == sources_dir or session_tree in sources_dir.parents

        # Both successes are on the timeline, not only failures.
        events = _events(service, session_id)
        assert {"apk.decompile", "apk.export_sources"} <= events, events

        # Backend not_found crosses _as_rpc intact through the envelope.
        missing = service.apk_decompile(session_id, _PACKAGE + ".Missing")
        assert missing.ok is False and missing.error is not None
        assert missing.error.code == "not_found", missing.error

        # jadx output is unregistered, so close is when it becomes reclaimable.
        assert session_tree.is_dir()
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        assert not session_tree.exists(), session_tree

        after = service.apk_decompile(session_id, _PACKAGE + ".Secret")
        assert after.ok is False and after.error is not None
        assert after.error.code in {"invalid_request", "session_not_found"}, after.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apktool_service_decode_repack_lifecycle(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")

    apk = _build_apk(apktool, tmp_path)
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])
        session_tree = settings.artifact_root.expanduser().resolve() / "apktool" / session_id

        # Decode through the service: the manifest round-trips and the decoded
        # tree sits under the session-keyed work dir.
        decoded = service.apk_decode(session_id)
        assert decoded.ok and decoded.data is not None, decoded.error
        manifest = Path(str(decoded.data["manifest"])).resolve()
        assert manifest.is_file()
        assert session_tree in manifest.parents, (manifest, session_tree)
        assert _PACKAGE in manifest.read_text(encoding="utf-8", errors="replace")

        # Repack the decoded tree (default decoded_dir): a real rebuilt APK
        # appears at the service-chosen path inside the session tree.
        repacked = service.apk_repack(session_id)
        assert repacked.ok and repacked.data is not None, repacked.error
        rebuilt = Path(str(repacked.data["apk"])).resolve()
        assert rebuilt == session_tree / "repacked.apk"
        assert rebuilt.is_file() and rebuilt.stat().st_size > 0

        events = _events(service, session_id)
        assert {"apk.decode", "apk.repack"} <= events, events

        # decoded_dir outside the session artifact tree is a containment
        # violation, refused as invalid_params before apktool ever runs.
        escape = service.apk_repack(session_id, decoded_dir=str(tmp_path))
        assert escape.ok is False and escape.error is not None
        assert escape.error.code == "invalid_params", escape.error

        # Close reclaims the apktool work tree; later calls stay structured.
        assert session_tree.is_dir()
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        assert not session_tree.exists(), session_tree

        after = service.apk_decode(session_id)
        assert after.ok is False and after.error is not None
        assert after.error.code in {"invalid_request", "session_not_found"}, after.error
    finally:
        service.close_all()
