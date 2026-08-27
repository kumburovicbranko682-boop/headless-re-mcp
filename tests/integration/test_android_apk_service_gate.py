"""Android service gate: the apk.* service surface on a real, valid APK.

Coverage today splits into two halves that never meet: the DEX gate drives
ApkClient directly on a real apktool-built APK, and the RE gate drives the
service but on a deliberately broken synthetic APK, asserting only failure
envelopes. Nothing proves the *success* path of the service layer -- the
_apk_call getattr dispatch, offset/limit forwarding, the ok/data/meta
envelope, timeline recording, and the close path that releases androguard's
parse caches -- against an APK androguard can actually analyze. This gate
builds a real APK (apktool's smali assembler; a framework-free manifest keeps
its bundled aapt2 SDK-free) and drives AnalysisService end to end, asserting:

- session.create classifies the real APK and reads its stdlib metadata,
- apk.open succeeds through the service and lands on the session timeline,
- every _apk_call-dispatched endpoint (manifest / permissions / certificates
  / components / native_libs) returns real data through the envelope,
- classes / methods / strings / xrefs recover the assembled class, its
  descriptors, the marker string and the reveal -> mangle call edge,
- offset/limit reach the backend (a one-string window of the string pool),
- ApkError codes cross _as_rpc intact on a *valid* APK: a missing class is
  not_found and an empty method name invalid_params, where the RE gate's
  broken fixture can only ever observe backend_error,
- closing the session drops androguard's cached parses for that path (the
  real release in close_session, not the unit tests' stub objects), and a
  later apk call answers with a structured envelope, never a crash.

Skips honestly when apktool (needs a JRE) or androguard is missing.
skip != pass.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.headlessre.gate"
_MARKER = "H3adl3ss-RE-service-9e2"
_CLASS_SMALI = "Lcom/headlessre/gate/Secret;"

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
# The MetaInfo header is what apktool reads back; a framework-free manifest
# keeps aapt2 from needing an installed android.jar for android:* attributes.
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"

# reveal() calls mangle() and holds the marker string, giving androguard a real
# class, two methods, a string constant and one intra-DEX call edge to resolve.
_SMALI = f""".class public Lcom/headlessre/gate/Secret;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static mangle(I)I
    .registers 2
    xor-int/lit8 v0, p0, 0x41
    add-int/lit8 v0, v0, 0x7
    return v0
.end method

.method public static reveal()Ljava/lang/String;
    .registers 2
    const/4 v1, 0x5
    invoke-static {{v1}}, Lcom/headlessre/gate/Secret;->mangle(I)I
    move-result v1
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


@pytest.mark.integration
def test_android_apk_service_surface_on_a_real_apk(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    if not ApkClient().available:
        pytest.skip("androguard not installed — service gate not run (skip != pass)")

    apk = _build_apk(apktool, tmp_path)
    resolved = str(apk.expanduser().resolve())

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        meta = session["metadata"]["apk"]
        assert meta["dex_count"] == 1, meta
        assert meta["native_abis"] == [], meta
        assert meta["signed_v1"] is False, meta
        session_id = str(session["id"])

        # apk.open is the endpoint with explicit backend/timeline recording:
        # a real success must land on the session timeline, not only failures.
        opened = service.apk_open(session_id)
        assert opened.ok and opened.data is not None, opened.error
        assert opened.data["package"] == _PACKAGE
        assert opened.meta.get("backend") == "apk"
        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None, timeline.error
        events = {entry.get("event") for entry in timeline.data["events"]}
        assert "apk.open" in events, events

        # The _apk_call getattr dispatch, one success per routed op.
        manifest = service.apk_manifest(session_id)
        assert manifest.ok and manifest.data is not None, manifest.error
        assert _PACKAGE in manifest.data["manifest_xml"]
        permissions = service.apk_permissions(session_id)
        assert permissions.ok and permissions.data is not None, permissions.error
        assert permissions.data["permissions"] == []
        certificates = service.apk_certificates(session_id)
        assert certificates.ok and certificates.data is not None, certificates.error
        assert certificates.data["v1_signed"] is False
        components = service.apk_components(session_id)
        assert components.ok and components.data is not None, components.error
        assert components.data["activities"] == []
        native_libs = service.apk_native_libs(session_id)
        assert native_libs.ok and native_libs.data is not None, native_libs.error
        assert native_libs.data["count"] == 0

        # Full DEX analysis through the service: the assembled class, its
        # descriptors, the marker string and the intra-DEX call edge.
        classes = service.apk_classes(session_id)
        assert classes.ok and classes.data is not None, classes.error
        assert _CLASS_SMALI in classes.data["classes"], classes.data
        methods = service.apk_methods(session_id, _PACKAGE + ".Secret")
        assert methods.ok and methods.data is not None, methods.error
        assert methods.data["class_name"] == _CLASS_SMALI
        by_name = {m["name"]: m for m in methods.data["methods"]}
        assert by_name["mangle"]["descriptor"] == "(I)I", by_name
        strings = service.apk_strings(session_id)
        assert strings.ok and strings.data is not None, strings.error
        assert _MARKER in strings.data["strings"], strings.data["strings"][:20]
        xrefs = service.apk_xrefs(session_id, "mangle")
        assert xrefs.ok and xrefs.data is not None, xrefs.error
        callers = {(c["class"], c["method"]) for c in xrefs.data["callers"]}
        assert (_CLASS_SMALI, "reveal") in callers, xrefs.data

        # offset/limit are forwarded, not swallowed by the service signature:
        # a one-string window of the pool pages exactly as the backend does.
        total = int(strings.data["total"])
        assert total > 1, strings.data
        page = service.apk_strings(session_id, offset=1, limit=1)
        assert page.ok and page.data is not None, page.error
        assert page.data["count"] == 1 and page.data["offset"] == 1, page.data
        assert page.data["total"] == total and page.data["has_more"] is True
        assert page.data["strings"] == strings.data["strings"][1:2]
        tail = service.apk_strings(session_id, offset=total)
        assert tail.ok and tail.data is not None, tail.error
        assert tail.data["strings"] == [] and tail.data["has_more"] is False

        # ApkError codes cross _as_rpc intact on a valid APK. The RE gate's
        # broken fixture can only observe backend_error; these are the caller
        # mistakes an agent actually makes and has to be able to tell apart.
        missing = service.apk_methods(session_id, _PACKAGE + ".Missing")
        assert missing.ok is False and missing.error is not None
        assert missing.error.code == "not_found", missing.error
        blank = service.apk_xrefs(session_id, "   ")
        assert blank.ok is False and blank.error is not None
        assert blank.error.code == "invalid_params", blank.error

        # The DEX analysis above really is resident before close...
        with ApkClient._cache_lock:
            assert any(key[0] == resolved for key in ApkClient._full_cache)

        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        # ...and close released it via the real path in close_session, which
        # the unit tests only ever exercise with stub cache entries.
        with ApkClient._cache_lock:
            assert not any(key[0] == resolved for key in ApkClient._light_cache)
            assert not any(key[0] == resolved for key in ApkClient._full_cache)

        # A closed session answers with an envelope, never a crash.
        after = service.apk_open(session_id)
        assert after.ok is False and after.error is not None
        assert after.error.code in {"invalid_request", "session_not_found"}, after.error
    finally:
        service.close_all()
