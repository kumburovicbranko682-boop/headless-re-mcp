"""Android static gate: androguard's real parse path on a committed APK.

The sibling ``test_android_re_gate`` builds a synthetic archive whose manifest
is not valid AXML, so it can only prove the backend *degrades* cleanly. Nothing
exercised androguard's happy path -- the package, versions, permissions,
components, certificate, and native ABIs a real capture depends on, nor the
full DEX analysis behind classes/methods/strings/xrefs -- so a regression in
that extraction would pass CI unseen. This gate consumes a committed, v1-signed
minimal APK carrying a real one-class DEX (see
fixtures/android/build_minimal_apk.py) and asserts the extracted facts. skip !=
pass: it skips only when androguard is not installed, and says so.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"
_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _exported_from_manifest_xml(xml_text: str) -> set[tuple[str, str]]:
    """The exported (type, name) set, computed off androguard's decoded XML.

    androguard renders the binary AXML to text XML independently of the stdlib
    reader; applying the export rule here (explicit android:exported wins,
    otherwise an <intent-filter> exports) over that tree is a second, tool-based
    decode of the same components -- so agreement proves the stdlib reader
    walked the AXML the way androguard did, name for name and flag for flag.
    """
    root = ET.fromstring(xml_text)
    app = root.find("application")
    exported: set[tuple[str, str]] = set()
    if app is None:
        return exported
    for element in list(app):
        if element.tag not in _COMPONENT_TAGS:
            continue
        name = element.get(f"{{{_ANDROID_NS}}}name")
        if not name:
            continue
        flag = element.get(f"{{{_ANDROID_NS}}}exported")
        has_filter = element.find("intent-filter") is not None
        is_exported = (flag == "true") if flag is not None else has_filter
        if is_exported:
            exported.add((element.tag, name))
    return exported


def _deep_links_from_manifest_xml(xml_text: str) -> set[tuple[str, str, str | None, str | None]]:
    """The (activity, scheme, host, pathPrefix) links off androguard's XML.

    The same rule the stdlib reader applies -- an activity/alias intent-filter
    carrying ACTION_VIEW, one record per <data> element that names a scheme --
    evaluated over androguard's independent render of the manifest, so the two
    decoders can be compared link for link.
    """
    root = ET.fromstring(xml_text)
    app = root.find("application")
    links: set[tuple[str, str, str | None, str | None]] = set()
    if app is None:
        return links
    for element in list(app):
        if element.tag not in ("activity", "activity-alias"):
            continue
        name = element.get(f"{{{_ANDROID_NS}}}name")
        if not name:
            continue
        for intent_filter in element.findall("intent-filter"):
            actions = {
                action.get(f"{{{_ANDROID_NS}}}name")
                for action in intent_filter.findall("action")
            }
            if "android.intent.action.VIEW" not in actions:
                continue
            for data in intent_filter.findall("data"):
                scheme = data.get(f"{{{_ANDROID_NS}}}scheme")
                if scheme:
                    links.add(
                        (
                            name,
                            scheme,
                            data.get(f"{{{_ANDROID_NS}}}host"),
                            data.get(f"{{{_ANDROID_NS}}}pathPrefix"),
                        )
                    )
    return links


@pytest.mark.integration
def test_android_apk_static_happy_path() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    assert classify_target(_FIXTURE) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session = created.data["session"]
        session_id = session["id"]
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True
        # Stdlib DEX header facts: the fixture's one-class, one-method DEX.
        assert meta["dex"]["versions"] == ["035"]
        assert meta["dex"]["class_count"] == 1
        assert meta["dex"]["method_count"] == 1

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        info = opened.data
        assert info["package"] == "com.example.headless"
        assert info["version_name"] == "1.0"
        assert info["version_code"] == "1"
        assert info["min_sdk"] == "21"
        assert info["target_sdk"] == "33"
        assert info["main_activity"] == "com.example.headless.MainActivity"
        assert info["permission_count"] == 1
        assert set(info["native_abis"]) == {"arm64-v8a", "x86_64"}

        # The stdlib AXML facts attached at session creation must agree with
        # androguard's parse -- the same package, versions, SDK levels and
        # permission read two independent ways (androguard reports the numeric
        # ones as strings, so compare with a cast).
        tool_free = meta["manifest"]
        assert tool_free["package"] == info["package"]
        assert str(tool_free["version_code"]) == info["version_code"]
        assert tool_free["version_name"] == info["version_name"]
        assert str(tool_free["min_sdk"]) == info["min_sdk"]
        assert str(tool_free["target_sdk"]) == info["target_sdk"]
        assert tool_free["permissions"] == ["android.permission.INTERNET"]
        # The launchable activity (entry point) the stdlib reader found from the
        # MAIN + LAUNCHER intent-filter must be the one androguard's own
        # get_main_activity resolves -- a second independent cross-check of the
        # entry-point fact, alongside the apktool gate's.
        assert tool_free["launcher_activity"] == info["main_activity"]
        # The <uses-library> dependency names the stdlib reader collected must
        # be exactly the set androguard's get_libraries resolves -- the second
        # independent decode of the manifest-level dependency list (the apktool
        # gate checks names and required flags against its text rendering).
        assert sorted(lib["name"] for lib in tool_free["uses_libraries"]) == info[
            "uses_libraries"
        ]
        assert info["uses_libraries"] == [
            "androidx.window.extensions",
            "org.apache.http.legacy",
        ]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.headless"
        assert "android.permission.INTERNET" in manifest.data["manifest_xml"]
        # The exported attack surface the stdlib reader found must be exactly
        # the set derived from androguard's own decode of the manifest -- the
        # implicit-via-filter launcher, the explicit-true service and provider,
        # with the explicit-false receiver (despite its filter) excluded.
        reader_surface = {
            (comp["type"], comp["name"]) for comp in tool_free["exported_components"]
        }
        assert reader_surface == _exported_from_manifest_xml(manifest.data["manifest_xml"])
        assert reader_surface == {
            ("activity", "com.example.headless.MainActivity"),
            ("service", "com.example.headless.ExportedService"),
            ("provider", "com.example.headless.SharedProvider"),
        }

        # The deep links -- the remotely-triggerable subset of that surface --
        # must match androguard's decode link for link: the https host with
        # its pathPrefix and the bare custom scheme, both on the launcher.
        reader_links = {
            (
                link["activity"],
                link["scheme"],
                link.get("host"),
                link.get("path_prefix"),
            )
            for link in tool_free["deep_links"]
        }
        assert reader_links == _deep_links_from_manifest_xml(manifest.data["manifest_xml"])
        assert reader_links == {
            (
                "com.example.headless.MainActivity",
                "https",
                "deeplink.example.com",
                "/open",
            ),
            ("com.example.headless.MainActivity", "headless", None, None),
        }

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert "android.permission.INTERNET" in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == ["com.example.headless.MainActivity"]
        assert components.data["services"] == ["com.example.headless.ExportedService"]
        assert components.data["receivers"] == ["com.example.headless.PrivateReceiver"]
        assert components.data["providers"] == ["com.example.headless.SharedProvider"]
        assert components.data["main_activity"] == "com.example.headless.MainActivity"

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is True
        assert len(certs.data["certificates"]) == 1
        assert certs.data["certificates"][0]["sha256"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apk_dex_analysis_happy_path() -> None:
    """androguard's full AnalyzeAPK path: the fixture carries a real one-class
    DEX, so classes/methods/strings/xrefs must return the analysed facts rather
    than a degradation envelope."""
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert "Lcom/example/headless/Sample;" in classes.data["classes"]

        # The stdlib DEX reader resolves the same defined class androguard does,
        # in dotted form (the descriptor Lcom/.../Sample; without its L...; wrap).
        tool_free = created.data["session"]["metadata"]["apk"]["dex"]["classes"]
        assert "com.example.headless.Sample" in tool_free

        methods = service.apk_methods(session_id, "com.example.headless.Sample")
        assert methods.ok, methods.error
        assert "getSecret" in [m["name"] for m in methods.data["methods"]]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert any("flag{headless-re}" in s for s in strings.data["strings"])

        # getSecret has no callers in this one-method DEX: the enumeration must
        # complete and say so, not error and not claim a phantom caller.
        xrefs = service.apk_xrefs(session_id, "getSecret")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["count"] == 0
        assert xrefs.data["has_more"] is False
    finally:
        service.close_all()
