"""Android static line against a *real*, signed APK (skip != pass).

``test_android_re_gate.py`` builds a synthetic zip whose ``AndroidManifest.xml``
is not valid binary AXML, so androguard cannot actually parse it -- that gate
only proves the ``apk.*`` surface returns a structured envelope on garbage, not
that the androguard/apktool parse layer works on real bytes. This gate closes
that hole: it assembles a genuine, signed APK from the committed
``fixtures/android`` project (apktool ``b`` -> keytool -> apksigner) and then
drives the service's ``apk.*`` tools over it, asserting the *values* androguard
and apktool return -- package name, permissions, components, the real DEX class
and method, an embedded string, the signing certificate, and an apktool
decode/rebuild/re-sign round trip.

The build chain (apktool + keytool + apksigner, all needing a JRE) is optional:
absent any of them the gate skips with a reason rather than failing, exactly
like the other portable gates. The hosted ``linux-integration`` CI job installs
them so this runs for real on every push. jadx is not packaged for apt, so the
decompile leg skips unless jadx is configured (CI installs it best-effort).
"""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_DIR = _PROJECT_ROOT / "fixtures" / "android"
_PACKAGE = "com.example.fixture"
_MAIN_CLASS = "Lcom/example/fixture/MainActivity;"
_FLAG = "fixture-flag-1337"
_KS_PASSWORD = "fixturepass"  # noqa: S105 - throwaway keystore for a synthetic fixture
_KS_ALIAS = "fixturekey"


def _build_chain() -> tuple[str, str, str]:
    """Resolve apktool/keytool/apksigner or skip; androguard must be present too."""
    if not ApkClient().available:
        pytest.skip("androguard not installed — Android static Gate not run (skip != pass)")
    tools = {name: shutil.which(name) for name in ("apktool", "keytool", "apksigner")}
    missing = sorted(name for name, path in tools.items() if path is None)
    if missing:
        pytest.skip(
            f"missing {', '.join(missing)} (need a JRE + Android build tools) — "
            "Gate not run (skip != pass)"
        )
    return tools["apktool"], tools["keytool"], tools["apksigner"]  # type: ignore[return-value]


def _run_or_skip(cmd: list[str]) -> None:
    """Run a build step; a tool that cannot build the fixture skips, never fails.

    A broken local apktool/keytool must not turn "could not construct the
    fixture" into a false red -- that is a missing-capability skip, not a
    product defect. Real product behaviour is asserted only once the APK exists
    and the service parses it.
    """
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=180)  # noqa: S603
    if completed.returncode != 0:
        pytest.skip(
            f"{Path(cmd[0]).name} exited {completed.returncode}; fixture APK not built — "
            f"Gate not run (skip != pass):\n{completed.stderr[-800:]}"
        )


@dataclasses.dataclass(frozen=True)
class _Fixture:
    apk: Path
    keystore: Path


@pytest.fixture(scope="module")
def signed_apk(tmp_path_factory: pytest.TempPathFactory) -> _Fixture:
    apktool, keytool, apksigner = _build_chain()
    workdir = tmp_path_factory.mktemp("apkbuild")
    # apktool writes build/ intermediates into the project tree, so build from a
    # throwaway copy rather than the committed fixtures.
    project = workdir / "project"
    shutil.copytree(_FIXTURE_DIR, project)

    unsigned = workdir / "fixture-unsigned.apk"
    _run_or_skip([apktool, "b", str(project), "-o", str(unsigned)])

    keystore = workdir / "fixture.keystore"
    _run_or_skip(
        [
            keytool, "-genkeypair",
            "-keystore", str(keystore),
            "-alias", _KS_ALIAS,
            "-storepass", _KS_PASSWORD,
            "-keypass", _KS_PASSWORD,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "30",
            "-dname", "CN=Fixture Gate",
        ]
    )

    signed = workdir / "fixture-signed.apk"
    _run_or_skip(
        [
            apksigner, "sign",
            "--ks", str(keystore),
            "--ks-pass", f"pass:{_KS_PASSWORD}",
            "--ks-key-alias", _KS_ALIAS,
            "--key-pass", f"pass:{_KS_PASSWORD}",
            "--out", str(signed),
            str(unsigned),
        ]
    )
    if not signed.is_file():
        pytest.skip("apksigner produced no output — Gate not run (skip != pass)")
    return _Fixture(apk=signed, keystore=keystore)


@pytest.fixture()
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    settings = dataclasses.replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings=settings)
    try:
        yield svc
    finally:
        svc.close_all()


@pytest.mark.integration
def test_android_static_line_parses_real_apk(
    service: AnalysisService, signed_apk: _Fixture
) -> None:
    """androguard parses real bytes: manifest facts, components, DEX, certificate."""
    assert classify_target(signed_apk.apk) is TargetKind.APK

    created = service.create_session(str(signed_apk.apk))
    assert created.ok, created.error
    session_id = created.data["session"]["id"]

    opened = service.apk_open(session_id)
    assert opened.ok, opened.error
    assert opened.data["package"] == _PACKAGE
    assert opened.data["version_name"] == "1.0"
    assert opened.data["main_activity"] == f"{_PACKAGE}.MainActivity"
    assert opened.data["permission_count"] == 2

    manifest = service.apk_manifest(session_id)
    assert manifest.ok, manifest.error
    assert _PACKAGE in manifest.data["manifest_xml"]
    assert "android.permission.INTERNET" in manifest.data["manifest_xml"]

    permissions = service.apk_permissions(session_id)
    assert permissions.ok, permissions.error
    assert set(permissions.data["permissions"]) == {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    }

    components = service.apk_components(session_id)
    assert components.ok, components.error
    assert components.data["activities"] == [f"{_PACKAGE}.MainActivity"]
    assert components.data["main_activity"] == f"{_PACKAGE}.MainActivity"

    certificates = service.apk_certificates(session_id)
    assert certificates.ok, certificates.error
    assert certificates.data["v1_signed"] is True
    certs = certificates.data["certificates"]
    assert certs and "Fixture Gate" in certs[0]["subject"]
    assert len(certs[0]["sha256"].replace(" ", "")) == 64

    classes = service.apk_classes(session_id)
    assert classes.ok, classes.error
    assert _MAIN_CLASS in classes.data["classes"]

    methods = service.apk_methods(session_id, _MAIN_CLASS)
    assert methods.ok, methods.error
    names = {method["name"] for method in methods.data["methods"]}
    assert {"<init>", "secretCheck"} <= names

    strings = service.apk_strings(session_id, limit=2000)
    assert strings.ok, strings.error
    assert _FLAG in strings.data["strings"]

    # xrefs must answer with a bounded envelope even for a method nobody calls.
    xrefs = service.apk_xrefs(session_id, "secretCheck")
    assert xrefs.ok, xrefs.error
    assert isinstance(xrefs.data["callers"], list)


@pytest.mark.integration
def test_android_decode_repack_and_resign_roundtrip(
    service: AnalysisService, signed_apk: _Fixture
) -> None:
    """apktool decodes to smali, rebuilds a valid APK, and apksigner re-signs it."""
    created = service.create_session(str(signed_apk.apk))
    assert created.ok, created.error
    session_id = created.data["session"]["id"]

    decoded = service.apk_decode(session_id)
    assert decoded.ok, decoded.error
    assert decoded.data["smali_dirs"], "apktool must emit at least one smali dir"
    assert Path(decoded.data["manifest"]).is_file()

    repacked = service.apk_repack(session_id)
    assert repacked.ok, repacked.error
    assert repacked.data["signed"] is False
    assert repacked.data["size"] > 0
    rebuilt = Path(repacked.data["apk"])
    assert rebuilt.is_file()

    # apk.sign only accepts a keystore inside the session artifact tree, so copy
    # the fixture keystore next to the rebuilt APK before signing.
    keystore_in_tree = rebuilt.parent / "fixture.keystore"
    shutil.copy(signed_apk.keystore, keystore_in_tree)
    signed = service.apk_sign(
        session_id,
        keystore=str(keystore_in_tree),
        keystore_password=_KS_PASSWORD,
        key_alias=_KS_ALIAS,
    )
    # apk.sign runs apksigner verify internally, so ok is proof the rebuilt APK
    # was signed and verified for real, not just that a file was written.
    assert signed.ok, signed.error
    assert signed.data["signed"] is True
    assert Path(signed.data["apk"]).is_file()


@pytest.mark.integration
def test_android_decompile_with_jadx(
    service: AnalysisService, signed_apk: _Fixture
) -> None:
    """jadx decompiles the real DEX back to Java (skipped when jadx is absent)."""
    if getattr(service.settings, "jadx", None) is None:
        pytest.skip("jadx not configured (not on apt) — decompile Gate not run (skip != pass)")

    created = service.create_session(str(signed_apk.apk))
    assert created.ok, created.error
    session_id = created.data["session"]["id"]

    exported = service.apk_export_sources(session_id)
    assert exported.ok, exported.error
    assert exported.data["java_file_count"] >= 1

    decompiled = service.apk_decompile(session_id, _MAIN_CLASS)
    assert decompiled.ok, decompiled.error
    assert "secretCheck" in decompiled.data["source"]
