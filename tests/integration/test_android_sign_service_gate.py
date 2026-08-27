"""Android service gate: apk.sign, the last untested apk.* service endpoint.

The android sign gate drives ApktoolClient.sign directly; the service endpoint
wrapping it (apk.sign) is exercised only by unit tests with mocked clients. The
service adds real behaviour on top of the client that mocks cannot prove:

- it chains its own outputs -- apk.repack writes ``<root>/repacked.apk`` and
  apk.sign with no apk_path picks exactly that up, signing to
  ``<root>/signed.apk``,
- both apk_path and keystore must stay inside the session artifact tree
  (_require_session_path); a keystore or source outside it is refused
  invalid_params *before* apksigner is ever spawned -- a real security
  boundary, previously proven only against mocks,
- a successful sign lands on the session timeline,
- ApkError/ApktoolError codes cross _as_rpc intact (missing credentials for a
  custom keystore is invalid_params, not backend_error),
- close_session reclaims the apktool work tree, and a later apk.sign answers
  with a structured envelope.

Two tiers of honesty. The containment/contract checks refuse before any tool
runs, so they use a synthetic APK and need no external tool at all -- they
always run. The positive sign flow assembles a real APK (apktool), makes a
keystore inside the session tree (keytool), signs through the service, and
verifies the artifact independently with `apksigner verify`; it skips when
apktool, apksigner or keytool is missing. skip != pass.
"""

from __future__ import annotations

import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.headlessre.gate"
_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
# The MetaInfo header is what apktool build reads back; a framework-free
# manifest keeps its bundled aapt2 from needing an installed android.jar.
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"


def _settings(tmp_path: Path) -> Settings:
    return replace(Settings.load(), artifact_root=tmp_path / "artifacts")


def _synthetic_apk(path: Path) -> Path:
    """A stdlib-classifiable APK: enough for a session, no androguard needed."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
    return path


def _build_real_apk(client: ApktoolClient, tmp_path: Path) -> Path:
    skeleton = tmp_path / "skeleton"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    out = tmp_path / "out.apk"
    built = client.build(skeleton, out)
    assert Path(built["apk"]).is_file()
    return out


def _make_keystore(dest: Path) -> Path | None:
    """A throwaway RSA keystore via keytool, or None when keytool is absent."""
    import shutil

    keytool = shutil.which("keytool")
    if keytool is None:
        return None
    keystore = dest / "gate.keystore"
    try:
        subprocess.run(
            [
                keytool,
                "-genkeypair",
                "-keystore",
                str(keystore),
                "-storepass",
                "gatepass",
                "-keypass",
                "gatepass",
                "-alias",
                "gatekey",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "365",
                "-dname",
                "CN=gate,O=test,C=US",
            ],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return keystore if keystore.is_file() else None


@pytest.mark.integration
def test_android_apk_sign_service_containment_and_contracts(tmp_path: Path) -> None:
    """Refused-before-tool checks: no external tool needed, so this always runs."""
    settings = _settings(tmp_path)
    apk = _synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])

        # A keystore outside the session artifact tree is refused as
        # invalid_params before apksigner is spawned. The path need not exist:
        # the containment check is a boundary, not a file probe.
        outside_ks = service.apk_sign(
            session_id,
            keystore=str(tmp_path / "outside.keystore"),
            keystore_password="x",
            key_alias="y",
        )
        assert outside_ks.ok is False and outside_ks.error is not None
        assert outside_ks.error.code == "invalid_params", outside_ks.error

        # Same boundary on the source apk_path argument.
        outside_src = service.apk_sign(session_id, apk_path=str(tmp_path / "elsewhere.apk"))
        assert outside_src.ok is False and outside_src.error is not None
        assert outside_src.error.code == "invalid_params", outside_src.error

        # A closed session answers with an envelope, never a crash.
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        after = service.apk_sign(session_id)
        assert after.ok is False and after.error is not None
        assert after.error.code in {"invalid_request", "session_not_found"}, after.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apk_sign_service_signs_the_repacked_apk(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    if not apktool.signer_available or settings.apksigner is None:
        pytest.skip("apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — skip != pass")

    apk = _build_real_apk(apktool, tmp_path)
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])
        session_tree = settings.artifact_root.expanduser().resolve() / "apktool" / session_id

        # Decode then repack so the service produces its own <root>/repacked.apk,
        # which apk.sign will pick up as its default source.
        decoded = service.apk_decode(session_id)
        assert decoded.ok, decoded.error
        repacked = service.apk_repack(session_id)
        assert repacked.ok and repacked.data is not None, repacked.error
        assert Path(str(repacked.data["apk"])).resolve() == session_tree / "repacked.apk"

        # The keystore must live inside the session tree; put it there (keytool).
        keystore = _make_keystore(session_tree)
        if keystore is None:
            pytest.skip("no keytool (JDK) to make a keystore — skip != pass")

        # No apk_path: the service defaults to the repacked.apk it just built,
        # signing to <root>/signed.apk.
        signed = service.apk_sign(
            session_id,
            keystore=str(keystore),
            keystore_password="gatepass",
            key_alias="gatekey",
        )
        assert signed.ok and signed.data is not None, signed.error
        assert signed.data["signed"] is True, signed.data
        assert signed.data["debug_keystore"] is False, signed.data
        assert signed.data["keystore"] == str(keystore), signed.data
        signed_apk = Path(str(signed.data["apk"])).resolve()
        assert signed_apk == session_tree / "signed.apk"
        assert signed_apk.is_file() and signed_apk.stat().st_size > 0

        # Independent proof: apksigner verify accepts the artifact.
        verify = subprocess.run(
            [str(settings.apksigner), "verify", "--verbose", str(signed_apk)],
            capture_output=True,
            timeout=60.0,
        )
        assert verify.returncode == 0, verify.stderr.decode("utf-8", "replace")[:400]
        assert "Number of signers: 1" in verify.stdout.decode("utf-8", "replace")

        # The success is on the session timeline.
        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None, timeline.error
        events = {entry.get("event") for entry in timeline.data["events"]}
        assert "apk.sign" in events, events

        # A custom keystore inside the tree but with no credentials is
        # invalid_params through _as_rpc, not backend_error.
        no_creds = service.apk_sign(session_id, keystore=str(keystore))
        assert no_creds.ok is False and no_creds.error is not None
        assert no_creds.error.code == "invalid_params", no_creds.error

        # Close reclaims the apktool work tree; later calls stay structured.
        assert session_tree.is_dir()
        assert service.close_session(session_id).ok
        assert not session_tree.exists(), session_tree
        after = service.apk_sign(session_id, keystore=str(keystore))
        assert after.ok is False and after.error is not None
        assert after.error.code in {"invalid_request", "session_not_found"}, after.error
    finally:
        service.close_all()
