"""APK v1 signer-identity gate: apksigner referees the META-INF PKCS#7 walk.

The signers fact now names v1 (JAR) signers too: each META-INF/*.RSA member is
the same PKCS#7 SignedData an Authenticode signature wraps, and the SHA-256 of
the certificate its SignerInfo resolves to is the identity Android pins. That
DER walk and its unit fixtures are both ours, so apksigner -- the platform's
own signer and verifier -- referees it two ways:

* the committed fixture is v1-only signed (jarsigner wrote its FX.RSA years
  before this reader existed): apksigner verify --print-certs must print
  exactly the digest the session reports, on an artifact neither side built
  for the occasion;
* a fresh identity minted with keytool signs the fixture through apksigner
  itself with v1 and v2 both enabled: the session must report the *same*
  certificate digest under both schemes -- the v1 entry read from META-INF,
  the v2 entry read from the signing block, both equal to the SHA-256 of the
  DER keytool exported and to the digest apksigner prints. One certificate,
  three independent views, one number.

apksigner and the JDK's keytool come from the workflow's installs.
skip != pass: each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_APK_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

_SHA256_RE = re.compile(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})$", re.M)


def _session_apk(binary: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["apk"]
        assert isinstance(facts, dict)
        return facts
    finally:
        service.close_all()


def _apksigner_digests(apksigner: str, apk: Path, *extra: str) -> set[str]:
    result = subprocess.run(
        [apksigner, "verify", "--print-certs", "--min-sdk-version", "21", *extra, str(apk)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    digests = set(_SHA256_RE.findall(result.stdout))
    assert digests, result.stdout + result.stderr
    return digests


@pytest.mark.integration
def test_the_committed_fixtures_v1_signer_matches_apksigner(tmp_path: Path) -> None:
    apksigner = shutil.which("apksigner")
    if apksigner is None:
        pytest.skip("apksigner not installed — v1 signer gate not run (skip != pass)")
    if not _APK_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_APK_FIXTURE}")

    # v1-only: apksigner accepts it only for the pre-v2 SDK range, which is
    # exactly the population v1-only packages target.
    referee = _apksigner_digests(apksigner, _APK_FIXTURE, "--max-sdk-version", "23")

    facts = _session_apk(_APK_FIXTURE)
    assert facts["signed_v1"] is True
    assert (facts["signed_v2"], facts["signed_v3"]) == (False, False)
    v1_digests = {s["cert_sha256"] for s in facts["signers"] if s["scheme"] == "v1"}
    assert v1_digests == referee


@pytest.mark.integration
def test_a_fresh_identity_reads_the_same_under_v1_and_v2(tmp_path: Path) -> None:
    apksigner = shutil.which("apksigner")
    if apksigner is None:
        pytest.skip("apksigner not installed — v1 signer gate not run (skip != pass)")
    keytool = shutil.which("keytool")
    if keytool is None:
        pytest.skip("keytool (JDK) not installed — identity builder missing (skip != pass)")
    if not _APK_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_APK_FIXTURE}")

    keystore = tmp_path / "probe.jks"
    subprocess.run(
        [
            keytool, "-genkeypair", "-keystore", str(keystore), "-storepass", "probe123",
            "-keypass", "probe123", "-alias", "probe", "-dname", "CN=Probe V1 Signer",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "1",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    exported = tmp_path / "probe.der"
    subprocess.run(
        [
            keytool, "-exportcert", "-keystore", str(keystore), "-storepass", "probe123",
            "-alias", "probe", "-file", str(exported),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    minted = hashlib.sha256(exported.read_bytes()).hexdigest()

    unsigned = tmp_path / "in.apk"
    unsigned.write_bytes(_APK_FIXTURE.read_bytes())
    signed = tmp_path / "signed.apk"
    subprocess.run(
        [
            apksigner, "sign", "--ks", str(keystore), "--ks-pass", "pass:probe123",
            "--key-pass", "pass:probe123", "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true", "--v3-signing-enabled", "false",
            "--in", str(unsigned), "--out", str(signed),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    # apksigner accepts its own signature and prints the minted certificate.
    assert _apksigner_digests(apksigner, signed) == {minted}

    facts = _session_apk(signed)
    assert (facts["signed_v1"], facts["signed_v2"], facts["signed_v3"]) == (True, True, False)
    # One certificate, both schemes: the v1 entry read from META-INF's PKCS#7
    # and the v2 entry read from the signing block carry the same digest --
    # the SHA-256 of the DER keytool exported.
    assert facts["signers"] == [
        {"scheme": "v1", "cert_sha256": minted},
        {"scheme": "v2", "cert_sha256": minted},
    ]
