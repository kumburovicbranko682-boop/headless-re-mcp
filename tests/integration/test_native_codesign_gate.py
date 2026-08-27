"""Mach-O code-signature gate: a real signer signs, the tool-free reader agrees.

describe_native now answers the macOS "who signed it" straight off
LC_CODE_SIGNATURE's SuperBlob: whether the image is signed at all, the signing
identifier, the team id, the ad-hoc flag, the digest algorithm and the SHA-256
of the CodeDirectory blob (what Apple's tooling derives the cdhash from). But
that parser and its unit fixtures are both ours, so nothing proved the walk of
a SuperBlob matches what a real code-signing implementation writes. rcodesign
(apple-codesign) is exactly that -- an independent, production signer and
verifier for the same structures -- and it runs on Linux, which Apple's own
codesign does not. This gate ad-hoc signs the committed fixture with rcodesign,
then requires the reader's facts to match what rcodesign itself prints for the
signature it just wrote: identifier for identifier, digest for digest -- the
Mach-O analogue of the Android gate cross-checking the APK signer certificate
digest against apksigner --print-certs. skip != pass when rcodesign is absent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
_IDENTIFIER = "com.example.minimal"

# rcodesign print-signature-info lists every blob of the SuperBlob with its
# own digests; the CodeDirectory entry's sha256 is the hash the reader must
# reproduce. The lazy match stops at that entry's first sha256 line (its sha1
# line precedes it), before any later blob.
_CD_SHA256_RE = re.compile(r"slot: CodeDirectory \(0\)\n.*?sha256: ([0-9a-f]{64})", re.S)
_IDENTIFIER_RE = re.compile(r"^\s*identifier: (\S+)$", re.M)
_FLAGS_RE = re.compile(r"^\s*flags: CodeSignatureFlags\(([^)]*)\)$", re.M)
_DIGEST_TYPE_RE = re.compile(r"^\s*digest_type: (\w+)$", re.M)


def _session_native(service: AnalysisService, binary: Path) -> dict[str, Any]:
    created = service.create_session(str(binary))
    assert created.ok, created.error
    session = created.data["session"]
    assert session["target"] == "native"
    return cast(dict[str, Any], session["metadata"]["native"])


@pytest.mark.integration
def test_macho_signature_facts_agree_with_rcodesign(tmp_path: Path) -> None:
    rcodesign = shutil.which("rcodesign")
    if rcodesign is None:
        pytest.skip("rcodesign not installed — codesign cross-check not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    signed_path = tmp_path / "signed.macho"
    result = subprocess.run(
        [
            rcodesign,
            "sign",
            "--binary-identifier",
            _IDENTIFIER,
            str(_MACHO_FIXTURE),
            str(signed_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr or result.stdout

    service = AnalysisService()
    try:
        # The committed fixture ships unsigned: the negative case is a real
        # binary with no LC_CODE_SIGNATURE, not a synthetic one.
        unsigned = _session_native(service, _MACHO_FIXTURE)
        assert unsigned["signed"] is False
        assert "signature" not in unsigned

        # The tool-free reader's view of the image rcodesign just signed.
        native = _session_native(service, signed_path)
        assert native["signed"] is True
        signature = native["signature"]
        # With no signing key given, rcodesign writes an ad-hoc signature:
        # a CodeDirectory but no certificate, so no team identity either.
        assert signature["ad_hoc"] is True
        assert signature["identifier"] == _IDENTIFIER
        assert signature["team_id"] is None

        # rcodesign's own decode of the signature it wrote is the ground
        # truth the reader must match fact for fact.
        info = subprocess.run(
            [rcodesign, "print-signature-info", str(signed_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert info.returncode == 0, info.stderr or info.stdout
        printed_identifier = _IDENTIFIER_RE.search(info.stdout)
        assert printed_identifier, info.stdout
        assert signature["identifier"] == printed_identifier.group(1)
        printed_flags = _FLAGS_RE.search(info.stdout)
        assert printed_flags, info.stdout
        assert signature["ad_hoc"] == ("ADHOC" in printed_flags.group(1))
        printed_digest_type = _DIGEST_TYPE_RE.search(info.stdout)
        assert printed_digest_type, info.stdout
        assert signature["hash_type"] == printed_digest_type.group(1)
        # The strongest check: the reader hashed the very same CodeDirectory
        # bytes rcodesign wrote and prints the digest of -- hex for hex.
        printed_cd = _CD_SHA256_RE.search(info.stdout)
        assert printed_cd, info.stdout
        assert signature["cd_sha256"] == printed_cd.group(1)
    finally:
        service.close_all()
