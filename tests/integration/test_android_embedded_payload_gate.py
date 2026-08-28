"""Cross-validate the APK embedded-payload census against file(1) and androguard.

describe_apk lists members whose bytes open with executable/container magic
while living outside their canonical home -- a DEX under assets/ (a runtime
DexClassLoader's stage two), a raw ELF shipped as data, a nested APK for later
install. The magic table and the "canonical home" rule are both ours, so two
independent referees check them over a planted archive:

* androguard opens the same APK and hands back each member's raw bytes through
  its own ZIP path (get_file) -- so the bytes the reader sniffed are the bytes
  a real Android tool sees, not a re-read of our own zipfile call;
* libmagic (file --brief) classifies those bytes independently: every member
  the reader flags must be the Dalvik dex / ELF / Android-package libmagic
  says it is, and the flag's kind must match libmagic's family.

The census must then name exactly the planted stowaways and skip the canonical
homes (classes*.dex at the root, lib/<abi>/*.so), which carry their own facts.

skip != pass: the gate skips, naming the missing piece, only when androguard,
file(1), or the committed fixture is absent.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

# libmagic's --brief description for each sniff kind (matched case-insensitively
# as a substring, so version suffixes like "version 035" do not matter).
_LIBMAGIC_DESCRIBES = {
    "dex": "dalvik dex",
    "elf": "elf ",
    "zip": ("android package", "zip archive"),
}


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _session_payloads(apk: Path) -> tuple[list[dict], int]:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["apk"]
        return facts["embedded_payloads"], facts["embedded_payload_count"]
    finally:
        service.close_all()


def _androguard_member(apk: Path, name: str) -> bytes:
    from loguru import logger

    logger.remove()
    from androguard.core.apk import APK

    return APK(str(apk)).get_file(name)


def _libmagic_describe(file_bin: str, data: bytes, scratch: Path) -> str:
    scratch.write_bytes(data)
    result = subprocess.run(
        [file_bin, "--brief", str(scratch)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip().lower()


def _plant(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A fixture copy with real stage-two payloads and canonical decoys.

    Returns the archive and the expected {member: kind} census -- built from
    the fixture's *own* real DEX and .so bytes so libmagic sees genuine
    formats, not stubs.
    """
    with zipfile.ZipFile(_FIXTURE) as archive:
        real_dex = archive.read("classes.dex")
        real_so = next(
            archive.read(n)
            for n in archive.namelist()
            if n.startswith("lib/") and n.endswith(".so")
        )
    planted = tmp_path / "planted.apk"
    shutil.copy(_FIXTURE, planted)
    with zipfile.ZipFile(planted, "a") as archive:
        # Stowaways outside canonical homes: must be listed.
        archive.writestr("assets/second_stage.bin", real_dex)
        archive.writestr("assets/native_blob.dat", real_so)
        archive.writestr("assets/inner.apk", _FIXTURE.read_bytes())
        # Canonical decoys: real formats in their proper homes, never listed.
        archive.writestr("classes2.dex", real_dex)
        archive.writestr("lib/armeabi-v7a/libdecoy.so", real_so)
    expected = {
        "assets/second_stage.bin": "dex",
        "assets/native_blob.dat": "elf",
        "assets/inner.apk": "zip",
    }
    return planted, expected


@pytest.mark.integration
def test_embedded_payload_census_agrees_with_file_and_androguard(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    file_bin = shutil.which("file")
    if file_bin is None:
        pytest.skip("file(1) not installed — embedded-payload gate not run (skip != pass)")
    if not _androguard_available():
        pytest.skip("androguard not installed — embedded-payload gate not run (skip != pass)")

    # The pristine fixture: no stowaways, and this also referees the fixture --
    # if the builder ever shipped a stray executable asset, it would show here.
    _pristine_list, pristine_count = _session_payloads(_FIXTURE)
    assert pristine_count == 0

    planted, expected = _plant(tmp_path)
    payloads, count = _session_payloads(planted)
    census = {entry["path"]: entry["kind"] for entry in payloads}

    # The census names exactly the stowaways -- the canonical homes
    # (classes2.dex, lib/armeabi-v7a/libdecoy.so) are absent.
    assert census == expected
    assert count == len(expected)

    # Each flagged member, refereed twice: androguard hands back the bytes, and
    # libmagic classifies them into the family the reader's kind claims.
    for member, kind in expected.items():
        raw = _androguard_member(planted, member)
        assert raw, f"androguard returned no bytes for {member}"
        description = _libmagic_describe(file_bin, raw, tmp_path / "scratch.bin")
        wanted = _LIBMAGIC_DESCRIBES[kind]
        needles = (wanted,) if isinstance(wanted, str) else wanted
        assert any(n in description for n in needles), (member, kind, description)

    # And the canonical decoys really are the same real formats -- proving they
    # were skipped for their location, not because their bytes were inert.
    decoy_dex = _libmagic_describe(file_bin, _androguard_member(planted, "classes2.dex"),
                                   tmp_path / "scratch.bin")
    assert "dalvik dex" in decoy_dex
    assert "classes2.dex" not in census
    assert "lib/armeabi-v7a/libdecoy.so" not in census
