"""Cross-validate the APK high-entropy member census against unzip and radare2.

describe_apk now flags members whose *decompressed* bytes measure near-random
with no magic to explain them -- the Android packer shape (an AES-encrypted
classes.dex parked under assets/) the embedded-payload census cannot see,
because an encrypted payload opens with no magic at all. Both halves of the
pipeline are ours -- zipfile decompression and the Shannon measure -- so the
gate rebuilds the whole answer through an independent pipeline: Info-ZIP's
``unzip`` extracts the members, radare2's ``ph entropy`` measures the
extracted bytes, and the referee numbers are pushed through the census's own
published contract (skip the canonical homes, META-INF/ and self-declaring
magic; flag at or past 7.2 bits per byte for members of 256 bytes or more,
rounded to two decimals). The flag lists must match record for record.

The planted archive also carries a PNG-magic member with the same random tail
as the flagged blob: radare2 confirms it *is* near-random, and the census must
still skip it -- proving the media-magic skip is the published rule at work,
not a missed measurement. The committed fixture is the real-world negative:
an empty census must be the shared answer.

unzip ships with the CI runner; radare2 comes from the workflow's r2 deb.
skip != pass: each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

# The census's published contract, restated here as the referee's rules.
_THRESHOLD = 7.2
_MIN_SIZE = 256
_CANONICAL_DEX_RE = re.compile(r"classes\d*\.dex")
# Magic that already explains near-random bytes: executables and containers
# (the embedded-payload census's beat) plus compressed media and fonts.
_SELF_DECLARING = (
    b"dex\n",
    b"\x7fELF",
    b"PK\x03\x04",
    b"MZ",
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"RIFF",
    b"OggS",
    b"ID3",
    b"\x1f\x8b",
    b"wOFF",
    b"wOF2",
    b"\x28\xb5\x2f\xfd",
)


def _session_flags(apk: Path) -> tuple[list[dict[str, Any]], int]:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        facts = created.data["session"]["metadata"]["apk"]
        return facts["high_entropy_members"], facts["high_entropy_member_count"]
    finally:
        service.close_all()


def _unzip_all(unzip: str, apk: Path, into: Path) -> None:
    result = subprocess.run(
        [unzip, "-o", "-qq", str(apk), "-d", str(into)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    # Info-ZIP exits 1 for warnings (e.g. trailing bytes) while extracting
    # fine; anything past that is a real failure.
    assert result.returncode <= 1, result.stderr


def _r2_entropy(r2: str, extracted: Path) -> float:
    """radare2's whole-file Shannon measure -- the referee's number."""
    size = extracted.stat().st_size
    result = subprocess.run(
        [r2, "-q", "-n", "-c", f"b {size}; ph entropy", str(extracted)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return float(result.stdout.strip())


def _referee_flags(unzip: str, r2: str, apk: Path, scratch: Path) -> list[dict[str, Any]]:
    """The census rebuilt through unzip + radare2, rule for rule."""
    _unzip_all(unzip, apk, scratch)
    flags: list[dict[str, Any]] = []
    with zipfile.ZipFile(apk) as archive:
        members = [info.filename for info in archive.infolist() if not info.is_dir()]
    for name in members:
        extracted = scratch / name
        if not extracted.is_file() or extracted.stat().st_size < _MIN_SIZE:
            continue
        if _CANONICAL_DEX_RE.fullmatch(name):
            continue
        if name.startswith("lib/") and name.endswith(".so"):
            continue
        if name.startswith("META-INF/"):
            continue
        with extracted.open("rb") as handle:
            head = handle.read(0x40)
        if any(head.startswith(magic) for magic in _SELF_DECLARING) or head[4:8] == b"ftyp":
            continue
        entropy = _r2_entropy(r2, extracted)
        if entropy >= _THRESHOLD:
            flags.append(
                {"path": name, "entropy": round(entropy, 2), "size": extracted.stat().st_size}
            )
    return flags


@pytest.mark.integration
def test_a_planted_opaque_blob_measures_like_radare2_after_unzip(tmp_path: Path) -> None:
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("unzip not installed — APK entropy gate not run (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — APK entropy gate not run (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE} — APK entropy gate not run (skip != pass)")

    # A real deflate stream is what a packer actually parks on disk; the PNG
    # decoy carries the same random tail but declares itself in its magic.
    corpus = " ".join(f"record {i} value {i * i}" for i in range(20000)).encode()
    blob = zlib.compress(corpus, level=9)
    apk = tmp_path / "planted.apk"
    apk.write_bytes(_FIXTURE.read_bytes())
    with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/opaque.bin", blob)
        archive.writestr("res/drawable/decoy.png", b"\x89PNG\r\n\x1a\n" + blob)
        archive.writestr("assets/strings.txt", b"the quick brown fox " * 200)

    flags, count = _session_flags(apk)
    assert count == 1
    assert [flag["path"] for flag in flags] == ["assets/opaque.bin"]
    assert flags[0]["entropy"] >= _THRESHOLD

    scratch = tmp_path / "unzipped"
    assert flags == _referee_flags(unzip, r2, apk, scratch)
    # The decoy is genuinely near-random -- radare2 says so over the same
    # bytes -- and the census still skips it: the media-magic rule at work,
    # not a missed measurement.
    assert _r2_entropy(r2, scratch / "res/drawable/decoy.png") >= _THRESHOLD


@pytest.mark.integration
def test_the_committed_fixture_is_clean_for_both(tmp_path: Path) -> None:
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("unzip not installed — APK entropy gate not run (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — APK entropy gate not run (skip != pass)")
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE} — APK entropy gate not run (skip != pass)")

    flags, count = _session_flags(_FIXTURE)
    assert flags == []
    assert count == 0
    # A real, unpacked APK: the empty census must be the shared answer.
    assert _referee_flags(unzip, r2, _FIXTURE, tmp_path / "unzipped") == []
