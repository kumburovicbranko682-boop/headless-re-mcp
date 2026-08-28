"""Cross-validate the APK container-slack facts against independent parsers.

describe_apk measures data glued onto the container at either end. In front:
the Janus smuggling shape (CVE-2017-13156), where one file is both a DEX and a
signed APK, measured by comparing the central directory's actual position with
the offset the EOCD records -- refereed here against Info-ZIP's unzip, which
performs the same reconciliation and prints "N extra bytes at beginning or
within zipfile". Behind: a stash appended after the EOCD's declared comment
end -- refereed against apksigner, Android's own verifier, which rejects such
a file as "not a ZIP archive" while unzip and the stdlib silently read past
the stash. The appended gate closes the loop behaviorally: truncating exactly
the reader's byte count off the tail must restore apksigner's acceptance,
proving the measured boundary is the byte Android cares about.

unzip ships with the CI runner image; apksigner and keytool are installed by
the CI cross-check step. skip != pass: the tests skip, naming the missing
piece, only when a referee or the committed fixture is absent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"

# unzip: "warning [x.apk]:  100 extra bytes at beginning or within zipfile"
_UNZIP_EXTRA_RE = re.compile(r"warning \[[^\]]*\]:\s+(\d+) extra bytes at beginning")


def _unzip_extra_bytes(unzip: str, apk: Path) -> int:
    """The leading-slack byte count Info-ZIP reports for the archive (0 if none).

    unzip -t both surfaces the warning and test-extracts every member, so a
    zero also certifies the archive is otherwise readable end to end.
    """
    result = subprocess.run(
        [unzip, "-t", str(apk)], capture_output=True, text=True, timeout=120
    )
    output = result.stdout + result.stderr
    match = _UNZIP_EXTRA_RE.search(output)
    if match is None:
        assert result.returncode == 0, output
        return 0
    return int(match.group(1))


def _session_prepended_size(apk: Path) -> int | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["apk"]["prepended_size"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_prepended_size_agrees_with_unzip(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("unzip (Info-ZIP) not installed — container gate not run (skip != pass)")

    # The pristine fixture: both readers must call the container clean. This
    # also referees the fixture itself -- if the builder ever emitted an
    # archive with internal slack, Info-ZIP would flag it here.
    assert _unzip_extra_bytes(unzip, _FIXTURE) == 0
    assert _session_prepended_size(_FIXTURE) == 0

    # A Janus-shaped copy: a DEX-looking header, then the whole signed APK.
    # The reader and Info-ZIP must report the same byte count -- exactly the
    # length of what was glued on.
    smuggled = b"dex\n035\x00" + b"\xcc" * 121
    janus = tmp_path / "janus.apk"
    janus.write_bytes(smuggled + _FIXTURE.read_bytes())

    assert _unzip_extra_bytes(unzip, janus) == len(smuggled)
    assert _session_prepended_size(janus) == len(smuggled)


def _session_appended_size(apk: Path) -> int | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["apk"]["appended_size"]
    finally:
        service.close_all()


def _apksigner_accepts(apksigner: str, apk: Path) -> bool:
    result = subprocess.run(
        [apksigner, "verify", str(apk)], capture_output=True, text=True, timeout=120
    )
    return result.returncode == 0


def _v2_signed_copy(apksigner: str, keystore: Path, out: Path) -> None:
    result = subprocess.run(
        [
            apksigner, "sign",
            "--ks", str(keystore), "--ks-pass", "pass:android",
            "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
            "--out", str(out), str(_FIXTURE),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _debug_keystore(tmp_path: Path) -> Path | None:
    keytool = shutil.which("keytool")
    if keytool is None:
        return None
    keystore = tmp_path / "debug.keystore"
    result = subprocess.run(
        [
            keytool, "-genkeypair", "-alias", "androiddebugkey",
            "-keypass", "android", "-keystore", str(keystore),
            "-storepass", "android", "-dname", "CN=Android Debug,O=Android,C=US",
            "-validity", "10000", "-keyalg", "RSA", "-keysize", "2048",
        ],
        capture_output=True, timeout=120,
    )
    return keystore if result.returncode == 0 and keystore.is_file() else None


@pytest.mark.integration
def test_apk_appended_size_marks_the_boundary_android_enforces(tmp_path: Path) -> None:
    """The reader's appended byte count is exactly the boundary apksigner enforces.

    Android's parser requires the EOCD comment to reach EOF; unzip and the
    stdlib scan backwards and silently tolerate a stash. So the referee for
    the appended fact is behavioral: a v2-signed copy verifies, the same copy
    with a stash is rejected as malformed, and truncating precisely the
    reader's appended_size off the tail restores acceptance. If the reader
    measured one byte too many or too few, the restored file would still be
    rejected -- apksigner referees the count, not just the flag. unzip -t
    passing over the stashed copy pins down the asymmetry that makes the fact
    worth reporting.
    """
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    apksigner = shutil.which("apksigner")
    if apksigner is None:
        pytest.skip("apksigner not installed — appended-stash gate not run (skip != pass)")
    keystore = _debug_keystore(tmp_path)
    if keystore is None:
        pytest.skip("keytool not installed — appended-stash gate not run (skip != pass)")
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("unzip (Info-ZIP) not installed — appended-stash gate not run (skip != pass)")

    # A v2-signed copy: Android accepts it and the reader calls the tail clean.
    signed = tmp_path / "signed.apk"
    _v2_signed_copy(apksigner, keystore, signed)
    assert _apksigner_accepts(apksigner, signed)
    assert _session_appended_size(signed) == 0

    # The same archive with a stash glued on: Android rejects it as malformed,
    # Info-ZIP reads right past the stash without a word, and the reader
    # reports exactly the glued-on byte count.
    stash = b"loader-config-the-app-reads-back" * 2
    stashed = tmp_path / "stashed.apk"
    stashed.write_bytes(signed.read_bytes() + stash)
    assert not _apksigner_accepts(apksigner, stashed)
    assert subprocess.run(
        [unzip, "-t", str(stashed)], capture_output=True, timeout=120
    ).returncode == 0
    measured = _session_appended_size(stashed)
    assert measured == len(stash)

    # Behavioral closure: cutting exactly the measured bytes restores the file
    # Android accepts -- the reader found the precise boundary.
    restored = tmp_path / "restored.apk"
    stashed_bytes = stashed.read_bytes()
    restored.write_bytes(stashed_bytes[: len(stashed_bytes) - measured])
    assert _apksigner_accepts(apksigner, restored)
    assert _session_appended_size(restored) == 0
