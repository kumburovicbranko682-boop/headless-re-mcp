"""Cross-validate the APK prepended-data (container slack) fact against Info-ZIP.

describe_apk measures bytes glued on before the ZIP container starts -- the
Janus smuggling shape (CVE-2017-13156), where one file is both a DEX and a
signed APK -- by comparing the central directory's actual file position with
the offset the EOCD records. That arithmetic and its unit fixtures are both
ours, so nothing proved it against an independent ZIP implementation. Info-ZIP's
unzip performs the same reconciliation on open and prints the discrepancy as
"N extra bytes at beginning or within zipfile"; this gate requires the two
byte counts to agree exactly, on the pristine fixture (no warning, size 0) and
on a Janus-shaped copy (warning naming precisely the prepended count).

unzip ships with the CI runner image. skip != pass: the tests skip, naming the
missing piece, only when unzip or the committed fixture is absent.
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
