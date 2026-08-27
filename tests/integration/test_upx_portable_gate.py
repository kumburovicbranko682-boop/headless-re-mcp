"""UPX portable unpack gate: the unpack.upx.* tools run on Linux, no Windows.

The official-UPX route only ever ran under ``test_m5_unpack_live_gate.py``,
which needs a Windows ``upx.exe``, committed packed-PE fixtures and (for the
dynamic half) x64dbg -- so on Linux it skips and the ``unpack.upx.test`` /
``unpack.upx.unpack`` service tools never execute here, even though the UPX
adapter only shells out to ``upx -t`` / ``upx -d`` and is format-agnostic.

The service layer is still PE-bound (``session.require_pe`` + ``scan_pe`` diff),
so this mints a *real* PE on Linux with mingw-w64, packs it with the system UPX,
and drives the two tools against that session. The unpack assertion is the crux:
UPX collapses the import table into a loader stub, so a genuine ``upx -d`` must
restore far more imported functions than the packed input carried -- proof the
tool actually decompressed rather than copied. Skips honestly when UPX or
mingw-w64 is absent (skip != pass).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MARKER = "HEADLESS_RE_UPX_MARKER"
# The static padding gives UPX something worth compressing; without a compressible
# payload a tiny PE trips UPX's "NotCompressible" refusal. PADDING (not BLOB) --
# the latter collides with a windows.h typedef.
_C_SOURCE = textwrap.dedent(
    f"""
    #include <windows.h>
    #include <stdio.h>
    static const char *MARKER = "{_MARKER}";
    static const char PADDING[8192] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    __declspec(noinline) int pe_helper(int v) {{ return v * 3 + 1; }}
    int main(void) {{
        printf("%s %d %c\\n", MARKER, pe_helper((int) GetCurrentProcessId()), PADDING[0]);
        return 0;
    }}
    """
)


def _upx_executable() -> Path | None:
    found = shutil.which("upx") or shutil.which("upx-ucl")
    return Path(found) if found else None


def _build_packed_pe(dest_dir: Path) -> Path | None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    upx = _upx_executable()
    if compiler is None or upx is None:
        return None
    src = dest_dir / "upxfix.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    original = dest_dir / "upxfix.exe"
    if subprocess.run(
        [compiler, "-O2", "-o", str(original), str(src)], capture_output=True
    ).returncode != 0 or not original.is_file():
        return None
    packed = dest_dir / "upxfix-packed.exe"
    # upx -o writes a packed copy and leaves the original intact.
    if subprocess.run(
        [str(upx), "-o", str(packed), str(original)], capture_output=True
    ).returncode != 0 or not packed.is_file():
        return None
    return packed


@dataclass
class _Harness:
    service: AnalysisService
    session_id: str
    packed: Path
    packed_bytes: bytes


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Harness]:
    upx = _upx_executable()
    if upx is None:
        pytest.skip("upx (upx-ucl) not installed — UPX portable Gate not run (skip != pass)")
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        pytest.skip("mingw-w64 not installed — UPX portable Gate not run (skip != pass)")
    root = tmp_path_factory.mktemp("upxgate")
    packed = _build_packed_pe(root)
    if packed is None:
        pytest.skip("could not build/pack a PE fixture — UPX portable Gate not run (skip != pass)")
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=root / "artifacts",
        upx=upx,
        diec=None,
    )
    service = AnalysisService(settings)
    created = service.create_session(str(packed))
    assert created.ok, created.error
    session_id = str(created.data["session"]["id"])
    harness = _Harness(
        service=service,
        session_id=session_id,
        packed=packed,
        packed_bytes=packed.read_bytes(),
    )
    yield harness
    service.close_all()


@pytest.mark.integration
def test_upx_test_validates_the_packed_pe(_harness: _Harness) -> None:
    result = _harness.service.unpack_upx_test(_harness.session_id, timeout=60.0)
    assert result.ok, result.error
    upx = result.data["upx"]
    assert upx["ok"] is True
    assert upx["operation"] == "test"
    assert upx["returncode"] == 0
    # A real upx binary reports a version; the field is load-bearing for callers.
    assert re.match(r"^\d+\.\d+", str(upx.get("version") or "")), upx.get("version")
    assert result.data["input_unchanged"] is True


@pytest.mark.integration
def test_upx_unpack_restores_the_import_table(_harness: _Harness) -> None:
    result = _harness.service.unpack_upx_unpack(_harness.session_id, timeout=60.0)
    assert result.ok, result.error
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True

    output_path = Path(result.data["output_path"])
    assert output_path.is_file()

    comparison = result.data["comparison"]
    assert comparison["architecture_match"] is True
    # The crux: packing folds the IAT into a stub (a handful of imports), so a
    # real decompress restores many more -- a copy or a failed unpack could not.
    imports = comparison["import_function_count"]
    assert imports["after"] > imports["before"], comparison
    # Section table is likewise reconstructed from the two UPX sections.
    sections = comparison["section_count"]
    assert sections["after"] > sections["before"], comparison

    # The plaintext marker lives compressed inside the packed image and only
    # reappears once it is genuinely decompressed.
    unpacked_bytes = output_path.read_bytes()
    assert _MARKER.encode() in unpacked_bytes
    assert _MARKER.encode() not in _harness.packed_bytes


@pytest.mark.integration
def test_the_packed_input_is_never_mutated(_harness: _Harness) -> None:
    # Both tools promise never to touch the original; confirm byte-for-byte after
    # a test and an unpack have run against this session.
    assert _harness.packed.read_bytes() == _harness.packed_bytes
