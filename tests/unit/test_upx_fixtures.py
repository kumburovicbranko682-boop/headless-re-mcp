"""Real official-UPX fixture unpack tests (skipped when UPX is unavailable)."""

from __future__ import annotations

import os
import shutil
from contextlib import suppress
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.pe import scan_pe

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "fixtures" / "upx"
UPX_ENV = os.environ.get("HEADLESS_RE_UPX")
# Mirror config.py's resolver: an explicit env/pinned build first, then any
# upx on PATH. Without the PATH probe these real fixture tests skipped on a box
# that had upx-ucl installed -- a skip that meant "resolver too narrow", not
# "tool absent", which is exactly the skip != pass trap the suite guards against.
_WHICH_UPX = shutil.which("upx")
UPX_CANDIDATES = [
    Path(UPX_ENV) if UPX_ENV else None,
    REPO / "artifacts" / "tools" / "upx-5.2.0" / "upx.exe",
    Path(_WHICH_UPX) if _WHICH_UPX else None,
]


def _upx_exe() -> Path | None:
    for candidate in UPX_CANDIDATES:
        if candidate is not None and candidate.is_file():
            return candidate
    return None


def _settings(tmp_path: Path, upx: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
        diec=None,
    )


@pytest.mark.parametrize(
    "arch",
    [
        pytest.param("x86", id="x86"),
        pytest.param("x64", id="x64"),
    ],
)
def test_official_upx_fixture_unpack_auto(tmp_path: Path, arch: str) -> None:
    upx = _upx_exe()
    if upx is None:
        pytest.skip("official UPX CLI not configured")
    packed = FIXTURES / f"console_fixture-{arch}.upx.exe"
    if not packed.is_file():
        pytest.skip(f"missing UPX fixture: {packed}")

    before_sha = packed.read_bytes()
    service = AnalysisService(_settings(tmp_path, upx))
    created = service.create_session(str(packed))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    auto = service.unpack_auto(session_id, use_die=False, open_ida=False)
    assert auto.ok and auto.data is not None, auto.error
    assert auto.data["status"] == "unpacked"
    assert packed.read_bytes() == before_sha

    output = Path(str(auto.data["unpack"]["output_path"]))
    assert output.is_file()
    artifact_root = (tmp_path / "artifacts").resolve()
    assert (artifact_root / "unpack" / session_id) in output.resolve().parents or (
        output.resolve().parent == artifact_root / "unpack" / session_id
    )
    pe = scan_pe(output)
    assert pe.architecture == arch
    assert pe.format == "PE"
    names = {section.name for section in pe.pe.sections}
    assert names


def _diec_exe() -> Path | None:
    env = os.environ.get("HEADLESS_RE_DIEC")
    candidates = [
        Path(env) if env else None,
        REPO / "artifacts" / "tools" / "die_win64_portable_3.21_x64" / "die" / "diec.exe",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    return None


def test_official_upx_fixture_die_rescan(tmp_path: Path) -> None:
    upx = _upx_exe()
    if upx is None:
        pytest.skip("official UPX CLI not configured")
    diec = _diec_exe()
    if diec is None:
        pytest.skip("diec not configured")
    packed = FIXTURES / "console_fixture-x64.upx.exe"
    if not packed.is_file():
        pytest.skip(f"missing UPX fixture: {packed}")

    before_sha = packed.read_bytes()
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
        diec=diec,
    )
    service = AnalysisService(settings)
    created = service.create_session(str(packed))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    unpacked = service.unpack_upx_unpack(session_id, open_ida=False)
    assert unpacked.ok and unpacked.data is not None, unpacked.error
    assert packed.read_bytes() == before_sha
    die_rescan = unpacked.data.get("die_rescan")
    assert isinstance(die_rescan, dict)
    assert die_rescan.get("status") == "completed"
    assert isinstance(die_rescan.get("finding_count"), int)
    assert unpacked.data.get("claims_universal_unpack") is False
    assert unpacked.data.get("input_unchanged") is True
    # unpack_upx_unpack envelope does not claim universal unpack success
    upx_payload = unpacked.data.get("upx")
    if isinstance(upx_payload, dict):
        assert upx_payload.get("claims_universal_unpack", False) is False


def test_official_upx_fixture_open_ida_reanalyze(tmp_path: Path) -> None:
    upx = _upx_exe()
    if upx is None:
        pytest.skip("official UPX CLI not configured")
    ida_home = os.environ.get("HEADLESS_RE_IDA_HOME")
    if not ida_home or not Path(ida_home).is_dir():
        pytest.skip("IDA home is not configured")
    packed = FIXTURES / "console_fixture-x64.upx.exe"
    if not packed.is_file():
        pytest.skip(f"missing UPX fixture: {packed}")

    before_sha = packed.read_bytes()
    settings = Settings(
        ida_home=Path(ida_home),
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
        diec=None,
    )
    service = AnalysisService(settings)
    created = service.create_session(str(packed))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    unpacked = service.unpack_upx_unpack(session_id, open_ida=True)
    assert unpacked.ok and unpacked.data is not None, unpacked.error
    assert packed.read_bytes() == before_sha
    reanalyze = unpacked.data.get("reanalyze")
    assert isinstance(reanalyze, dict)
    assert reanalyze.get("static_open_ok") is True
    with suppress(Exception):
        service.close_all()
