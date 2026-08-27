"""Live Gate for the official UPX CLI unpack route on Linux.

The built-in detection gate proves the engine *recommends* the UPX route for a
packed sample; this gate proves that route actually works. The existing UPX
unpack coverage on ``main`` is bound to the Windows/x64dbg unpack session and
skips on Linux, so the pure-CLI adapter (``unpack.upx.test`` / ``unpack.upx.unpack``
/ ``unpack.auto``) had no integration coverage there at all.

Driven against a committed UPX-packed PE, this gate closes the whole
detect -> unpack -> verify-clean loop:

- ``upx -t`` validates the packed file and leaves it byte-for-byte unchanged.
- ``upx -d`` writes a *new* artifact (input untouched) that is a larger, valid
  PE of the same architecture, with the sections and imports UPX had folded
  away restored -- and re-classifying that output with the built-in engine now
  concludes ``none_detected``, i.e. it is no longer a packed file.
- ``unpack.auto`` reaches the ``verified`` phase for the ``upx`` route and
  registers an ``upx_unpacked`` artifact.

Guards stay honest: with no ``upx`` configured the surface degrades to
``capability_unavailable`` (not a fake success), and a closed session is
refused with ``invalid_request``. It skips only when no ``upx`` is available --
skip is never a pass. On the Linux reference machine ``upx`` is on ``PATH``
(official upx release).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_PACKED = _REPO / "fixtures" / "upx" / "console_fixture-x64.upx.exe"


def _resolve_upx() -> Path:
    configured = os.environ.get("HEADLESS_RE_UPX")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
    discovered = shutil.which("upx")
    if discovered:
        return Path(discovered).resolve()
    pytest.skip("no upx CLI on PATH or HEADLESS_RE_UPX; skip is not a pass")


def _settings(tmp_path: Path, *, upx: Path | None) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
        diec=None,
    )


def _require_fixture(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _open(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_upx_test_passes_and_leaves_the_input_unchanged(tmp_path: Path) -> None:
    upx = _resolve_upx()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, upx=upx))
    session_id = _open(service, _PACKED)

    before = _PACKED.read_bytes()
    result = service.unpack_upx_test(session_id, timeout=60.0)
    assert result.ok and result.data is not None, result.error
    upx_result = result.data["upx"]
    assert upx_result["ok"] is True
    assert upx_result["operation"] == "test"
    assert str(upx_result["version"])[0].isdigit()
    assert result.data["input_unchanged"] is True
    # `upx -t` inspects only; it must not produce an output artifact.
    assert upx_result["output_path"] is None
    assert _PACKED.read_bytes() == before

    service.close_session(session_id)


@pytest.mark.integration
def test_upx_unpack_restores_the_original_and_verifies_clean(tmp_path: Path) -> None:
    upx = _resolve_upx()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, upx=upx))
    session_id = _open(service, _PACKED)

    before = _PACKED.read_bytes()
    result = service.unpack_upx_unpack(session_id, timeout=60.0)
    assert result.ok and result.data is not None, result.error
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True
    assert _PACKED.read_bytes() == before, "unpack must not touch the input"

    comparison = result.data["comparison"]
    assert comparison["architecture_match"] is True
    assert comparison["input_sha256"] != comparison["output_sha256"]
    # UPX folds the real sections into UPX0/UPX1 and rebuilds a tiny import
    # table; unpacking restores both, so the output has strictly more.
    assert comparison["section_count"]["after"] > comparison["section_count"]["before"]
    assert (
        comparison["import_function_count"]["after"] > comparison["import_function_count"]["before"]
    )

    output = Path(result.data["output_path"])
    assert output.is_file()
    assert output.stat().st_size > _PACKED.stat().st_size

    # Close the loop: the unpacked artifact is no longer a packed file. Run the
    # built-in engine (use_die=False) on a fresh session over the output.
    child_id = _open(service, output)
    classified = service.packer_classify(child_id, use_die=False)
    assert classified.ok and classified.data is not None, classified.error
    assert classified.data["conclusion"] == "none_detected"
    assert classified.data["candidates"] == []

    scanned = service.detect_scan(child_id, use_die=False)
    assert scanned.ok and scanned.data is not None
    assert not [item for item in scanned.data["report"]["findings"] if item["category"] == "packer"]

    service.close_session(child_id)
    service.close_session(session_id)


@pytest.mark.integration
def test_unpack_auto_reaches_verified_for_the_upx_route(tmp_path: Path) -> None:
    upx = _resolve_upx()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, upx=upx))
    session_id = _open(service, _PACKED)

    result = service.unpack_auto(session_id, use_die=False, timeout=60.0)
    assert result.ok and result.data is not None, result.error
    assert result.data.get("status") == "unpacked"
    assert result.data["claims_universal_unpack"] is False
    unpack = result.data["unpack"]
    assert unpack["route"] == "upx"
    assert unpack["phase"] in {"verified", "reanalyzed"}
    artifact_kinds = [
        item.get("kind") for item in (unpack.get("artifacts") or []) if isinstance(item, dict)
    ]
    assert "upx_unpacked" in artifact_kinds

    service.close_session(session_id)


@pytest.mark.integration
def test_upx_degrades_to_capability_unavailable_when_unconfigured(tmp_path: Path) -> None:
    _require_fixture(_PACKED)
    # No upx configured (and the service does not fall back to PATH here): the
    # route must say capability_unavailable rather than claim it unpacked.
    service = AnalysisService(_settings(tmp_path, upx=None))
    session_id = _open(service, _PACKED)

    test_result = service.unpack_upx_test(session_id)
    assert test_result.ok is False and test_result.error is not None
    assert test_result.error.code == "capability_unavailable"

    unpack_result = service.unpack_upx_unpack(session_id)
    assert unpack_result.ok is False and unpack_result.error is not None
    assert unpack_result.error.code == "capability_unavailable"

    service.close_session(session_id)


@pytest.mark.integration
def test_upx_refuses_a_closed_session(tmp_path: Path) -> None:
    upx = _resolve_upx()
    _require_fixture(_PACKED)
    service = AnalysisService(_settings(tmp_path, upx=upx))
    session_id = _open(service, _PACKED)
    service.close_session(session_id)

    test_result = service.unpack_upx_test(session_id)
    assert test_result.ok is False and test_result.error is not None
    assert test_result.error.code == "invalid_request"

    unpack_result = service.unpack_upx_unpack(session_id)
    assert unpack_result.ok is False and unpack_result.error is not None
    assert unpack_result.error.code == "invalid_request"
