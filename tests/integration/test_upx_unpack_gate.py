"""UPX unpack gate: the official-CLI route on a real packed PE, on Linux.

The two existing unpack gates (``test_m5_unpack_live_gate.py`` /
``test_unpack_live_gate.py``) are x64dbg/headless-bound and skip everywhere but a
configured Windows box, so the UPX route -- which is just the official ``upx``
CLI and needs no debugger -- had no gate that runs on Linux. Its adapter had only
unit coverage.

This gate runs ``unpack.upx.test`` / ``unpack.upx.unpack`` / ``unpack.auto``
through ``AnalysisService`` against the committed, genuinely UPX-packed
``console_fixture-x64.upx.exe``. Every assertion checks a real unpack result, not
an envelope: the test passes with the original left byte-for-byte unchanged; the
unpack rebuilds the PE (the UPX0/UPX1 pair becomes the original sections again,
the collapsed import table is restored) and writes a distinct output; and --
closing the loop with the detection engine -- re-classifying that output finds no
packer, so the unpack genuinely removed the packing rather than merely producing
a file. ``unpack.auto`` drives the same route to the ``verified`` phase with a
``upx_unpacked`` artifact.

upx absent skips with "skip != pass" (``settings.upx`` auto-discovers ``upx`` on
PATH); the closed-session (``invalid_request``, checked before the backend) and
unconfigured (``capability_unavailable``) guards always run. Verified against
upx 4.2.2 on Linux.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PACKED = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.upx.exe"


def _upx_available() -> bool:
    return Settings.load().upx is not None


@pytest.mark.integration
def test_upx_unpacks_a_real_packed_pe() -> None:
    if not _upx_available():
        pytest.skip("official upx CLI not on PATH — UPX unpack Gate not run (skip != pass)")
    assert _PACKED.is_file(), f"fixture missing: {_PACKED}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_PACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        tested = service.unpack_upx_test(session_id)
        assert tested.ok, tested.error
        assert tested.data["upx"]["ok"] is True
        assert tested.data["upx"]["returncode"] == 0
        assert tested.data["upx"]["version"]
        assert tested.data["input_unchanged"] is True

        unpacked = service.unpack_upx_unpack(session_id)
        assert unpacked.ok, unpacked.error
        comparison = unpacked.data["comparison"]
        # A genuine unpack, not a copy: the architecture is preserved, but the
        # UPX0/UPX1 layout is replaced by the original sections and the collapsed
        # import table is restored, so both counts must grow.
        assert comparison["architecture_match"] is True
        assert comparison["section_count"]["after"] > comparison["section_count"]["before"]
        assert (
            comparison["import_function_count"]["after"]
            > comparison["import_function_count"]["before"]
        )
        assert comparison["output_sha256"] != comparison["input_sha256"]
        # The packed original must be left untouched, and the output must exist.
        assert unpacked.data["input_unchanged"] is True
        output_path = Path(unpacked.data["output_path"])
        assert output_path.is_file()

        # Close the loop with the detection engine: the unpacked output must no
        # longer look packed. This is what proves the unpack removed the packing,
        # not merely that upx wrote some bytes.
        child = service.create_session(str(output_path))
        assert child.ok, child.error
        reclassified = service.packer_classify(child.data["session"]["id"], use_die=False)
        assert reclassified.ok, reclassified.error
        assert reclassified.data["conclusion"] == "none_detected"
        assert reclassified.data["candidates"] == []
    finally:
        service.close_all()


@pytest.mark.integration
def test_upx_auto_route_reaches_verified() -> None:
    if not _upx_available():
        pytest.skip("official upx CLI not on PATH — UPX unpack Gate not run (skip != pass)")
    assert _PACKED.is_file(), f"fixture missing: {_PACKED}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_PACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        auto = service.unpack_auto(session_id, use_die=False)
        assert auto.ok, auto.error
        assert auto.data["status"] == "unpacked"
        unpack = auto.data["unpack"]
        assert unpack["route"] == "upx"
        assert unpack["phase"] == "verified"
        artifact_kinds = {a.get("kind") for a in unpack.get("artifacts", []) if isinstance(a, dict)}
        assert "upx_unpacked" in artifact_kinds, artifact_kinds
    finally:
        service.close_all()


@pytest.mark.integration
def test_upx_test_refuses_a_closed_session() -> None:
    """State is checked before the backend, so this runs without upx."""
    assert _PACKED.is_file(), f"fixture missing: {_PACKED}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_PACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        service.close_session(session_id)

        result = service.unpack_upx_test(session_id)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_upx_degrades_when_unconfigured() -> None:
    """With no upx configured, the tool reports capability_unavailable, not a crash."""
    assert _PACKED.is_file(), f"fixture missing: {_PACKED}"
    # Force upx off even on a box that has it, so this guard runs everywhere.
    settings = dataclasses.replace(Settings.load(), upx=None)
    service = AnalysisService(settings=settings)
    try:
        created = service.create_session(str(_PACKED))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.unpack_upx_test(session_id)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()
