"""unpack.score_oep must disclose when the candidate list was cut at the cap.

``score_oep_candidates`` keeps the highest-scoring ``max_candidates`` and drops
the rest. The service returned only ``candidate_count`` (the survivors), so a
caller reading it as "candidates found" read the top N of many as the whole
set -- the silent truncation every other listing in this project discloses with
a ``*_truncated`` / ``*_total`` / ``*_limit`` trio. These tests pin that the cut
is now reported both in the tool payload and in the persisted timeline, and that
an uncut result carries no such flags.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.session import UnpackPhase, create_unpack_session, transition
from tests.unit.test_m5_unpack_session import _write_pe

_BASE = 0x140000000
_SIZE = 0x4000

# Four distinct RVAs score at all; scoring by kind weight leaves a strict order.
_OBSERVATIONS = [
    {"kind": "rip_in_main_module_code", "oep_rva": 0x1000},
    {"kind": "write_to_execute", "oep_rva": 0x1100},
    {"kind": "ep_section_protect_changed", "oep_rva": 0x1200},
    {"kind": "new_executable_region", "oep_rva": 0x1300},
]


def _running_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    service._store_unpack_session(state)
    return service, session_id


def test_score_oep_discloses_the_cut(tmp_path: Path) -> None:
    service, session_id = _running_session(tmp_path)
    scored = service.unpack_score_oep(
        session_id,
        module_base=_BASE,
        module_size=_SIZE,
        observations=list(_OBSERVATIONS),
        max_candidates=2,
    )
    assert scored.ok and scored.data is not None
    data = scored.data
    # Only the survivors are returned, but the count is not the whole story.
    assert data["candidate_count"] == 2
    assert len(data["candidates"]) == 2
    assert data["candidates_truncated"] is True
    assert data["candidates_total"] == 4
    assert data["candidates_limit"] == 2


def test_score_oep_timeline_records_the_cut(tmp_path: Path) -> None:
    service, session_id = _running_session(tmp_path)
    scored = service.unpack_score_oep(
        session_id,
        module_base=_BASE,
        module_size=_SIZE,
        observations=list(_OBSERVATIONS),
        max_candidates=2,
    )
    assert scored.ok and scored.data is not None
    entries = scored.data["unpack"]["timeline"]
    scored_entry = next(e for e in entries if e["event"] == "oep_candidates_scored")
    details = scored_entry["details"]
    assert details["candidate_count"] == 2
    assert details["candidates_truncated"] is True
    assert details["candidates_total"] == 4
    assert details["candidates_limit"] == 2


def test_score_oep_without_a_cut_is_not_flagged(tmp_path: Path) -> None:
    service, session_id = _running_session(tmp_path)
    scored = service.unpack_score_oep(
        session_id,
        module_base=_BASE,
        module_size=_SIZE,
        observations=list(_OBSERVATIONS),
        max_candidates=8,
    )
    assert scored.ok and scored.data is not None
    data = scored.data
    assert data["candidate_count"] == 4
    assert "candidates_truncated" not in data
    assert "candidates_total" not in data
    assert "candidates_limit" not in data
    entries = data["unpack"]["timeline"]
    scored_entry = next(e for e in entries if e["event"] == "oep_candidates_scored")
    assert "candidates_truncated" not in scored_entry["details"]
