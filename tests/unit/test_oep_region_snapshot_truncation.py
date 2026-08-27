"""Auto-collected OEP scoring must disclose a truncated memory-region snapshot.

``_collect_oep_observations_from_runtime`` reads a single page of
``memory.regions`` (offset 0, limit 512) and diffs it as the whole map. A
process with more mapped regions than that page hands the observation collector
a partial map, so a protect change -- or the region RIP sits in -- beyond the
page is not seen and the resulting (possibly empty) candidate set is not the
last word. ``memory.regions`` reports ``has_more``; these tests pin that
``unpack.score_oep`` carries that cut through as ``regions_truncated`` (with
``region_limit`` / ``region_total`` and a caveat note), and that an untruncated
snapshot is not flagged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.unit.test_dynamic_service import FakeDynamicWorker, _service, _write_minimal_pe

JsonObject = dict[str, Any]

_BASE = 0x140000000
_SIZE = 0x4000


class _TruncatedRegionWorker(FakeDynamicWorker):
    """Serves memory.regions with has_more=True, as a many-region process does."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "memory.regions":
            self.requests.append((command, params or {}))
            region = {
                "base": self.module_base,
                "allocation_base": self.module_base,
                "size": self.module_size,
                "protect": 0x20,
                "protect_name": "execute_read",
                "state": "commit",
                "type": "image",
                "info": self.module_name,
            }
            return {
                "regions": [region],
                "count": 1,
                "total": 999,
                "offset": int((params or {}).get("offset", 0)),
                "limit": int((params or {}).get("limit", 512)),
                "has_more": True,
            }
        return super().request(command, params, timeout=timeout)


def _paused_worker(worker: FakeDynamicWorker) -> FakeDynamicWorker:
    worker.current_state = {
        "debugging": True,
        "running": False,
        "state": "paused",
        "process_id": 7100,
        "thread_id": 7200,
    }
    return worker


def test_score_oep_discloses_truncated_region_snapshot(tmp_path: Path) -> None:
    binary = tmp_path / "many-regions.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, _paused_worker(_TruncatedRegionWorker()))
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    scored = service.unpack_score_oep(
        session_id,
        module_base=_BASE,
        module_size=_SIZE,
        observations=None,
    )
    assert scored.ok and scored.data is not None
    data = scored.data
    assert data["auto_collected"] is True
    assert data["regions_truncated"] is True
    assert data["region_limit"] == 512
    assert data["region_total"] == 999
    # The caveat must reach the note a reader actually sees.
    assert "truncated" in str(data.get("note", "")).lower()


def test_score_oep_untruncated_snapshot_is_not_flagged(tmp_path: Path) -> None:
    binary = tmp_path / "few-regions.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, _paused_worker(FakeDynamicWorker()))
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    scored = service.unpack_score_oep(
        session_id,
        module_base=_BASE,
        module_size=_SIZE,
        observations=None,
    )
    assert scored.ok and scored.data is not None
    data = scored.data
    assert data["auto_collected"] is True
    assert "regions_truncated" not in data
    assert "region_limit" not in data
    assert "truncated" not in str(data.get("note", "")).lower()


def test_explicit_observations_do_not_carry_region_truncation(tmp_path: Path) -> None:
    binary = tmp_path / "explicit.exe"
    _write_minimal_pe(binary)
    # Even a truncating worker is never consulted when observations are supplied.
    service = _service(tmp_path, _paused_worker(_TruncatedRegionWorker()))
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    scored = service.unpack_score_oep(
        session_id,
        module_base=_BASE,
        module_size=_SIZE,
        observations=[{"kind": "rip_in_main_module_code", "oep_rva": 0x1000}],
    )
    assert scored.ok and scored.data is not None
    assert scored.data["auto_collected"] is False
    assert "regions_truncated" not in scored.data
