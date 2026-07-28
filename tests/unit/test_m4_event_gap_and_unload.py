"""M4.5: event-gap resync gate and module unload race around dump."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import FakeDynamicWorker


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    path.write_bytes(image)


def _gap_batch(cursor: int = 0) -> DebugEventBatch:
    return DebugEventBatch(
        events=(
            DebugEvent(
                sequence=cursor + 5,
                timestamp_unix_ms=1,
                source="x64dbg.plugin_callback",
                kind="debug.paused",
                data={},
            ),
        ),
        cursor=cursor,
        next_cursor=cursor + 5,
        oldest_sequence=cursor + 5,
        latest_sequence=cursor + 5,
        dropped=4,
        dropped_total=4,
        has_more=False,
        capacity=1024,
    )


def test_event_gap_blocks_dump_until_modules_list(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker(event_batches=[_gap_batch()])
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        ),
        dynamic_worker_factory=lambda session, cfg: worker,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    events = service.dynamic_events(session_id, limit=8)
    assert events.ok and events.data is not None
    assert events.data["dropped"] == 4

    blocked = service.modules_dump(session_id, worker.module_base, size=0x100)
    assert not blocked.ok and blocked.error is not None
    assert blocked.error.code == "event_gap_resync_required"

    blocked_iat = service.imports_scan(session_id, worker.module_base)
    assert not blocked_iat.ok and blocked_iat.error is not None
    assert blocked_iat.error.code == "event_gap_resync_required"

    catalog = service.dynamic_modules(session_id)
    assert catalog.ok

    dumped = service.modules_dump(session_id, worker.module_base, size=0x100)
    assert dumped.ok and dumped.data is not None
    assert Path(str(dumped.data["output_path"])).is_file()


class _UnloadAfterDumpWorker(FakeDynamicWorker):
    def __init__(self) -> None:
        super().__init__()
        self._dump_count = 0

    def request(self, command: str, params=None, *, timeout: float = 120.0):  # noqa: ANN001
        if command == "modules.list":
            self.requests.append((command, params or {}))
            if self._dump_count > 0:
                return {"modules": [], "count": 0}
            return super().request(command, params, timeout=timeout)
        if command == "modules.dump":
            self._dump_count += 1
            return super().request(command, params, timeout=timeout)
        return super().request(command, params, timeout=timeout)


def test_module_unloaded_during_dump_detected(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = _UnloadAfterDumpWorker()
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        ),
        dynamic_worker_factory=lambda session, cfg: worker,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    result = service.modules_dump(session_id, worker.module_base, size=0x100)
    assert not result.ok and result.error is not None
    assert result.error.code == "module_unloaded_during_dump"
    assert result.error.details.get("race") == "post_dump"
