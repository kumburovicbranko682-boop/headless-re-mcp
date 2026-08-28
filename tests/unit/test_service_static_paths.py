"""Edge-path coverage for the static surface split out of AnalysisService.

The mainline flows (list/paginate, write-and-record, oversized spills) are
pinned by test_static_write_service; this file covers the arms those tests
never reach -- optional search bounds, base64 patch payloads, malformed batch
result shapes, and the disclosure fields written when the timeline, the spill
file, or the artifact registration fails after the underlying operation
already succeeded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_static as service_static
import headless_re_mcp.core.store.timeline as timeline_mod
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import FakeStaticWorker, _create, _write_minimal_pe


class _EchoStaticWorker(FakeStaticWorker):
    """Records every request and answers from a per-command response table."""

    def __init__(self, responses: dict[str, JsonObject] | None = None) -> None:
        self.calls: list[tuple[str, JsonObject]] = []
        self.responses = dict(responses or {})

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
                "static.search.bytes",
                "static.search.text",
                "static.search.immediate",
                "static.bytes.patch",
                "static.batch",
                "static.decompile",
                "static.disassemble",
                "static.name.set",
            }
        )

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        del timeout
        values = dict(params or {})
        self.calls.append((command, values))
        if command in self.responses:
            return dict(self.responses[command])
        return {"items": [], "total": 0}


def _open_static(
    tmp_path: Path,
    worker: _EchoStaticWorker,
) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    settings = Settings(
        ida_home=tmp_path / "fake-ida",
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "fake-ida").mkdir(parents=True, exist_ok=True)
    service = AnalysisService(settings, static_worker_factory=lambda session, cfg: worker)
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok
    return service, session_id


def test_search_methods_forward_optional_start_and_end_bounds(tmp_path: Path) -> None:
    """A bounded search must reach the worker with its bounds, not silently full-range."""
    worker = _EchoStaticWorker()
    service, session_id = _open_static(tmp_path, worker)

    assert service.static_search_bytes(session_id, pattern="90 90", start=0x1000, end=0x2000).ok
    assert service.static_search_text(session_id, text="flag", start=0x1000, end=0x2000).ok
    assert service.static_search_immediate(session_id, value=0xDEAD, start=0x1000, end=0x2000).ok

    forwarded = {command: params for command, params in worker.calls}
    for command in ("search_bytes", "search_text", "search_immediate"):
        assert forwarded[command]["start"] == 0x1000
        assert forwarded[command]["end"] == 0x2000


def test_bytes_patch_forwards_a_base64_payload(tmp_path: Path) -> None:
    worker = _EchoStaticWorker(
        responses={"bytes_patch": {"address": 0x1000, "size": 2, "ok": True}}
    )
    service, session_id = _open_static(tmp_path, worker)

    result = service.static_bytes_patch(session_id, address=0x1000, base64="kJA=")

    assert result.ok
    command, params = worker.calls[-1]
    assert command == "bytes_patch"
    assert params["base64"] == "kJA="
    assert "hex" not in params


def test_static_batch_rejects_a_commands_value_that_is_not_a_list(tmp_path: Path) -> None:
    service, session_id = _open_static(tmp_path, _EchoStaticWorker())

    rejected = service.static_batch(
        session_id,
        commands=({"command": "names"},),  # type: ignore[arg-type]
    )

    assert not rejected.ok
    assert rejected.error is not None
    assert not any(command == "batch" for command, _params in [])


def test_batch_recording_passes_through_malformed_result_shapes(tmp_path: Path) -> None:
    """A worker answering with a non-list or non-dict entries must not crash recording."""
    worker = _EchoStaticWorker(responses={"batch": {"results": "not-a-list", "count": 0}})
    service, session_id = _open_static(tmp_path, worker)

    odd_shape = service.static_batch(session_id, commands=[{"command": "names"}])
    assert odd_shape.ok and odd_shape.data is not None
    assert odd_shape.data["results"] == "not-a-list"

    worker.responses["batch"] = {
        "results": [
            "surprise-string-entry",
            {"command": "name_set", "ok": True, "data": {"address": 0x1000}},
        ],
        "count": 2,
    }

    def record_without_data(
        session: str, operation: str, result: Result[JsonObject]
    ) -> Result[JsonObject]:
        return Result[JsonObject](ok=True, data=None)

    # A recorder that produced no payload must leave the item's original data alone.
    service._record_static_patch = record_without_data  # type: ignore[method-assign]

    recorded = service.static_batch(session_id, commands=[{"command": "name_set"}])
    assert recorded.ok and recorded.data is not None
    items = recorded.data["results"]
    assert items[0] == "surprise-string-entry"
    assert items[1]["data"] == {"address": 0x1000}


def test_a_timeline_that_cannot_be_written_is_disclosed_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rename applied; a full timeline volume must not turn that into an error."""
    worker = _EchoStaticWorker(
        responses={"name_set": {"address": 0x1000, "name": "renamed", "ok": True}}
    )
    service, session_id = _open_static(tmp_path, worker)

    def refuse(*args: Any, **kwargs: Any) -> JsonObject:
        return {"write_failed": "OSError: [Errno 28] No space left on device"}

    monkeypatch.setattr(timeline_mod, "append_session_timeline", refuse)

    result = service.static_name_set(session_id, address=0x1000, name="renamed")

    assert result.ok and result.data is not None
    assert result.data["timeline_write_failed"] is True
    assert "timeline_event" not in result.data


def test_spill_helper_leaves_non_string_text_untouched(tmp_path: Path) -> None:
    """A worker replying with a non-string code field is passed through verbatim."""
    worker = _EchoStaticWorker(responses={"decompile": {"address": 0x1000, "code": 12345}})
    service, session_id = _open_static(tmp_path, worker)

    result = service.static_decompile(session_id, address=0x1000)

    assert result.ok and result.data is not None
    assert result.data["code"] == 12345
    assert "truncated" not in result.data


def test_a_failed_spill_returns_the_preview_with_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full volume must yield a usable partial answer, not a retry loop."""
    huge = "x" * (64 * 1024 + 100)
    worker = _EchoStaticWorker(responses={"decompile": {"address": 0x1000, "code": huge}})
    service, session_id = _open_static(tmp_path, worker)

    real_write_bytes = Path.write_bytes

    def refuse_oversized(self: Path, data: bytes) -> int:
        if "oversized" in self.as_posix():
            raise OSError(28, "No space left on device")
        return int(real_write_bytes(self, data))

    monkeypatch.setattr(Path, "write_bytes", refuse_oversized)

    result = service.static_decompile(session_id, address=0x1000)

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert "spill_failed" in result.data
    assert "artifact" not in result.data
    assert len(str(result.data["code"]).encode("utf-8")) <= 1024


def test_a_spill_that_cannot_be_registered_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file exists on disk; a failed registration must say so, not hide the path."""
    huge = "y" * (64 * 1024 + 100)
    worker = _EchoStaticWorker(responses={"decompile": {"address": 0x1000, "code": huge}})
    service, session_id = _open_static(tmp_path, worker)

    def refuse_registration(*args: Any, **kwargs: Any) -> JsonObject:
        raise ValueError("artifact table rejected the row")

    monkeypatch.setattr(service_static, "_record_artifact", refuse_registration)

    result = service.static_decompile(session_id, address=0x1000)

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert Path(str(result.data["artifact"])).is_file()
    assert "artifact table rejected the row" in str(result.data["artifact_unregistered"])
    assert "artifact_id" not in result.data


def test_disassemble_passes_through_a_non_list_instruction_field(tmp_path: Path) -> None:
    worker = _EchoStaticWorker(
        responses={"disassemble": {"address": 0x1000, "instructions": "banana"}}
    )
    service, session_id = _open_static(tmp_path, worker)

    result = service.static_disassemble(session_id, address=0x1000)

    assert result.ok and result.data is not None
    assert result.data["instructions"] == "banana"
