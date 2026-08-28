"""Search-bound forwarding, batch write recording, and spill failure arms.

The static mixin sits between the tool surface and the IDA worker: search
bounds must reach the worker exactly when given, batch write recording must
survive malformed worker replies, and a full volume must degrade a spill or a
patch record into an annotated answer instead of an exception.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import MAX_STATIC_INLINE_TEXT
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service_static import StaticAnalysisMixin

JsonObject = dict[str, Any]

_CAPABILITIES = frozenset(
    {
        "static.search.bytes",
        "static.search.text",
        "static.search.immediate",
        "static.bytes.patch",
        "static.batch",
        "static.disassemble",
        "static.decompile",
        "static.name.set",
    }
)


class _StubWorker:
    def __init__(self) -> None:
        self.capabilities = _CAPABILITIES
        self.replies: dict[str, JsonObject] = {}
        self.calls: list[tuple[str, JsonObject]] = []

    def request(self, command: str, params: JsonObject) -> JsonObject:
        self.calls.append((command, dict(params)))
        return dict(self.replies.get(command, {}))


class _Runtime:
    def __init__(self, worker: _StubWorker) -> None:
        self.lock = threading.RLock()
        self.worker = worker


class _Service(StaticAnalysisMixin):
    def __init__(self, artifact_root: Path) -> None:
        self.settings = Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
        )
        self.repository = InMemoryAnalysisRepository(artifact_root)
        self.worker = _StubWorker()
        self._runtime_object = _Runtime(self.worker)

    def _runtime(self, session_id: str, kind: Any) -> Any:
        return self._runtime_object

    def _require_current_runtime(self, session_id: str, kind: Any, runtime: Any) -> None:
        return None

    def _fail_runtime(
        self, session_id: str, kind: Any, *, failure: BaseException | None = None
    ) -> None:
        return None

    def last_params(self) -> JsonObject:
        return self.worker.calls[-1][1]


def test_search_bounds_reach_the_worker_only_when_given(tmp_path: Path) -> None:
    service = _Service(tmp_path)

    assert service.static_search_bytes("sid", pattern="90 90").ok
    assert "start" not in service.last_params() and "end" not in service.last_params()
    assert service.static_search_bytes("sid", pattern="90 90", start=0x1000, end=0x2000).ok
    assert service.last_params()["start"] == 0x1000
    assert service.last_params()["end"] == 0x2000

    assert service.static_search_text("sid", text="flag", start=0x10, end=0x20).ok
    assert service.last_params()["start"] == 0x10
    assert service.last_params()["end"] == 0x20

    assert service.static_search_immediate("sid", value=7, start=0x30, end=0x40).ok
    assert service.last_params()["start"] == 0x30
    assert service.last_params()["end"] == 0x40


def test_bytes_patch_forwards_the_base64_payload(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.worker.replies["bytes_patch"] = {"address": 0x1000}

    result = service.static_bytes_patch("sid", address=0x1000, base64="kJA=")

    assert result.ok
    patched = service.worker.calls[0][1]
    assert patched == {"address": 0x1000, "base64": "kJA="}


def test_batch_refuses_a_non_list_command_payload(tmp_path: Path) -> None:
    service = _Service(tmp_path)

    result = service.static_batch("sid", commands=("nope",))  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert service.worker.calls == []


def test_batch_passes_a_malformed_results_field_through(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.worker.replies["batch"] = {"results": "not-a-list"}

    result = service.static_batch("sid", commands=[{"command": "name_set"}])

    assert result.ok and result.data is not None
    assert result.data["results"] == "not-a-list"


def test_batch_keeps_a_non_object_item_and_records_the_write_items(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.worker.replies["batch"] = {
        "results": [
            41,
            {"command": "name_set", "ok": True, "data": {"address": 0x1000}},
            {"command": "functions", "ok": True, "data": {"count": 1}},
        ]
    }

    result = service.static_batch("sid", commands=[{"command": "name_set"}])

    assert result.ok and result.data is not None
    items = result.data["results"]
    assert items[0] == 41
    assert items[1]["data"]["patch_artifact"]
    assert items[1]["data"]["timeline_event"] == "static.name.set"
    assert "patch_artifact" not in items[2]["data"]


def test_a_write_notes_a_timeline_that_cannot_be_appended(tmp_path: Path) -> None:
    """The patch already happened; a dead timeline must not fail the call."""
    service = _Service(tmp_path)
    service.worker.replies["name_set"] = {"address": 0x1000, "name": "decrypt"}
    # A file where the sessions directory belongs makes every timeline append fail.
    (tmp_path / "sessions").write_text("in the way", encoding="utf-8")

    result = service.static_name_set("sid", address=0x1000, name="decrypt")

    assert result.ok and result.data is not None
    assert result.data["timeline_write_failed"] is True
    assert result.data["patch_artifact"]


def test_a_write_notes_a_patch_record_that_cannot_be_written(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.worker.replies["name_set"] = {"address": 0x1000, "name": "decrypt"}
    # A file where the static directory belongs makes the patch record unwritable.
    (tmp_path / "static").write_text("in the way", encoding="utf-8")

    result = service.static_name_set("sid", address=0x1000, name="decrypt")

    assert result.ok and result.data is not None
    assert "patch_record_failed" in result.data
    assert "patch_artifact" not in result.data
    assert result.data["timeline_event"] == "static.name.set"


def test_decompile_leaves_non_text_code_untouched(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.worker.replies["decompile"] = {"code": 123}

    result = service.static_decompile("sid")

    assert result.ok and result.data is not None
    assert result.data["code"] == 123
    assert "truncated" not in result.data


def test_an_oversized_decompile_spills_to_an_artifact(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    huge = "x" * (MAX_STATIC_INLINE_TEXT + 10)
    service.worker.replies["decompile"] = {"code": huge}

    result = service.static_decompile("sid")

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert result.data["artifact_bytes"] == len(huge)
    described = service.repository.describe_artifact(str(result.data["artifact_id"]))
    assert described is not None
    assert described["kind"] == "static_decompile"


def test_a_spill_that_cannot_be_written_degrades_to_a_preview(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    huge = "x" * (MAX_STATIC_INLINE_TEXT + 10)
    service.worker.replies["decompile"] = {"code": huge}
    (tmp_path / "static").write_text("in the way", encoding="utf-8")

    result = service.static_decompile("sid")

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert "spill_failed" in result.data
    assert "artifact" not in result.data
    assert len(result.data["code"]) <= 1024


def test_a_spill_whose_registration_fails_reports_it_in_the_payload(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    huge = "x" * (MAX_STATIC_INLINE_TEXT + 10)
    service.worker.replies["decompile"] = {"code": huge}

    def refuse_registration(**fields: Any) -> JsonObject:
        raise ValueError("registration refused")

    service.record_artifact = refuse_registration  # type: ignore[attr-defined]
    result = service.static_decompile("sid")

    assert result.ok and result.data is not None
    assert "artifact_unregistered" in result.data
    assert "artifact_id" not in result.data
    assert Path(str(result.data["artifact"])).is_file()


def test_disassemble_passes_through_when_instructions_are_not_a_list(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    service.worker.replies["disassemble"] = {"instructions": "bogus"}

    result = service.static_disassemble("sid", address=0x1000)

    assert result.ok and result.data is not None
    assert result.data["instructions"] == "bogus"
    assert "truncated" not in result.data
