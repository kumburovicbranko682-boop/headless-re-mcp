"""Contract tests for the static facade's search shaping and spill failure paths.

Everything here goes through the public ``static_*`` surface with a recording
fake worker: the point is to pin what the facade forwards to the backend
(optional search bounds, base64 patches), how it guards hostile batch shapes,
and that spill/registration/timeline failures are disclosed instead of raised.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import FakeStaticWorker, _create, _write_minimal_pe


class _RecordingStaticWorker(FakeStaticWorker):
    """Records every backend request and answers with canned payloads."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, JsonObject]] = []
        self.responses: dict[str, JsonObject] = {}

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
                "static.decompile",
                "static.disassemble",
                "static.search.bytes",
                "static.search.text",
                "static.search.immediate",
                "static.bytes.patch",
                "static.name.set",
                "static.batch",
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
        self.calls.append((command, dict(params or {})))
        if command in self.responses:
            return dict(self.responses[command])
        return {"items": [], "total": 0}

    def last_params(self, command: str) -> JsonObject:
        for name, params in reversed(self.calls):
            if name == command:
                return params
        raise AssertionError(f"backend never saw {command}")


def _service(tmp_path: Path) -> tuple[AnalysisService, _RecordingStaticWorker, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = _RecordingStaticWorker()
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
    return service, worker, session_id


# ---------------------------------------------------------------------------
# Search bounds: optional start/end must reach the backend only when given.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "command", "needle"),
    [
        ("static_search_bytes", "search_bytes", {"pattern": "90 90"}),
        ("static_search_text", "search_text", {"text": "flag{"}),
        ("static_search_immediate", "search_immediate", {"value": 0xDEAD}),
    ],
)
def test_search_bounds_are_forwarded_when_given(
    tmp_path: Path,
    method: str,
    command: str,
    needle: dict[str, Any],
) -> None:
    service, worker, session_id = _service(tmp_path)

    bounded = getattr(service, method)(
        session_id,
        start=0x140001000,
        end=0x140002000,
        **needle,
    )
    assert bounded.ok
    sent = worker.last_params(command)
    assert sent["start"] == 0x140001000
    assert sent["end"] == 0x140002000

    unbounded = getattr(service, method)(session_id, **needle)
    assert unbounded.ok
    sent = worker.last_params(command)
    assert "start" not in sent and "end" not in sent, (
        "bounds the caller never gave must not be invented for the backend"
    )


def test_bytes_patch_forwards_base64_payload(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["bytes_patch"] = {"address": 0x140001000, "size": 1, "ok": True}

    patched = service.static_bytes_patch(session_id, address=0x140001000, base64="kA==")

    assert patched.ok
    sent = worker.last_params("bytes_patch")
    assert sent["base64"] == "kA=="
    assert "hex" not in sent, "an absent hex payload must not be forwarded as one"


# ---------------------------------------------------------------------------
# Batch guards: hostile shapes from the wire or from the backend.
# ---------------------------------------------------------------------------


def test_batch_refuses_commands_that_are_not_a_list(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)

    refused = service.static_batch(
        session_id,
        commands=("not", "a", "list"),  # type: ignore[arg-type]
    )

    assert not refused.ok
    assert refused.error is not None
    assert refused.error.code == "invalid_request"
    assert "list" in refused.error.message
    assert not any(name == "batch" for name, _ in worker.calls), (
        "a refused batch must never reach the backend"
    )


def test_batch_result_without_a_results_list_passes_through(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["batch"] = {"results": "corrupted", "count": 0}

    result = service.static_batch(session_id, commands=[{"command": "names"}])

    assert result.ok and result.data is not None
    assert result.data["results"] == "corrupted", (
        "a backend answer the recorder cannot walk is returned untouched"
    )


def test_batch_non_dict_items_survive_write_recording(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["batch"] = {
        "results": [
            "stray string from a confused backend",
            {
                "index": 1,
                "command": "name_set",
                "ok": True,
                "data": {"address": 0x140001000, "name": "renamed", "ok": True},
            },
        ],
        "count": 2,
    }

    result = service.static_batch(
        session_id,
        commands=[{"command": "name_set", "params": {"address": 0x140001000, "name": "renamed"}}],
    )

    assert result.ok and result.data is not None
    items = result.data["results"]
    assert isinstance(items, list)
    assert items[0] == "stray string from a confused backend"
    recorded = items[1]["data"]
    assert Path(str(recorded["patch_artifact"])).is_file(), (
        "the dict-shaped write next to the stray item is still recorded"
    )


# ---------------------------------------------------------------------------
# Disassembly inline path: small listings must come back untouched.
# ---------------------------------------------------------------------------


def test_small_disassembly_is_returned_inline_untruncated(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["disassemble"] = {
        "address": 0x140001000,
        "instructions": [{"address": 0x140001000, "text": "nop"}],
        "returned": 1,
    }

    result = service.static_disassemble(session_id, address=0x140001000, count=1)

    assert result.ok and result.data is not None
    assert "truncated" not in result.data
    assert "artifact" not in result.data
    assert result.data["instructions"] == [{"address": 0x140001000, "text": "nop"}]


def test_disassembly_without_an_instruction_list_passes_through(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["disassemble"] = {"address": 0x140001000, "instructions": "not-a-list"}

    result = service.static_disassemble(session_id, address=0x140001000, count=1)

    assert result.ok and result.data is not None
    assert result.data["instructions"] == "not-a-list", (
        "an answer the spill logic cannot walk is returned untouched"
    )


# ---------------------------------------------------------------------------
# Disclosure paths: timeline, spill, and registration failures must be named
# in the payload instead of failing a call whose effect already happened.
# ---------------------------------------------------------------------------


def test_timeline_write_failure_is_disclosed_on_the_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["name_set"] = {"address": 0x140001000, "name": "renamed", "ok": True}

    import headless_re_mcp.core.store.timeline as timeline_module

    def refuse(*args: Any, **kwargs: Any) -> JsonObject:
        return {"event": "static.name.set", "write_failed": "OSError: disk full"}

    monkeypatch.setattr(timeline_module, "append_session_timeline", refuse)

    renamed = service.static_name_set(session_id, address=0x140001000, name="renamed")

    assert renamed.ok and renamed.data is not None, "the rename applied, so the call succeeded"
    assert renamed.data["timeline_write_failed"] is True
    assert "timeline_event" not in renamed.data, (
        "an event that was never written must not be advertised"
    )


def test_non_text_decompile_payload_is_not_spilled(tmp_path: Path) -> None:
    service, worker, session_id = _service(tmp_path)
    worker.responses["decompile"] = {"address": 0x140001000, "code": None}

    result = service.static_decompile(session_id, address=0x140001000)

    assert result.ok and result.data is not None
    assert result.data["code"] is None
    assert "truncated" not in result.data


def _huge_decompile(worker: _RecordingStaticWorker) -> str:
    body = "// recovered line\n" * 8000
    worker.responses["decompile"] = {"address": 0x140001000, "code": body}
    return body


def test_spill_write_failure_keeps_the_preview_and_names_the_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, worker, session_id = _service(tmp_path)
    _huge_decompile(worker)

    real_write_bytes = Path.write_bytes

    def refuse_oversized(self: Path, data: Any) -> int:
        if "oversized" in self.as_posix():
            raise OSError(28, "No space left on device")
        return int(real_write_bytes(self, data))

    monkeypatch.setattr(Path, "write_bytes", refuse_oversized)

    result = service.static_decompile(session_id, address=0x140001000)

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert "No space left on device" in str(result.data["spill_failed"])
    assert "artifact" not in result.data, "no path may be named for a file never written"
    assert len(str(result.data["code"]).encode("utf-8")) <= 1024, "the preview survives"


def test_spill_registration_failure_is_disclosed_not_raised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, worker, session_id = _service(tmp_path)
    _huge_decompile(worker)

    import headless_re_mcp.core.service_static as service_static

    def refuse_registration(*args: Any, **kwargs: Any) -> JsonObject:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(service_static, "_record_artifact", refuse_registration)

    result = service.static_decompile(session_id, address=0x140001000)

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert Path(str(result.data["artifact"])).is_file(), "the spill file itself was written"
    assert "database is locked" in str(result.data["artifact_unregistered"])
    assert "artifact_id" not in result.data, "an id that was never issued must not be invented"
