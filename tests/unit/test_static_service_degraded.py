"""Degraded-path coverage for the static-analysis service facade.

These pin the honest-reporting and fail-closed arms of ``service_static`` that
the happy-path suite does not reach: the optional search-window forwarding, the
``static.batch`` shape guards, and the three ways a static write or oversized
spill can partly fail (an unwritable timeline log, a spill file that cannot be
written, and a spilled artifact the repository refuses to register). Each of
these must surface a disclosure flag rather than raise or silently drop data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import MAX_STATIC_INLINE_TEXT
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import FakeStaticWorker, _create, _write_minimal_pe


class _RecordingStaticWorker(FakeStaticWorker):
    """Records every request and returns minimal ok payloads.

    ``batch_result`` lets a test hand back a deliberately malformed batch
    envelope so the write-recording pass can be driven through its guards.
    """

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, JsonObject]] = []
        self.batch_result: JsonObject | None = None

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
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
        values = dict(params or {})
        self.calls.append((command, values))
        if command in {"search_bytes", "search_text", "search_immediate"}:
            return {"matches": [], "count": 0, "returned": 0, "ok": True}
        if command == "bytes_patch":
            return {
                "address": int(values["address"]),
                "size": 0,
                "before_hex": "",
                "after_hex": "",
                "ok": True,
            }
        if command == "name_set":
            return {
                "address": int(values["address"]),
                "name": str(values.get("name")),
                "previous_name": "",
                "ok": True,
            }
        if command == "batch":
            assert self.batch_result is not None, "test must set batch_result first"
            return self.batch_result
        return super().request(command, params)


def _service_with(worker: FakeStaticWorker, tmp_path: Path) -> tuple[AnalysisService, str]:
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


def _call_params(worker: _RecordingStaticWorker, command: str) -> JsonObject:
    return next(params for cmd, params in worker.calls if cmd == command)


def test_search_methods_forward_the_optional_start_and_end_window(tmp_path: Path) -> None:
    """A bounded search must pass its window through; dropping it silently would

    turn a scoped scan into a whole-image scan and mislabel the result's extent.
    """
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    assert service.static_search_bytes(
        session_id, pattern="90 90", start=0x1000, end=0x2000
    ).ok
    assert service.static_search_text(
        session_id, text="hello", start=0x1000, end=0x2000
    ).ok
    assert service.static_search_immediate(
        session_id, value=42, start=0x1000, end=0x2000
    ).ok

    for command in ("search_bytes", "search_text", "search_immediate"):
        params = _call_params(worker, command)
        assert params["start"] == 0x1000
        assert params["end"] == 0x2000


def test_bytes_patch_forwards_a_base64_payload(tmp_path: Path) -> None:
    """The base64 alternative to a hex patch must reach the backend as base64."""
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    result = service.static_bytes_patch(session_id, address=0x140001000, base64="kJA=")

    assert result.ok
    params = _call_params(worker, "bytes_patch")
    assert params["base64"] == "kJA="
    assert "hex" not in params


def test_batch_refuses_a_non_list_command_payload(tmp_path: Path) -> None:
    """A batch is a list of commands; anything else is rejected before dispatch."""
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    result = service.static_batch(session_id, commands={"command": "names"})  # type: ignore[arg-type]

    assert not result.ok
    assert result.error is not None
    assert "commands must be a list" in result.error.message
    assert all(command != "batch" for command, _ in worker.calls)


def test_batch_recording_passes_a_non_list_results_field_through(tmp_path: Path) -> None:
    """If the backend's ``results`` is not a list there is nothing to record;

    the envelope is returned verbatim rather than coerced or dropped.
    """
    worker = _RecordingStaticWorker()
    worker.batch_result = {"results": "not-a-list", "count": 0}
    service, session_id = _service_with(worker, tmp_path)

    result = service.static_batch(session_id, commands=[{"command": "names"}])

    assert result.ok and result.data is not None
    assert result.data["results"] == "not-a-list"


def test_batch_recording_keeps_a_non_dict_item_verbatim(tmp_path: Path) -> None:
    """A scalar item inside ``results`` is preserved, not reshaped into a dict."""
    worker = _RecordingStaticWorker()
    worker.batch_result = {
        "results": [
            "a bare scalar the recorder must not touch",
            {"command": "names", "ok": True, "data": {"count": 0}},
        ],
        "count": 2,
    }
    service, session_id = _service_with(worker, tmp_path)

    result = service.static_batch(session_id, commands=[{"command": "names"}])

    assert result.ok and result.data is not None
    assert result.data["results"][0] == "a bare scalar the recorder must not touch"


def test_a_write_whose_timeline_log_fails_is_flagged_not_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The database already changed, so the write succeeded; a failed timeline

    log must be disclosed as ``timeline_write_failed`` instead of failing the
    call (which would invite a retry that re-reports the applied patch).
    """
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    import headless_re_mcp.core.store.timeline as timeline_mod

    def _log_failed(
        path: Path, *, event: str, message: str, details: JsonObject | None = None
    ) -> JsonObject:
        return {
            "event": event,
            "message": message,
            "write_failed": "OSError: no space left on device",
        }

    monkeypatch.setattr(timeline_mod, "append_session_timeline", _log_failed)

    result = service.static_name_set(session_id, address=0x140001000, name="pinned")

    assert result.ok and result.data is not None
    assert result.data.get("timeline_write_failed") is True
    assert "timeline_event" not in result.data


def test_spill_leaves_a_non_string_field_untouched(tmp_path: Path) -> None:
    """Only string text is spillable; a non-string field is returned unchanged."""
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    payload: JsonObject = {"code": 123, "address": 0x140001000}
    out = service._maybe_spill_static_text(
        session_id, payload, kind="decompile", text_key="code"
    )

    assert out is payload


def test_a_failed_spill_write_returns_the_preview_with_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full volume must not lose the answer: the caller keeps a truncated

    preview plus a ``spill_failed`` reason, and no path is claimed for a file
    that was never written.
    """
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    def _boom(self: Path, data: bytes) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_bytes", _boom)

    big = "A" * (MAX_STATIC_INLINE_TEXT + 4096)
    out = service._maybe_spill_static_text(
        session_id, {"code": big}, kind="decompile", text_key="code"
    )

    assert out.get("truncated") is True
    assert "spill_failed" in out
    assert "artifact" not in out
    assert len(str(out["code"])) <= 1024


def test_a_spilled_artifact_that_cannot_register_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spill file is on disk, but if the repository rejects the row the

    result says ``artifact_unregistered`` rather than handing back an id that
    points at nothing gc will ever reclaim.
    """
    worker = _RecordingStaticWorker()
    service, session_id = _service_with(worker, tmp_path)

    import headless_re_mcp.core.service_static as static_mod

    def _reject(*args: Any, **kwargs: Any) -> JsonObject:
        raise ValueError("artifact registry rejected the row")

    monkeypatch.setattr(static_mod, "_record_artifact", _reject)

    big = "B" * (MAX_STATIC_INLINE_TEXT + 4096)
    out = service._maybe_spill_static_text(
        session_id, {"code": big}, kind="decompile", text_key="code"
    )

    assert out.get("truncated") is True
    assert str(out.get("artifact"))
    assert "artifact_unregistered" in out
    assert "artifact_id" not in out
