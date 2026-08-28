"""Optional-parameter and failure branches of the static analysis facade.

test_static_write_service.py drives the happy write/spill paths; this file adds
the search-window optional args (start/end), the base64 patch arm, the batch
guards (non-list commands, non-list/ non-dict results), the timeline-write and
spill failure disclosures, and the direct ``_maybe_spill_static_text`` guards.
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
from tests.unit.test_dynamic_service import _create, _write_minimal_pe
from tests.unit.test_static_write_service import _WriteCapableStaticWorker


class _SearchWorker(_WriteCapableStaticWorker):
    """Records the last params and answers the search/disassemble commands."""

    def __init__(self, *, disassemble_payload: JsonObject | None = None) -> None:
        super().__init__()
        self.last_params: dict[str, JsonObject] = {}
        self._disassemble_payload = disassemble_payload

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
                "static.disassemble",
                "static.search.bytes",
                "static.search.text",
                "static.search.immediate",
                "static.bytes.patch",
                "static.batch",
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
        self.last_params[command] = values
        if command in {"search_bytes", "search_text", "search_immediate"}:
            return {"matches": [], "total": 0}
        if command == "disassemble":
            if self._disassemble_payload is not None:
                return dict(self._disassemble_payload)
            return {"address": values.get("address"), "instructions": []}
        return super().request(command, params)


def _service(tmp_path: Path, worker: Any) -> tuple[AnalysisService, str]:
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


# --- optional search window + base64 patch --------------------------------------


def test_search_bytes_forwards_the_start_and_end_window(tmp_path: Path) -> None:
    worker = _SearchWorker()
    service, session_id = _service(tmp_path, worker)

    result = service.static_search_bytes(session_id, pattern="90 90", start=0x1000, end=0x2000)

    assert result.ok
    assert worker.last_params["search_bytes"]["start"] == 0x1000
    assert worker.last_params["search_bytes"]["end"] == 0x2000


def test_search_text_forwards_the_start_and_end_window(tmp_path: Path) -> None:
    worker = _SearchWorker()
    service, session_id = _service(tmp_path, worker)

    service.static_search_text(session_id, text="flag", start=0x10, end=0x20)

    assert worker.last_params["search_text"]["start"] == 0x10
    assert worker.last_params["search_text"]["end"] == 0x20


def test_search_immediate_forwards_the_start_and_end_window(tmp_path: Path) -> None:
    worker = _SearchWorker()
    service, session_id = _service(tmp_path, worker)

    service.static_search_immediate(session_id, value=0xDEAD, start=0x1, end=0x2)

    assert worker.last_params["search_immediate"]["start"] == 0x1
    assert worker.last_params["search_immediate"]["end"] == 0x2


def test_bytes_patch_forwards_base64(tmp_path: Path) -> None:
    class _Base64PatchWorker(_SearchWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            del timeout
            self.last_params[command] = dict(params or {})
            if command == "bytes_patch":
                return {"address": 0, "size": 1, "ok": True}
            return super().request(command, params)

    worker = _Base64PatchWorker()
    service, session_id = _service(tmp_path, worker)

    result = service.static_bytes_patch(session_id, address=0x140001000, base64="kA==")

    assert result.ok
    assert worker.last_params["bytes_patch"]["base64"] == "kA=="


# --- disassemble: instructions not a list ---------------------------------------


def test_disassemble_without_an_instruction_list_is_passed_through(
    tmp_path: Path,
) -> None:
    worker = _SearchWorker(disassemble_payload={"address": 0x140001000, "instructions": "oops"})
    service, session_id = _service(tmp_path, worker)

    result = service.static_disassemble(session_id, address=0x140001000)

    assert result.ok and result.data is not None
    assert result.data["instructions"] == "oops"  # returned unchanged, not spilled
    assert "truncated" not in result.data


# --- batch guards ---------------------------------------------------------------


def test_batch_rejects_a_non_list_commands_argument(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path, _SearchWorker())

    result = service.static_batch(session_id, commands="not-a-list")  # type: ignore[arg-type]

    assert not result.ok
    assert result.error is not None
    assert "must be a list" in result.error.message


def test_batch_results_that_are_not_a_list_pass_through(tmp_path: Path) -> None:
    class _OddBatchWorker(_SearchWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            del timeout
            if command == "batch":
                return {"results": "not-a-list", "count": 0}
            return super().request(command, params)

    service, session_id = _service(tmp_path, _OddBatchWorker())

    result = service.static_batch(session_id, commands=[{"command": "names", "params": {}}])

    assert result.ok and result.data is not None
    assert result.data["results"] == "not-a-list"


def test_batch_keeps_non_dict_result_items_verbatim(tmp_path: Path) -> None:
    class _ScalarItemBatchWorker(_SearchWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            del timeout
            if command == "batch":
                return {
                    "results": [
                        "a bare string result",
                        {"index": 1, "command": "names", "ok": True, "data": {}},
                    ],
                    "count": 2,
                }
            return super().request(command, params)

    service, session_id = _service(tmp_path, _ScalarItemBatchWorker())

    result = service.static_batch(session_id, commands=[{"command": "names", "params": {}}])

    assert result.ok and result.data is not None
    assert result.data["results"][0] == "a bare string result"


def test_batch_leaves_the_item_data_when_the_patch_record_has_no_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The defensive arm: a patch-record result carrying no data leaves the
    batch item's own data intact rather than overwriting it with ``None``."""

    class _WriteResultBatchWorker(_SearchWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            del timeout
            if command == "batch":
                return {
                    "results": [
                        {
                            "index": 0,
                            "command": "name_set",
                            "ok": True,
                            "data": {"address": 0x140001000, "name": "n", "ok": True},
                        }
                    ],
                    "count": 1,
                }
            return super().request(command, params)

    service, session_id = _service(tmp_path, _WriteResultBatchWorker())
    monkeypatch.setattr(service, "_record_static_patch", lambda *a, **k: Result(ok=True, data=None))

    result = service.static_batch(
        session_id,
        commands=[{"command": "name_set", "params": {"address": 0, "name": "n"}}],
    )

    assert result.ok and result.data is not None
    # The recorded result had no data, so the item keeps its original payload.
    assert result.data["results"][0]["data"]["name"] == "n"


# --- timeline + spill failure disclosures ---------------------------------------


def test_a_patch_discloses_a_failed_timeline_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        timeline_mod,
        "append_session_timeline",
        lambda *args, **kwargs: {"write_failed": "disk full"},
    )
    service, session_id = _service(tmp_path, _SearchWorker())

    result = service.static_name_set(session_id, address=0x140001000, name="renamed")

    assert result.ok and result.data is not None
    assert result.data["timeline_write_failed"] is True
    assert "timeline_event" not in result.data


def test_maybe_spill_returns_non_string_text_unchanged(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path, _SearchWorker())
    static = service  # the facade owns _maybe_spill_static_text

    data = {"text": 12345}
    result = static._maybe_spill_static_text(session_id, data, kind="disassemble", text_key="text")

    assert result is data  # not a string -> returned as-is


def _huge_disassemble_worker() -> _SearchWorker:
    line = "é" * 100
    instructions = [{"text": line, "address": 0x140001000 + i} for i in range(400)]
    return _SearchWorker(
        disassemble_payload={
            "address": 0x140001000,
            "instructions": instructions,
            "returned": len(instructions),
        }
    )


def test_a_spill_whose_write_fails_returns_a_preview_with_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path, _huge_disassemble_worker())
    real_write_bytes = Path.write_bytes

    def refuse_oversized(self: Path, data: bytes) -> int:
        if "oversized" in self.as_posix():
            raise OSError(28, "No space left on device")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", refuse_oversized)

    result = service.static_disassemble(session_id, address=0x140001000, count=400)

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert "spill_failed" in result.data
    assert "artifact" not in result.data  # nothing was written to register


def test_a_spill_that_cannot_be_registered_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path, _huge_disassemble_worker())

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("artifact store rejected this")

    monkeypatch.setattr(service_static, "_record_artifact", boom)

    result = service.static_disassemble(session_id, address=0x140001000, count=400)

    assert result.ok and result.data is not None
    assert result.data["truncated"] is True
    assert Path(str(result.data["artifact"])).is_file()  # the bytes did land
    assert "artifact_unregistered" in result.data
    assert "artifact_id" not in result.data
