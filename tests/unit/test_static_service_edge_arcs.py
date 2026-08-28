"""StaticAnalysisMixin edge arcs: optional params, batch shaping, and spill guards.

The mainline static tests drive the happy write/decompile/disassemble paths.
These pin the branches around them: the optional ``start``/``end`` search
params actually reaching the worker, ``static.batch`` refusing a non-list and
tolerating a non-list ``results`` payload or a non-dict row, the spill helper
short-circuiting on non-text and disclosing (rather than raising on) a failed
artifact write or a failed registration, and a patch whose timeline append
reports a write failure. Each is a caller-visible contract: a search that
silently dropped its bounds, a batch that crashed on a malformed row, or a
spill that raised instead of returning a usable partial answer would all be
regressions a caller could not see coming.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import JsonObject
from tests.unit.test_static_write_service import (
    _service_with,
    _WriteCapableStaticWorker,
)

_ADDR = 0x140001000


class _FlexibleStaticWorker(_WriteCapableStaticWorker):
    """A write-capable worker that also answers reads, searches, and spills.

    Per-test hooks (``disasm_result`` / ``decompile_result`` / ``batch_result``)
    let a single worker shape stand in for every static surface a test needs.
    """

    def __init__(self) -> None:
        super().__init__()
        self.disasm_result: JsonObject | None = None
        self.decompile_result: JsonObject | None = None
        self.batch_result: JsonObject | None = None

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
                "static.name.set",
                "static.comment.set",
                "static.type.apply",
                "static.function.create",
                "static.function.delete",
                "static.bytes.patch",
                "static.batch",
                "static.disassemble",
                "static.decompile",
                "static.search.bytes",
                "static.search.text",
                "static.search.immediate",
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
        values = params or {}
        if command == "disassemble":
            return self.disasm_result if self.disasm_result is not None else {"instructions": []}
        if command == "decompile":
            return self.decompile_result if self.decompile_result is not None else {"code": ""}
        if command in {"search_bytes", "search_text", "search_immediate"}:
            return {"matches": [], "params_echo": dict(values)}
        if command == "batch" and self.batch_result is not None:
            return self.batch_result
        if command == "bytes_patch" and "base64" in values and "hex" not in values:
            import base64 as b64

            raw = b64.b64decode(str(values["base64"]))
            address = int(values["address"])
            self.patched[address] = raw
            return {
                "address": address,
                "size": len(raw),
                "before_hex": "",
                "after_hex": raw.hex(),
                "ok": True,
            }
        return super().request(command, params)


def _flex_service(tmp_path: Path) -> tuple[Any, str, _FlexibleStaticWorker]:
    worker = _FlexibleStaticWorker()
    service, session_id = _service_with(worker, tmp_path)
    return service, session_id, worker


# ---------------------------------------------------------------------------
# Optional search bounds reach the worker.


def test_search_bytes_forwards_start_and_end(tmp_path: Path) -> None:
    service, session_id, _ = _flex_service(tmp_path)
    result = service.static_search_bytes(session_id, pattern="90 90", start=0x1000, end=0x2000)
    assert result.ok and result.data is not None
    echo = result.data["params_echo"]
    assert echo["start"] == 0x1000
    assert echo["end"] == 0x2000


def test_search_text_forwards_start_and_end(tmp_path: Path) -> None:
    service, session_id, _ = _flex_service(tmp_path)
    result = service.static_search_text(session_id, text="hello", start=0x10, end=0x20)
    assert result.ok and result.data is not None
    echo = result.data["params_echo"]
    assert echo["start"] == 0x10
    assert echo["end"] == 0x20


def test_search_immediate_forwards_start_and_end(tmp_path: Path) -> None:
    service, session_id, _ = _flex_service(tmp_path)
    result = service.static_search_immediate(session_id, value=42, start=0x30, end=0x40)
    assert result.ok and result.data is not None
    echo = result.data["params_echo"]
    assert echo["start"] == 0x30
    assert echo["end"] == 0x40


def test_bytes_patch_accepts_a_base64_payload(tmp_path: Path) -> None:
    service, session_id, _ = _flex_service(tmp_path)
    result = service.static_bytes_patch(session_id, address=_ADDR, base64="kJA=")
    assert result.ok and result.data is not None
    assert result.data["after_hex"] == "9090"


# ---------------------------------------------------------------------------
# Disassemble short-circuit and spill helper guards.


def test_disassemble_passes_through_a_non_list_instructions_payload(
    tmp_path: Path,
) -> None:
    """A disassemble reply whose ``instructions`` is not a list is returned as-is."""
    service, session_id, worker = _flex_service(tmp_path)
    worker.disasm_result = {"address": _ADDR, "instructions": "unexpected"}
    result = service.static_disassemble(session_id, address=_ADDR)
    assert result.ok and result.data is not None
    assert result.data["instructions"] == "unexpected"


def test_decompile_leaves_a_non_string_code_field_untouched(tmp_path: Path) -> None:
    """The spill helper only touches text; a non-string body passes through."""
    service, session_id, worker = _flex_service(tmp_path)
    worker.decompile_result = {"address": _ADDR, "code": 12345}
    result = service.static_decompile(session_id, address=_ADDR)
    assert result.ok and result.data is not None
    assert result.data["code"] == 12345


def test_spill_discloses_a_failed_artifact_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unwritable spill file returns the preview with the reason, not an error."""
    service, session_id, worker = _flex_service(tmp_path)
    worker.decompile_result = {"address": _ADDR, "code": "A" * (70 * 1024)}

    real_write_bytes = Path.write_bytes

    def refuse_oversized(self: Path, data: Any) -> int:
        if "oversized" in self.as_posix():
            raise OSError(28, "No space left on device")
        return int(real_write_bytes(self, data))

    monkeypatch.setattr(Path, "write_bytes", refuse_oversized)

    result = service.static_decompile(session_id, address=_ADDR)
    assert result.ok and result.data is not None
    assert result.data.get("truncated") is True
    assert "spill_failed" in result.data
    assert "artifact" not in result.data


def test_spill_discloses_a_failed_artifact_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spill that writes but cannot register says so rather than raising."""
    import headless_re_mcp.core.service_static as service_static

    service, session_id, worker = _flex_service(tmp_path)
    worker.decompile_result = {"address": _ADDR, "code": "B" * (70 * 1024)}

    def boom_register(*args: Any, **kwargs: Any) -> JsonObject:
        raise ValueError("artifact registry unavailable")

    monkeypatch.setattr(service_static, "_record_artifact", boom_register)

    result = service.static_decompile(session_id, address=_ADDR)
    assert result.ok and result.data is not None
    assert result.data.get("truncated") is True
    assert "artifact_unregistered" in result.data
    assert "artifact_id" not in result.data


# ---------------------------------------------------------------------------
# Batch shaping guards.


def test_batch_refuses_a_non_list_commands_argument(tmp_path: Path) -> None:
    service, session_id, _ = _flex_service(tmp_path)
    result = service.static_batch(session_id, commands="not-a-list")
    assert not result.ok
    assert result.error is not None


def test_batch_passes_through_a_non_list_results_payload(tmp_path: Path) -> None:
    """A worker answering batch with a non-list ``results`` is returned unchanged."""
    service, session_id, worker = _flex_service(tmp_path)
    worker.batch_result = {"results": "unexpected", "count": 0}
    result = service.static_batch(session_id, commands=[{"command": "names", "params": {}}])
    assert result.ok and result.data is not None
    assert result.data["results"] == "unexpected"


def test_batch_keeps_a_non_dict_row_verbatim(tmp_path: Path) -> None:
    """A malformed (non-dict) row in results is preserved, not crashed on."""
    service, session_id, worker = _flex_service(tmp_path)
    worker.batch_result = {
        "results": [
            "malformed-row",
            {"command": "names", "ok": True, "data": {}},
        ],
        "count": 2,
    }
    result = service.static_batch(session_id, commands=[{"command": "names", "params": {}}])
    assert result.ok and result.data is not None
    assert result.data["results"][0] == "malformed-row"


def test_batch_tolerates_a_patch_recorder_that_returns_no_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write row whose recorder yields no data keeps the row's original data."""
    service, session_id, worker = _flex_service(tmp_path)
    original = {"address": _ADDR, "name": "batched", "ok": True}
    worker.batch_result = {
        "results": [{"command": "name_set", "ok": True, "data": original}],
        "count": 1,
    }

    def no_data(*args: Any, **kwargs: Any) -> Result[JsonObject]:
        return Result[JsonObject](ok=True, data=None)

    monkeypatch.setattr(service, "_record_static_patch", no_data)

    result = service.static_batch(session_id, commands=[{"command": "name_set", "params": {}}])
    assert result.ok and result.data is not None
    assert result.data["results"][0]["data"] == original


def test_patch_discloses_a_timeline_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A patch that applies but whose timeline append fails is disclosed, not failed."""
    import headless_re_mcp.core.store.timeline as timeline_mod

    service, session_id, _ = _flex_service(tmp_path)

    def failing_append(*args: Any, **kwargs: Any) -> JsonObject:
        return {"write_failed": "disk full"}

    monkeypatch.setattr(timeline_mod, "append_session_timeline", failing_append)

    result = service.static_name_set(session_id, address=_ADDR, name="renamed")
    assert result.ok and result.data is not None
    assert result.data["timeline_write_failed"] is True
    assert "timeline_event" not in result.data
