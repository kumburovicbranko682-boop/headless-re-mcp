"""Pure helpers in service_ext: binding lookup, capture registration, failure notes.

service_ext has no dedicated test file; these module-level helpers are used by
every backend mixin but only exercised incidentally. ``_breakpoint_binding_address``
walks a workflow-status payload to the one address a breakpoint intent binds,
rejecting every shape that is not exactly that; ``_register_capture`` records a
file a capture wrote without ever failing the capture over bookkeeping; and
``_note_failed`` lands a post-work persistence failure in the result's meta
rather than as the outcome. All three are pure given their inputs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service_ext import (
    _breakpoint_binding_address,
    _note_failed,
    _register_capture,
)


def _status(bindings: Any) -> dict[str, Any]:
    return {"workflow": {"state": {"breakpoints": {"bindings": bindings}}}}


# ---- _breakpoint_binding_address -------------------------------------------


def test_a_blank_intent_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="intent_id must not be blank"):
        _breakpoint_binding_address(_status([]), "   ")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"workflow": "not a mapping"},
        {"workflow": {}},
        {"workflow": {"state": "not a mapping"}},
        {"workflow": {"state": {}}},
        {"workflow": {"state": {"breakpoints": "nope"}}},
        {"workflow": {"state": {"breakpoints": {}}}},
        {"workflow": {"state": {"breakpoints": {"bindings": "not a list"}}}},
    ],
)
def test_a_malformed_status_is_an_invalid_state(payload: dict[str, Any]) -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(payload, "bp1")
    assert excinfo.value.code == "invalid_state"


def test_no_matching_binding_is_reported_with_its_count() -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(_status([{"intent_id": "other", "address": 1}]), "bp1")
    assert excinfo.value.code == "invalid_state"
    assert excinfo.value.details["binding_count"] == 0


def test_more_than_one_matching_binding_is_refused() -> None:
    bindings = [
        {"intent_id": "bp1", "address": 0x1000},
        {"intent_id": "bp1", "address": 0x2000},
    ]
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(_status(bindings), "bp1")
    assert excinfo.value.details["binding_count"] == 2


@pytest.mark.parametrize("address", [0, -1, "0x1000", 1.5, True, None])
def test_a_non_positive_or_non_int_address_is_refused(address: Any) -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _breakpoint_binding_address(_status([{"intent_id": "bp1", "address": address}]), "bp1")
    assert excinfo.value.code == "invalid_state"


def test_exactly_one_binding_returns_its_address() -> None:
    bindings = [
        {"intent_id": "other", "address": 0x1000},
        {"intent_id": "bp1", "address": 0x401000},
    ]
    assert _breakpoint_binding_address(_status(bindings), "bp1") == 0x401000


# ---- _register_capture ------------------------------------------------------


class _RecordingService:
    def __init__(self, outcome: Any = None, *, raises: BaseException | None = None) -> None:
        self._outcome = outcome
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    def record_artifact(self, **fields: Any) -> dict[str, Any]:
        self.calls.append(fields)
        if self._raises is not None:
            raise self._raises
        return self._outcome


def test_a_capture_with_no_file_returns_the_payload_untouched() -> None:
    service = _RecordingService()
    payload = {"endpoint": "x"}
    result = _register_capture(
        service, "s", Path("/does/not/exist"), kind="k", source="src", payload=payload
    )
    assert result == payload
    assert service.calls == [], "a missing file must not be registered"


def test_a_registered_capture_carries_its_artifact_id(tmp_path: Path) -> None:
    f = tmp_path / "cap.bin"
    f.write_bytes(b"hello")
    service = _RecordingService({"id": "cap-7"})
    result = _register_capture(
        service, "s", f, kind="screenshot", source="web.screenshot", payload={"w": 1}
    )
    assert result["w"] == 1
    assert result["artifact_id"] == "cap-7"


def test_a_registration_failure_travels_in_the_payload_not_as_an_exception(
    tmp_path: Path,
) -> None:
    f = tmp_path / "cap.bin"
    f.write_bytes(b"hello")
    service = _RecordingService(raises=RuntimeError("store is read-only"))
    result = _register_capture(
        service, "s", f, kind="har", source="proxy.export_har", payload={"n": 2}
    )
    assert result["n"] == 2
    assert "store is read-only" in result["artifact_error"]


# ---- _note_failed -----------------------------------------------------------


def test_a_bookkeeping_failure_lands_in_meta_without_changing_the_result() -> None:
    result = Result[dict[str, Any]](ok=True, data={"closed": True}, meta={})
    _note_failed("close_session", RuntimeError("artifact root vanished"), result)
    assert result.ok is True
    assert result.meta["persisted"] is False
    assert "RuntimeError" in result.meta["persist_error"]
    assert "artifact root vanished" in result.meta["persist_error"]
