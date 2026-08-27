"""Guard clauses and failure arms of the paused-target inspection mixin.

service_dynamic_inspect.py is a block of uniform wrappers: each validates its
inputs fail-closed and forwards one bounded debugger request. The integration
tests drive a few of them through a live-ish service; this file pins every
invalid_params guard, the passthrough method names and params, and the
modules.dump / pe.headers.runtime error arms against a recorder harness so a
loosened guard or a renamed RPC method fails a unit test rather than a session.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_dynamic_inspect as sdi
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import MAX_MODULE_DUMP_BYTES
from headless_re_mcp.core.models import BackendKind, Result, RpcError
from headless_re_mcp.core.service_dynamic_inspect import (
    DynamicInspectMixin,
    _atomic_write_bytes,
    _module_base_present,
)
from headless_re_mcp.unpack.stage_labels import STAGE_DUMPED

JsonObject = dict[str, Any]


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )


class _FakeWorker:
    def __init__(
        self,
        capabilities: set[str],
        handler: Callable[[str, JsonObject | None], JsonObject] | None = None,
    ) -> None:
        self.capabilities = capabilities
        self._handler = handler
        self.metadata: JsonObject = {}

    def request(
        self, method: str, params: JsonObject | None = None, *, timeout: float = 30.0
    ) -> JsonObject:
        assert self._handler is not None, f"unexpected worker request {method}"
        return self._handler(method, params)


class _FakeRuntime:
    def __init__(self, worker: _FakeWorker) -> None:
        self.lock = threading.RLock()
        self.worker = worker
        self.snapshot_resync_required = False


class _Recorder(DynamicInspectMixin):
    """DynamicInspectMixin over recorded stubs instead of a live facade."""

    def __init__(self, tmp_path: Path | None = None) -> None:
        self.calls: list[tuple[str, JsonObject | None]] = []
        self.failed: list[str] = []
        self.runtime: Any = None
        self.memory_read: Result[JsonObject] | None = None
        if tmp_path is not None:
            self.settings = _settings(tmp_path)

    def _dynamic_request(
        self,
        session_id: str,
        method: str,
        params: JsonObject | None = None,
        *,
        wait_for: set[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        self.calls.append((method, params))
        return Result[JsonObject](ok=True, data={"method": method})

    def _runtime(self, session_id: str, kind: BackendKind) -> Any:
        if isinstance(self.runtime, BaseException):
            raise self.runtime
        return self.runtime

    def _require_current_runtime(self, session_id: str, kind: BackendKind, runtime: Any) -> None:
        return None

    def _fail_runtime(
        self,
        session_id: str,
        kind: BackendKind,
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.failed.append(str(getattr(failure, "code", "")))

    def record_artifact(self, **fields: Any) -> JsonObject:
        return {"id": "art-1", **fields}

    def dynamic_memory_read(self, session_id: str, address: int, size: int) -> Result[JsonObject]:
        assert self.memory_read is not None, "unexpected memory read"
        return self.memory_read


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda r: r.memory_regions("s", offset=-1), id="regions-neg-offset"),
        pytest.param(lambda r: r.memory_regions("s", offset=True), id="regions-bool-offset"),
        pytest.param(lambda r: r.memory_regions("s", limit=0), id="regions-zero-limit"),
        pytest.param(lambda r: r.memory_regions("s", limit=True), id="regions-bool-limit"),
        pytest.param(lambda r: r.memory_protect_query("s", -1), id="protect-query-neg"),
        pytest.param(lambda r: r.memory_protection("s", -1), id="protection-neg"),
        pytest.param(
            lambda r: r.memory_protection("s", 0x1000, rights=""), id="protection-empty-rights"
        ),
        pytest.param(lambda r: r.threads_list("s", offset=-1), id="threads-neg-offset"),
        pytest.param(lambda r: r.threads_list("s", limit=0), id="threads-zero-limit"),
        pytest.param(lambda r: r.threads_list("s", limit=1025), id="threads-limit-over"),
        pytest.param(lambda r: r.threads_context_read("s", 0), id="ctx-read-zero-tid"),
        pytest.param(lambda r: r.threads_context_write("s", 0, "rip", 1), id="ctx-write-zero-tid"),
        pytest.param(lambda r: r.stack_read("s", count=0), id="stack-zero-count"),
        pytest.param(lambda r: r.stack_read("s", count=257), id="stack-count-over"),
        pytest.param(lambda r: r.stack_read("s", address=-1), id="stack-neg-address"),
        pytest.param(lambda r: r.stack_trace("s", limit=0), id="trace-zero-limit"),
        pytest.param(lambda r: r.stack_trace("s", limit=257), id="trace-limit-over"),
        pytest.param(lambda r: r.disassembly_read("s", -1), id="disasm-neg-address"),
        pytest.param(lambda r: r.disassembly_read("s", 0x1000, count=0), id="disasm-zero-count"),
        pytest.param(lambda r: r.symbols_list("s", 0), id="symbols-zero-base"),
        pytest.param(lambda r: r.symbols_list("s", 0x1000, limit=0), id="symbols-zero-limit"),
        pytest.param(lambda r: r.symbols_list("s", 0x1000, limit=4097), id="symbols-limit-over"),
        pytest.param(lambda r: r.symbols_resolve("s", ""), id="resolve-empty"),
        pytest.param(lambda r: r.imports_read("s", 0, 64), id="imports-read-zero-va"),
        pytest.param(lambda r: r.imports_read("s", 0x1000, 0), id="imports-read-zero-size"),
        pytest.param(lambda r: r.imports_scan("s", 0), id="imports-scan-zero-base"),
        pytest.param(
            lambda r: r.imports_scan("s", 0x1000, mode="bogus"), id="imports-scan-bad-mode"
        ),
        pytest.param(lambda r: r.modules_dump("s", 0), id="dump-zero-base"),
        pytest.param(lambda r: r.modules_dump("s", 0x1000, size=0), id="dump-zero-size"),
        pytest.param(lambda r: r.pe_headers_runtime("s", 0), id="headers-zero-base"),
        pytest.param(lambda r: r.breakpoints_hardware_set("s", -1), id="hwbp-neg-address"),
        pytest.param(
            lambda r: r.breakpoints_hardware_set("s", 0x1000, bp_type="q"), id="hwbp-bad-type"
        ),
        pytest.param(lambda r: r.breakpoints_hardware_set("s", 0x1000, size=3), id="hwbp-bad-size"),
        pytest.param(
            lambda r: r.breakpoints_memory_set("s", 0x1000, bp_type="q"), id="membp-bad-type"
        ),
        pytest.param(lambda r: r.breakpoints_condition_set("s", 0x1000, ""), id="cond-empty"),
        pytest.param(
            lambda r: r.breakpoints_condition_set("s", 0x1000, "a" * 513), id="cond-too-long"
        ),
        pytest.param(
            lambda r: r.breakpoints_condition_set("s", 0x1000, "rax; rbx"), id="cond-metachar"
        ),
        pytest.param(lambda r: r.patches_apply("s", 0x1000, ""), id="patch-empty-data"),
    ],
)
def test_invalid_inputs_fail_closed_without_touching_the_debugger(
    call: Callable[[_Recorder], Result[JsonObject]],
) -> None:
    recorder = _Recorder()
    result = call(recorder)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert recorder.calls == [], "a rejected request must never reach the backend"


def test_an_oversized_dump_request_is_refused_before_any_io() -> None:
    recorder = _Recorder()
    result = recorder.modules_dump("s", 0x1000, size=MAX_MODULE_DUMP_BYTES + 1)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "dump_too_large"
    assert recorder.calls == []


def test_passthroughs_forward_the_method_names_and_params() -> None:
    recorder = _Recorder()
    recorder.memory_regions("s", offset=2, limit=5)
    recorder.memory_protect_query("s", 0x1000)
    recorder.memory_protection("s", 0x1000, rights="rwx")
    recorder.threads_list("s", offset=1, limit=8)
    recorder.threads_current("s")
    recorder.threads_context_read("s", 7)
    recorder.threads_context_write("s", 7, "rip", 0x401000)
    recorder.stack_read("s", address=0x10, count=4)
    recorder.stack_trace("s", limit=9)
    recorder.disassembly_read("s", 0x2000, count=3)
    recorder.symbols_list("s", 0x400000, limit=16)
    recorder.symbols_resolve("s", "kernel32!CreateFileW")
    recorder.imports_read("s", 0x5000, 64)
    recorder.breakpoints_hardware_set("s", 0x1000, bp_type="w", size=4)
    recorder.breakpoints_hardware_remove("s", 0x1000)
    recorder.breakpoints_hardware_list("s")
    recorder.breakpoints_memory_set("s", 0x1000, bp_type="r")
    recorder.breakpoints_memory_remove("s", 0x1000)
    recorder.breakpoints_memory_list("s")
    recorder.breakpoints_condition_set("s", 0x1000, "rax == 1")
    recorder.breakpoints_condition_get("s", 0x1000)
    recorder.patches_list("s")
    recorder.patches_apply("s", 0x1000, "9090")
    recorder.patches_restore("s", 0x1000)

    calls = dict(recorder.calls)
    assert set(calls) == {
        "memory.regions",
        "memory.protect.query",
        "memory.protection",
        "threads.list",
        "threads.current",
        "threads.context.read",
        "threads.context.write",
        "stack.read",
        "stack.trace",
        "disassembly.read",
        "symbols.list",
        "symbols.resolve",
        "imports.read",
        "breakpoints.hardware.set",
        "breakpoints.hardware.remove",
        "breakpoints.hardware.list",
        "breakpoints.memory.set",
        "breakpoints.memory.remove",
        "breakpoints.memory.list",
        "breakpoints.condition.set",
        "breakpoints.condition.get",
        "patches.list",
        "patches.apply",
        "patches.restore",
    }
    assert calls["memory.regions"] == {"offset": 2, "limit": 5}
    assert calls["memory.protection"] == {"address": 0x1000, "rights": "rwx"}
    assert calls["stack.read"] == {"count": 4, "address": 0x10}
    assert calls["threads.context.write"] == {"tid": 7, "name": "rip", "value": 0x401000}
    assert calls["breakpoints.hardware.set"] == {"address": 0x1000, "type": "w", "size": 4}
    assert calls["imports.read"] == {"iat_va": 0x5000, "size": 64}


def test_module_base_present_requires_a_dict_with_a_module_list() -> None:
    assert _module_base_present("not a dict", 0x1000) is False
    assert _module_base_present({"modules": "not a list"}, 0x1000) is False
    assert _module_base_present({"modules": [{"base": 0x1000}]}, 0x1000) is True
    assert _module_base_present({"modules": [{"base": 0x2000}, "junk"]}, 0x1000) is False


def test_atomic_write_cleans_its_temp_file_when_the_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out" / "dump.bin"

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError):
        _atomic_write_bytes(destination, b"payload")
    assert not destination.exists()
    assert list(destination.parent.iterdir()) == [], "no temp litter on failure"


def test_imports_scan_forwards_the_optional_search_bounds() -> None:
    recorder = _Recorder()
    recorder.runtime = _FakeRuntime(_FakeWorker(set()))

    result = recorder.imports_scan(
        "s", 0x400000, search_start=0x401000, search_size=0x2000, mode="sparse"
    )

    assert result.ok is True
    assert recorder.calls == [
        (
            "imports.scan",
            {
                "module_base": 0x400000,
                "max_candidates": 8,
                "mode": "sparse",
                "search_start": 0x401000,
                "search_size": 0x2000,
            },
        )
    ]


def test_imports_scan_refuses_to_run_over_a_stale_snapshot() -> None:
    recorder = _Recorder()
    runtime = _FakeRuntime(_FakeWorker(set()))
    runtime.snapshot_resync_required = True
    recorder.runtime = runtime

    result = recorder.imports_scan("s", 0x400000)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "event_gap_resync_required"
    assert recorder.calls == []


def test_imports_scan_fatal_runtime_errors_fail_the_runtime() -> None:
    recorder = _Recorder()
    recorder.runtime = XdbgRpcError("worker_exited", "worker went away")

    result = recorder.imports_scan("s", 0x400000)

    assert result.ok is False
    assert recorder.failed == ["worker_exited"]


def test_imports_scan_unexpected_errors_become_failures() -> None:
    recorder = _Recorder()
    recorder.runtime = RuntimeError("boom")

    result = recorder.imports_scan("s", 0x400000)

    assert result.ok is False
    assert recorder.failed == []


def test_module_catalog_without_modules_list_capability_is_a_clean_failure() -> None:
    recorder = _Recorder()
    recorder.runtime = _FakeRuntime(_FakeWorker(set()))

    result = recorder.module_catalog("s")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"
    assert recorder.failed == []


def test_module_catalog_fatal_and_unexpected_error_arms() -> None:
    fatal = _Recorder()
    fatal.runtime = XdbgRpcError("rpc_transport_error", "pipe broke")
    assert fatal.module_catalog("s").ok is False
    assert fatal.failed == ["rpc_transport_error"]

    unexpected = _Recorder()
    unexpected.runtime = RuntimeError("boom")
    assert unexpected.module_catalog("s").ok is False
    assert unexpected.failed == []


def _dump_recorder(
    tmp_path: Path,
    capabilities: set[str],
    handler: Callable[[str, JsonObject | None], JsonObject],
) -> _Recorder:
    recorder = _Recorder(tmp_path)
    recorder.runtime = _FakeRuntime(_FakeWorker(capabilities, handler))
    return recorder


def test_modules_dump_rejects_a_traversal_session_id() -> None:
    recorder = _Recorder()
    result = recorder.modules_dump("../evil", 0x400000, size=4096)
    assert result.ok is False
    assert recorder.calls == []


def test_modules_dump_without_the_capability_is_a_clean_failure(tmp_path: Path) -> None:
    recorder = _dump_recorder(tmp_path, set(), lambda m, p: {})
    result = recorder.modules_dump("sess", 0x400000, size=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_modules_dump_detects_the_module_missing_before_the_dump(tmp_path: Path) -> None:
    recorder = _dump_recorder(
        tmp_path,
        {"modules.dump", "modules.list"},
        lambda m, p: {"modules": [{"base": 0x999}]},
    )
    result = recorder.modules_dump("sess", 0x400000, size=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "module_not_found"


def test_modules_dump_refuses_a_worker_path_that_cannot_resolve(tmp_path: Path) -> None:
    def handler(method: str, params: JsonObject | None) -> JsonObject:
        if method == "modules.list":
            return {"modules": [{"base": 0x400000}]}
        return {"output_path": "bad\x00path"}

    recorder = _dump_recorder(tmp_path, {"modules.dump", "modules.list"}, handler)
    result = recorder.modules_dump("sess", 0x400000, size=4096)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "rpc_protocol_error"
    # Protocol errors are fatal: the worker can no longer be trusted.
    assert recorder.failed == ["rpc_protocol_error"]


def test_modules_dump_reports_a_worker_that_wrote_nothing(tmp_path: Path) -> None:
    recorder = _dump_recorder(tmp_path, {"modules.dump"}, lambda m, p: {})
    result = recorder.modules_dump("sess", 0x400000, size=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "artifact_missing"


def test_modules_dump_cleans_up_when_the_worker_crashes_mid_dump(tmp_path: Path) -> None:
    def handler(method: str, params: JsonObject | None) -> JsonObject:
        raise RuntimeError("worker crashed")

    recorder = _dump_recorder(tmp_path, {"modules.dump"}, handler)
    result = recorder.modules_dump("sess", 0x400000, size=4096)

    assert result.ok is False
    dump_dir = recorder.settings.artifact_root / "dump" / "sess"
    assert not any(dump_dir.glob("*.bin")), "a failed dump must not leave artifacts"


def test_modules_dump_success_registers_and_labels_the_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        sdi, "_timeline_append", lambda _self, _sid, event, _msg, **_kw: events.append(event)
    )

    def handler(method: str, params: JsonObject | None) -> JsonObject:
        if method == "modules.list":
            return {"modules": [{"base": 0x400000}]}
        assert params is not None
        Path(str(params["output_path"])).write_bytes(b"MZ" + b"\0" * 62)
        return {}

    recorder = _dump_recorder(tmp_path, {"modules.dump", "modules.list"}, handler)
    result = recorder.modules_dump("sess", 0x400000, size=4096)

    assert result.ok is True
    assert result.data is not None
    assert result.data["actual_size"] == 64
    assert result.data["artifact_id"] == "art-1"
    assert result.data["stage_label"] == STAGE_DUMPED
    assert len(str(result.data["sha256"])) == 64
    assert events == ["artifact.registered"]


class _HeaderWriter(_Recorder):
    """pe.headers.runtime replies OK after writing the requested artifact."""

    def _dynamic_request(
        self,
        session_id: str,
        method: str,
        params: JsonObject | None = None,
        *,
        wait_for: set[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        assert params is not None
        Path(str(params["output_path"])).write_bytes(b"HDRBYTES")
        return Result[JsonObject](ok=True, data={"machine": "x64"})


def test_pe_headers_runtime_registers_the_header_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdi, "_register_capture", lambda *_a, **_kw: {"capture_id": "cap-1"})
    recorder = _HeaderWriter(tmp_path)

    result = recorder.pe_headers_runtime("sess", 0x400000)

    assert result.ok is True
    assert result.data is not None
    assert Path(str(result.data["header_artifact"])).is_file()
    assert len(str(result.data["header_sha256"])) == 64
    assert result.data["capture_id"] == "cap-1"


def test_pe_headers_runtime_rejects_a_traversal_session_id() -> None:
    recorder = _Recorder()
    result = recorder.pe_headers_runtime("../evil", 0x400000)
    assert result.ok is False
    assert recorder.calls == []


class _ErrorReply(_Recorder):
    def __init__(self, code: str, tmp_path: Path | None = None) -> None:
        super().__init__(tmp_path)
        self._code = code

    def _dynamic_request(
        self,
        session_id: str,
        method: str,
        params: JsonObject | None = None,
        *,
        wait_for: set[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        self.calls.append((method, params))
        return Result[JsonObject](
            ok=False, error=RpcError(code=self._code, message="backend said no")
        )


def test_pe_headers_runtime_passes_through_non_capability_errors() -> None:
    recorder = _ErrorReply("backend_error")
    result = recorder.pe_headers_runtime("sess", 0x400000, save_artifact=False)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_pe_headers_fallback_gives_up_when_memory_read_fails() -> None:
    recorder = _ErrorReply("method_not_found")
    recorder.memory_read = Result[JsonObject](
        ok=False, error=RpcError(code="not_paused", message="target running")
    )
    result = recorder.pe_headers_runtime("sess", 0x400000, save_artifact=False)
    # The original capability error is the answer, not the read failure.
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "method_not_found"


def test_pe_headers_fallback_rejects_a_non_pe_image() -> None:
    recorder = _ErrorReply("capability_unavailable")
    recorder.memory_read = Result[JsonObject](ok=True, data={"data": "zz-not-hex"})
    result = recorder.pe_headers_runtime("sess", 0x400000, save_artifact=False)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_pe"


def test_pe_headers_fallback_parses_memory_and_saves_the_artifact(tmp_path: Path) -> None:
    from tests.unit.test_pe_rebuild import _make_runtime_dump

    recorder = _ErrorReply("method_not_found", tmp_path)
    image = _make_runtime_dump()[:0x1000]
    recorder.memory_read = Result[JsonObject](ok=True, data={"data": image.hex()})

    result = recorder.pe_headers_runtime("sess", 0x400000)

    assert result.ok is True
    assert result.data is not None
    assert result.data["source"] == "memory.read_fallback"
    assert result.data["base"] == 0x400000
    artifact = Path(str(result.data["header_artifact"]))
    assert artifact.is_file()
    assert artifact.stat().st_size == int(result.data["header_bytes"])


class _RaisingRequest(_Recorder):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self._error = error

    def _dynamic_request(
        self,
        session_id: str,
        method: str,
        params: JsonObject | None = None,
        *,
        wait_for: set[str] | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        raise self._error


def test_pe_headers_runtime_fatal_rpc_errors_fail_the_runtime() -> None:
    recorder = _RaisingRequest(XdbgRpcError("worker_exited", "gone"))
    result = recorder.pe_headers_runtime("sess", 0x400000, save_artifact=False)
    assert result.ok is False
    assert recorder.failed == ["worker_exited"]


def test_pe_headers_runtime_nonfatal_rpc_errors_keep_the_runtime() -> None:
    recorder = _RaisingRequest(XdbgRpcError("not_paused", "target running"))
    result = recorder.pe_headers_runtime("sess", 0x400000, save_artifact=False)
    assert result.ok is False
    assert recorder.failed == []


def test_optional_params_are_omitted_when_left_at_their_defaults() -> None:
    recorder = _Recorder()
    recorder.memory_regions("s")
    recorder.memory_protection("s", 0x1000)
    recorder.stack_read("s")
    calls = dict(recorder.calls)
    assert calls["memory.regions"] == {"offset": 0}
    assert calls["memory.protection"] == {"address": 0x1000}
    assert calls["stack.read"] == {"count": 32}


def test_modules_dump_without_a_size_caps_at_the_configured_maximum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdi, "_timeline_append", lambda *_a, **_kw: None)
    seen: list[JsonObject] = []

    def handler(method: str, params: JsonObject | None) -> JsonObject:
        assert params is not None
        seen.append(params)
        Path(str(params["output_path"])).write_bytes(b"MZ")
        return {}

    recorder = _dump_recorder(tmp_path, {"modules.dump"}, handler)
    result = recorder.modules_dump("sess", 0x400000)

    assert result.ok is True
    assert seen and "size" not in seen[0], "no explicit size means the worker decides"


def test_pe_headers_runtime_tolerates_a_worker_that_wrote_no_header_file(
    tmp_path: Path,
) -> None:
    recorder = _Recorder(tmp_path)
    result = recorder.pe_headers_runtime("sess", 0x400000)
    assert result.ok is True
    assert result.data is not None
    assert "header_artifact" not in result.data


def test_pe_headers_fallback_without_save_artifact_returns_headers_only() -> None:
    from tests.unit.test_pe_rebuild import _make_runtime_dump

    recorder = _ErrorReply("method_not_found")
    recorder.memory_read = Result[JsonObject](
        ok=True, data={"data": _make_runtime_dump()[:0x1000].hex()}
    )
    result = recorder.pe_headers_runtime("sess", 0x400000, save_artifact=False)
    assert result.ok is True
    data = result.data
    assert data is not None
    assert data["source"] == "memory.read_fallback"
    assert "header_artifact" not in data
