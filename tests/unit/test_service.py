from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState
from headless_re_mcp.core.service import AnalysisService, JsonObject, StaticWorker


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


class FakeWorker:
    def __init__(self, failure: IdaWorkerError | None = None) -> None:
        self.failure = failure
        self.closed = False
        self.terminated = False
        self.requests: list[tuple[str, JsonObject]] = []

    @property
    def pid(self) -> int:
        return 4242

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            {
                "static.functions",
                "static.strings",
                "static.decompile",
                "static.metadata",
                "static.segments",
                "static.imports",
                "static.exports",
                "static.entrypoints",
                "static.disassemble",
                "static.xrefs_to",
                "static.xrefs_from",
                "static.callers",
                "static.callees",
                "static.basic_blocks",
                "static.cfg",
                "static.globals",
                "static.names",
                "static.types",
                "static.structs",
                "static.enums",
                "static.bytes.read",
                "static.search.bytes",
                "static.search.text",
                "static.search.immediate",
            }
        )

    @property
    def metadata(self) -> JsonObject:
        return {
            "image_base": 0x140000000,
            "function_count": 2,
            "string_count": 1,
            "capabilities": sorted(self.capabilities),
        }

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        del timeout
        values = params or {}
        self.requests.append((command, values))
        if self.failure is not None:
            raise self.failure
        empty_page = {
            "items": [],
            "offset": int(values.get("offset", 0) or 0),
            "limit": int(values.get("limit", 100) or 100),
            "returned": 0,
            "total": 0,
        }
        responses: dict[str, JsonObject] = {
            "functions": {
                "items": [
                    {
                        "address": 0x140001000,
                        "name": "main",
                        "end": 0x140001020,
                        "size": 0x20,
                        "flags": 0,
                    }
                ],
                "total": 1,
            },
            "strings": {
                "items": [
                    {
                        "address": 0x140002000,
                        "value": "fixture",
                        "length": 7,
                        "type": 0,
                        "truncated": False,
                    }
                ],
                "total": 1,
            },
            "decompile": {
                "address": 0x140001000,
                "end": 0x140001020,
                "code": "int main() { return 0; }",
            },
            "metadata": {
                "input_path": "fixture.exe",
                "image_base": 0x140000000,
                "start_ip": 0x140001000,
                "bitness": 64,
                "processor": "metapc",
                "function_count": 1,
                "string_count": 1,
                "hashes": {},
                "capabilities": sorted(self.capabilities),
            },
            "segments": {
                **empty_page,
                "items": [
                    {
                        "start": 0x140001000,
                        "end": 0x140002000,
                        "size": 0x1000,
                        "name": ".text",
                        "perm": 5,
                        "bitness": 2,
                    }
                ],
                "returned": 1,
                "total": 1,
            },
            "imports": {
                **empty_page,
                "items": [
                    {
                        "ea": 0x140003000,
                        "module": "kernel32.dll",
                        "name": "ExitProcess",
                        "ordinal": 0,
                    }
                ],
                "returned": 1,
                "total": 1,
            },
            "exports": {**empty_page, "total": 0},
            "entrypoints": {
                **empty_page,
                "items": [
                    {
                        "ea": 0x140001000,
                        "name": "start",
                        "kind": "start_ip",
                        "ordinal": None,
                    }
                ],
                "returned": 1,
                "total": 1,
            },
            "disassemble": {
                "address": int(values.get("address", 0x140001000)),
                "count_requested": int(values.get("count", 32) or 32),
                "instructions": [
                    {"ea": 0x140001000, "size": 1, "text": "retn"},
                ],
                "returned": 1,
                "next_ea": 0x140001001,
                "bytes_consumed": 1,
                "partial": False,
            },
            "xrefs_to": {
                **empty_page,
                "address": int(values.get("address", 0)),
                "total": 0,
            },
            "xrefs_from": {
                **empty_page,
                "address": int(values.get("address", 0)),
                "total": 0,
            },
            "callers": {
                **empty_page,
                "address": int(values.get("address", 0)),
                "note": "call-type xrefs only; not a complete callgraph",
                "total": 0,
            },
            "callees": {
                **empty_page,
                "address": int(values.get("address", 0)),
                "note": "call-type xrefs from function body; not a complete callgraph",
                "total": 0,
            },
            "basic_blocks": {
                **empty_page,
                "address": int(values.get("address", 0x140001000)),
                "function_end": 0x140001020,
                "items": [
                    {
                        "id": 0,
                        "start": 0x140001000,
                        "end": 0x140001020,
                        "size": 0x20,
                        "type": 0,
                        "succ_ids": [],
                        "pred_ids": [],
                    }
                ],
                "returned": 1,
                "total": 1,
            },
            "cfg": {
                "address": int(values.get("address", 0x140001000)),
                "function_end": 0x140001020,
                "nodes": [{"id": 0, "start": 0x140001000, "end": 0x140001020, "type": 0}],
                "edges": [],
                "node_count": 1,
                "edge_count": 0,
            },
            "globals": {**empty_page, "total": 0, "note": "named addresses outside functions"},
            "names": {
                **empty_page,
                "items": [{"ea": 0x140001000, "name": "main"}],
                "returned": 1,
                "total": 1,
            },
            "types": {**empty_page, "total": 0},
            "structs": {**empty_page, "total": 0},
            "enums": {**empty_page, "total": 0},
            "bytes_read": {
                "address": int(values.get("address", 0x140001000)),
                "size": 1,
                "hex": "c3",
                "base64": "ww==",
                "truncated": False,
            },
            "search_bytes": {**empty_page, "pattern": values.get("pattern", ""), "total": 0},
            "search_text": {**empty_page, "text": values.get("text", ""), "total": 0},
            "search_immediate": {
                **empty_page,
                "value": int(values.get("value", 0) or 0),
                "total": 0,
            },
        }
        return responses[command]

    def close(self, *, timeout: float = 15.0) -> None:
        del timeout
        self.closed = True

    def terminate(self) -> None:
        self.terminated = True


def _service(
    tmp_path: Path,
    worker: FakeWorker,
) -> AnalysisService:
    def factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        return worker

    return AnalysisService(_settings(tmp_path), worker_factory=factory)


def _session_id(result_data: JsonObject | None) -> str:
    assert result_data is not None
    session = result_data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def test_static_session_lifecycle(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeWorker()
    service = _service(tmp_path, worker)

    created = service.create_session(str(binary))
    assert created.ok
    session_id = _session_id(created.data)

    opened = service.open_static(session_id)
    assert opened.ok
    session = service.registry.get(session_id)
    assert session.state == SessionState.READY
    assert session.backends

    functions = service.static_functions(session_id, limit=10)
    strings = service.static_strings(session_id, limit=10)
    decompiled = service.static_decompile(session_id, address=0x140001000)
    meta = service.static_metadata(session_id)
    segments = service.static_segments(session_id, limit=10)
    imports = service.static_imports(session_id, limit=10)
    disasm = service.static_disassemble(session_id, address=0x140001000, count=8)
    assert functions.ok and functions.data is not None
    assert functions.data["items"][0]["name"] == "main"
    assert strings.ok and strings.data is not None
    assert strings.data["items"][0]["value"] == "fixture"
    assert decompiled.ok and decompiled.data is not None
    assert "int main" in decompiled.data["code"]
    assert meta.ok and meta.data is not None
    assert meta.data["image_base"] == 0x140000000
    assert "static.metadata" in meta.data["capabilities"]
    assert segments.ok and segments.data is not None
    assert segments.data["items"][0]["name"] == ".text"
    assert imports.ok and imports.data is not None
    assert imports.data["items"][0]["name"] == "ExitProcess"
    assert disasm.ok and disasm.data is not None
    assert disasm.data["instructions"]
    blocks = service.static_basic_blocks(session_id, address=0x140001000, limit=10)
    cfg = service.static_cfg(session_id, address=0x140001000)
    names = service.static_names(session_id, limit=10)
    raw = service.static_bytes_read(session_id, address=0x140001000, size=1)
    assert blocks.ok and blocks.data is not None
    assert blocks.data["items"]
    assert cfg.ok and cfg.data is not None
    assert cfg.data["node_count"] == 1
    assert names.ok and names.data is not None
    assert names.data["items"][0]["name"] == "main"
    assert raw.ok and raw.data is not None
    assert raw.data["hex"] == "c3"

    closed = service.close_session(session_id)
    assert closed.ok
    assert worker.closed
    assert service.registry.get(session_id).state == SessionState.CLOSED
    assert not service.registry.get(session_id).backends


def test_static_operation_requires_open_backend(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeWorker())
    created = service.create_session(str(binary))
    session_id = _session_id(created.data)

    result = service.static_functions(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_unavailable"


def test_fatal_worker_error_marks_session_failed(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeWorker(
        IdaWorkerError("worker_exited", "worker crashed", retryable=True)
    )
    service = _service(tmp_path, worker)
    created = service.create_session(str(binary))
    session_id = _session_id(created.data)
    assert service.open_static(session_id).ok

    result = service.static_functions(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "worker_exited"
    assert worker.terminated
    assert service.registry.get(session_id).state == SessionState.FAILED


def test_missing_binary_returns_structured_error(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeWorker())
    result = service.create_session(str(tmp_path / "missing.exe"))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "file_not_found"