from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind, Result, Session, SessionState
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
        # Mirrors IdaWorkerClient: None while the worker process is running.
        self.exit_code: int | None = None
        self.close_error: BaseException | None = None
        self.terminate_error: BaseException | None = None

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
        if self.close_error is not None:
            raise self.close_error

    def terminate(self) -> None:
        self.terminated = True
        if self.terminate_error is not None:
            raise self.terminate_error


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


def test_opening_backends_for_different_sessions_is_not_serialised(tmp_path: Path) -> None:
    """Starting one analyser must not block starting another.

    Every open used to hold the service-wide lock across the whole worker
    launch, and an IDA worker is allowed 300 seconds to come up. That made
    batch.analyze's max_workers a lie: it hands the opens to a thread pool, and
    they queued behind each other anyway.

    A barrier rather than a stopwatch, so this fails outright when the opens are
    serialised instead of being slow and flaky.
    """
    workers = 3
    barrier = threading.Barrier(workers, timeout=10)

    def rendezvous_factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        barrier.wait()
        return FakeWorker()

    service = AnalysisService(_settings(tmp_path), worker_factory=rendezvous_factory)
    session_ids = []
    for index in range(workers):
        binary = tmp_path / f"fixture-{index}.exe"
        _write_minimal_pe(binary)
        session_ids.append(_session_id(service.create_session(str(binary)).data))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(service.open_static, session_ids))

    assert [result.ok for result in results] == [True] * workers
    for session_id in session_ids:
        assert service.registry.get(session_id).state == SessionState.READY


def test_closing_a_session_mid_open_is_refused_with_something_actionable(
    tmp_path: Path,
) -> None:
    """Opening no longer holds the lock, so a close can now arrive during one.

    It used to queue behind the launch and then succeed. Failing fast is the
    better trade, since the alternative is a close that blocks for an analyser
    startup, but only if the caller is told what to do next rather than being
    handed the raw state machine transition.
    """
    started = threading.Event()
    proceed = threading.Event()

    def blocking_factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        started.set()
        proceed.wait(10)
        return FakeWorker()

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(_settings(tmp_path), worker_factory=blocking_factory)
    session_id = _session_id(service.create_session(str(binary)).data)

    with ThreadPoolExecutor(max_workers=2) as pool:
        opening = pool.submit(service.open_static, session_id)
        assert started.wait(10)
        refused = pool.submit(service.close_session, session_id).result(timeout=10)
        proceed.set()
        assert opening.result(timeout=10).ok

    assert not refused.ok and refused.error is not None
    assert refused.error.code == "invalid_request"
    assert "once that open returns" in refused.error.message
    # And the retry the message asks for has to work.
    assert service.close_session(session_id).ok


def test_two_backends_of_one_new_session_cannot_open_concurrently(tmp_path: Path) -> None:
    """A session opening its first backend refuses the second, and leaks nothing.

    This is the state machine, not the lock: a brand new session moves to
    OPENING for its first backend and no open is allowed from there. A caller
    that fires both at once therefore gets one backend and one refusal, and must
    open the second after the first returns. Pinned here because the refusal has
    to stay a clean error rather than a half-registered worker.
    """
    started = threading.Event()
    proceed = threading.Event()
    built: list[FakeWorker] = []

    def blocking_factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        started.set()
        proceed.wait(10)
        worker = FakeWorker()
        built.append(worker)
        return worker

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        _settings(tmp_path),
        static_worker_factory=blocking_factory,
        dynamic_worker_factory=blocking_factory,
    )
    session_id = _session_id(service.create_session(str(binary)).data)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(service.open_static, session_id)
        assert started.wait(10)
        second = pool.submit(service.open_dynamic, session_id)
        refused = second.result()
        proceed.set()
        opened = first.result()

    assert opened.ok
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "invalid_request"
    # The refusal happened before any worker was built, so nothing to clean up.
    assert len(built) == 1
    assert set(service.registry.get(session_id).backends) == {BackendKind.IDA}


def test_a_dead_ida_worker_is_reported_and_then_reopened(tmp_path: Path) -> None:
    """The static backend has to be recoverable, not only the dynamic one.

    IDA speaks over the worker's stdio pipes, so there is no connection to
    rebuild independently of the process: a dead worker can only be reopened.
    The health report is what tells the caller which of the two it is.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    opened: list[FakeWorker] = []

    def factory(session: Session, settings: Settings) -> StaticWorker:
        del session, settings
        worker = FakeWorker()
        opened.append(worker)
        return worker

    service = AnalysisService(_settings(tmp_path), worker_factory=factory)
    session_id = _session_id(service.create_session(str(binary)).data)
    assert service.open_static(session_id).ok
    assert len(opened) == 1

    healthy = service.session_health(session_id)
    assert healthy.ok and healthy.data is not None
    assert healthy.data["healthy"] is True

    opened[0].exit_code = 1
    reported = service.session_health(session_id)
    assert reported.ok and reported.data is not None
    assert reported.data["healthy"] is False
    entry = reported.data["backends"][0]
    assert entry["backend"] == "ida"
    assert entry["worker_alive"] is False
    # Reporting is not repairing: a dead worker is never restarted behind the
    # caller's back, because the replacement analyses nothing until asked.
    assert entry["reconnects"] == 0
    assert len(opened) == 1

    recovered = service.session_recover(session_id, ["ida"])
    assert recovered.ok and recovered.data is not None
    assert recovered.data["failed"] == 0
    # The dead registration must be replaced rather than reported as kept.
    assert [item["action"] for item in recovered.data["backends"]] == ["reopened"]
    assert len(opened) == 2
    assert opened[0].terminated
    assert service.static_functions(session_id, limit=1).ok


def test_a_worker_that_cannot_be_terminated_still_ends_the_session(
    tmp_path: Path,
) -> None:
    """Cleanup that throws must not strand the session in CLOSING.

    Terminate is the fallback for a close that already failed, and on Windows it
    genuinely can throw: the worker's temporary userdir is routinely still held
    by an antivirus scan or a handle the exited process has not released. That
    exception escaped the close, so the session never reached a terminal state,
    and the runtime had already been popped, meaning nothing held the worker any
    more. CLOSING accepts only CLOSED or FAILED, so the session was stuck for
    good and could not even be recovered.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeWorker()
    worker.close_error = IdaWorkerError("worker_timeout", "worker did not answer close")
    worker.terminate_error = PermissionError("temporary userdir is still in use")
    service = _service(tmp_path, worker)
    session_id = _session_id(service.create_session(str(binary)).data)
    assert service.open_static(session_id).ok

    closed = service.close_session(session_id)

    assert not closed.ok and closed.error is not None
    assert closed.error.code == "worker_timeout"
    assert worker.terminated
    state = service.registry.get(session_id).state
    assert state in {SessionState.CLOSED, SessionState.FAILED}
    assert not service.registry.get(session_id).backends


def test_repeated_session_cycles_leave_nothing_behind(tmp_path: Path) -> None:
    """What a long-lived server actually does: open and close, forever.

    Measured over 500 cycles this held its thread count and process handle count
    flat, which is what the sqlite connections being closed buys. The registry
    did not: every session ever opened stayed resident, so this pins the bound.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(_settings(tmp_path), worker_factory=lambda a, b: FakeWorker())
    before = {thread.name for thread in threading.enumerate()}

    cycles = 150
    for _ in range(cycles):
        session_id = _session_id(service.create_session(str(binary)).data)
        assert service.open_static(session_id).ok
        assert service.static_functions(session_id, limit=1).ok
        assert service.close_session(session_id).ok

    assert service._runtime_owner.snapshot() == []
    assert service.session_health().data == {"backends": [], "count": 0, "healthy": None}
    tracked = service.registry.list()
    assert 0 < len(tracked) < cycles
    assert all(item.state is SessionState.CLOSED for item in tracked)

    # The health sweep starts with the first backend and must not outlive the last.
    for _ in range(100):
        leaked = {thread.name for thread in threading.enumerate()} - before
        if not leaked:
            break
        time.sleep(0.02)
    assert not leaked


def test_missing_binary_returns_structured_error(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeWorker())
    result = service.create_session(str(tmp_path / "missing.exe"))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "file_not_found"


def test_pe_tools_on_apk_and_web_sessions_report_target_mismatch(tmp_path: Path) -> None:
    import zipfile

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("lib/arm64-v8a/libx.so", b"\x7fELF")
        archive.writestr("META-INF/CERT.RSA", b"sig")

    service = AnalysisService(_settings(tmp_path))
    try:
        apk_created = service.create_session(str(apk), target="apk")
        assert apk_created.ok and apk_created.data is not None
        apk_session = apk_created.data["session"]
        assert isinstance(apk_session, dict)
        apk_id = str(apk_session["id"])
        apk_static = service.static_functions(apk_id)
        apk_dynamic = service.dynamic_state(apk_id)
        assert not apk_static.ok and apk_static.error is not None
        assert apk_static.error.code == "target_mismatch"
        assert not apk_dynamic.ok and apk_dynamic.error is not None
        assert apk_dynamic.error.code == "target_mismatch"

        web_created = service.create_session("https://example.com/app", target="web")
        assert web_created.ok and web_created.data is not None
        web_session = web_created.data["session"]
        assert isinstance(web_session, dict)
        web_id = str(web_session["id"])
        web_static = service.static_functions(web_id)
        web_dynamic = service.dynamic_state(web_id)
        assert not web_static.ok and web_static.error is not None
        assert web_static.error.code == "target_mismatch"
        assert not web_dynamic.ok and web_dynamic.error is not None
        assert web_dynamic.error.code == "target_mismatch"
    finally:
        service.close_all()


def test_nonpe_tools_reject_a_session_they_cannot_analyse(tmp_path: Path) -> None:
    """The symmetric guard to the PE-on-wrong-session test above.

    That test pins the PE tools; this pins the other direction, which had no
    coverage: every apk.* tool must refuse a non-APK session, and the binary
    backends (r2, ghidra) must refuse a web session that is backed by no local
    file. All of these reject with target_mismatch *before* touching a backend,
    so the guard holds even where androguard / r2 / ghidra are not installed --
    a regression that dropped the require_target/require_binary check would let
    the tool try to parse a PE as an APK (or shell out with no file) and surface
    as an internal_error incident instead of the honest "wrong session kind".

    apk.* is guarded by a single shared helper (_apk_binary), so exercising the
    whole surface here is what catches a newly added apk tool that forgets it.
    """
    pe = tmp_path / "sample.exe"
    _write_minimal_pe(pe)

    service = AnalysisService(_settings(tmp_path))
    try:
        pe_created = service.create_session(str(pe))
        assert pe_created.ok and pe_created.data is not None
        pe_id = str(pe_created.data["session"]["id"])

        web_created = service.create_session("https://example.com/app", target="web")
        assert web_created.ok and web_created.data is not None
        web_id = str(web_created.data["session"]["id"])

        # Every apk.* tool, called on a PE session with otherwise-valid default
        # args, must stop at the APK target guard. Named so a failure points at
        # the exact tool that skipped the check.
        apk_on_pe: dict[str, Callable[[], Result[JsonObject]]] = {
            "apk_open": lambda: service.apk_open(pe_id),
            "apk_manifest": lambda: service.apk_manifest(pe_id),
            "apk_permissions": lambda: service.apk_permissions(pe_id),
            "apk_certificates": lambda: service.apk_certificates(pe_id),
            "apk_components": lambda: service.apk_components(pe_id),
            "apk_native_libs": lambda: service.apk_native_libs(pe_id),
            "apk_classes": lambda: service.apk_classes(pe_id),
            "apk_methods": lambda: service.apk_methods(pe_id, "Lcom/example/Gate;"),
            "apk_strings": lambda: service.apk_strings(pe_id),
            "apk_xrefs": lambda: service.apk_xrefs(pe_id, "callee"),
            "apk_decompile": lambda: service.apk_decompile(pe_id, "Lcom/example/Gate;"),
            "apk_export_sources": lambda: service.apk_export_sources(pe_id),
            "apk_decode": lambda: service.apk_decode(pe_id),
            "apk_repack": lambda: service.apk_repack(pe_id),
            "apk_sign": lambda: service.apk_sign(pe_id),
        }
        for name, call in apk_on_pe.items():
            result = call()
            assert not result.ok, f"{name} unexpectedly ran on a PE session"
            assert result.error is not None, name
            assert result.error.code == "target_mismatch", f"{name}: {result.error.code}"

        # A representative apk tool on a web session takes the same guard.
        apk_on_web = service.apk_methods(web_id, "Lcom/example/Gate;")
        assert apk_on_web.error is not None
        assert apk_on_web.error.code == "target_mismatch"

        # r2/ghidra need a local file to analyse; a web session has none, so
        # require_binary rejects them before any executable is resolved.
        r2_on_web = service.r2_open(web_id)
        assert r2_on_web.error is not None
        assert r2_on_web.error.code == "target_mismatch"
        ghidra_on_web = service.ghidra_analyze(web_id)
        assert ghidra_on_web.error is not None
        assert ghidra_on_web.error.code == "target_mismatch"
    finally:
        service.close_all()