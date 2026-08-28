"""Paused-target inspection: memory, threads, stack, symbols, modules, imports.

Split out of AnalysisService, which had grown past 6700 lines. These are the
thin, uniform wrappers over one bounded debugger request each, which is why they
move as a block: between them they reach for only eight things the facade owns.

Behaviour is unchanged. The members below are supplied by AnalysisService, and
mypy checks these declarations against the real definitions, so a signature that
drifts fails as an incompatible override rather than at runtime.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.addressing import RuntimeModuleCatalog
from headless_re_mcp.core.limits import MAX_MODULE_DUMP_BYTES
from headless_re_mcp.core.models import BackendKind, ModuleSelector, Result, RpcError
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _register_capture, _timeline_append
from headless_re_mcp.core.service_static import _FATAL_WORKER_ERRORS
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.pe_rebuild import PeRebuildError, parse_runtime_headers
from headless_re_mcp.unpack.stage_labels import STAGE_DUMPED

if TYPE_CHECKING:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.repository import AnalysisRepository
    from headless_re_mcp.core.service import _BackendRuntime

JsonObject = dict[str, Any]


def _module_base_present(modules_payload: object, base: int) -> bool:
    if not isinstance(modules_payload, dict):
        return False
    modules = modules_payload.get("modules")
    if not isinstance(modules, list):
        return False
    return any(isinstance(item, dict) and int(item.get("base", 0) or 0) == base for item in modules)


def _atomic_write_bytes(destination: Path, payload: bytes) -> None:
    """Write ``payload`` via a sibling temp file and ``os.replace``."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{destination.stem}-",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            with suppress(OSError):
                temporary.unlink()


class DynamicInspectMixin:
    """Read-side debugger surface for a paused target."""

    settings: Settings
    repository: AnalysisRepository

    if TYPE_CHECKING:

        def record_artifact(self, **fields: Any) -> JsonObject: ...

        def _runtime(self, session_id: str, kind: BackendKind) -> _BackendRuntime: ...

        def _require_current_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            runtime: _BackendRuntime,
        ) -> None: ...

        def _fail_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            *,
            failure: BaseException | None = None,
        ) -> None: ...

        def _dynamic_request(
            self,
            session_id: str,
            method: str,
            params: JsonObject | None = None,
            *,
            wait_for: set[str] | None = None,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def _explicit_module_operation(
            self,
            session_id: str,
            selector: ModuleSelector,
            *,
            source: Literal["preferred", "runtime"] | None,
            address: int | None = None,
        ) -> Result[JsonObject]: ...

        def dynamic_memory_read(
            self,
            session_id: str,
            address: int,
            size: int,
        ) -> Result[JsonObject]: ...

    def memory_regions(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Return a paused-only page of VirtualQuery-style memory regions."""
        if type(offset) is not int or offset < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="offset must be a non-negative integer",
                ),
            )
        params: JsonObject = {"offset": offset}
        if limit is not None:
            if type(limit) is not int or limit <= 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="limit must be a positive integer",
                    ),
                )
            params["limit"] = limit
        return self._dynamic_request(
            session_id,
            "memory.regions",
            params,
            timeout=timeout,
        )
    def memory_protect_query(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Return the memory region containing ``address`` (paused-only)."""
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        return self._dynamic_request(
            session_id,
            "memory.protect.query",
            {"address": address},
            timeout=timeout,
        )
    def memory_protection(
        self,
        session_id: str,
        address: int,
        *,
        rights: str | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Query or set page rights (alias of protect.query + optional SetPageRights)."""
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        params: JsonObject = {"address": address}
        if rights is not None:
            if not isinstance(rights, str) or not rights:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="rights must be a non-empty string",
                    ),
                )
            params["rights"] = rights
        return self._dynamic_request(
            session_id,
            "memory.protection",
            params,
            timeout=timeout,
        )
    def threads_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 256,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(offset) is not int or offset < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="offset must be a non-negative integer",
                ),
            )
        if type(limit) is not int or not 1 <= limit <= 1024:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="limit must be between 1 and 1024",
                ),
            )
        return self._dynamic_request(
            session_id,
            "threads.list",
            {"offset": offset, "limit": limit},
            timeout=timeout,
        )
    def threads_current(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "threads.current", timeout=timeout)
    def threads_context_read(
        self,
        session_id: str,
        tid: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(tid) is not int or tid <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="tid must be a positive integer"),
            )
        return self._dynamic_request(
            session_id,
            "threads.context.read",
            {"tid": tid},
            timeout=timeout,
        )
    def threads_context_write(
        self,
        session_id: str,
        tid: int,
        name: str,
        value: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(tid) is not int or tid <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="tid must be a positive integer"),
            )
        # The schema caps name at 1..16 chars and value at ge=0, but tid was the
        # only argument this handler screened. The agent transport hands it raw
        # model arguments, so without this an over-long register name would be
        # forwarded whole to the worker and a non-integer value would ride a
        # round-trip only to be rejected there. The worker still owns the register
        # allowlist; this just holds the shape the schema promises.
        if not isinstance(name, str) or not 1 <= len(name) <= 16:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="name must be a register name of 1 to 16 characters",
                ),
            )
        if type(value) is not int or value < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="value must be a non-negative integer",
                ),
            )
        return self._dynamic_request(
            session_id,
            "threads.context.write",
            {"tid": tid, "name": name, "value": value},
            timeout=timeout,
        )
    def stack_read(
        self,
        session_id: str,
        *,
        address: int | None = None,
        count: int = 32,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(count) is not int or not 1 <= count <= 256:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="count must be 1..256"),
            )
        params: JsonObject = {"count": count}
        if address is not None:
            if type(address) is not int or address < 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="address must be a non-negative integer",
                    ),
                )
            params["address"] = address
        return self._dynamic_request(session_id, "stack.read", params, timeout=timeout)
    def stack_trace(
        self,
        session_id: str,
        *,
        limit: int = 256,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(limit) is not int or not 1 <= limit <= 256:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="limit must be 1..256"),
            )
        return self._dynamic_request(
            session_id,
            "stack.trace",
            {"limit": limit},
            timeout=timeout,
        )
    def disassembly_read(
        self,
        session_id: str,
        address: int,
        *,
        count: int = 32,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        if type(count) is not int or not 1 <= count <= 256:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="count must be 1..256"),
            )
        return self._dynamic_request(
            session_id,
            "disassembly.read",
            {"address": address, "count": count},
            timeout=timeout,
        )
    def symbols_list(
        self,
        session_id: str,
        module_base: int,
        *,
        limit: int = 256,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(module_base) is not int or module_base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="module_base must be a positive integer",
                ),
            )
        if type(limit) is not int or not 1 <= limit <= 4096:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="limit must be 1..4096"),
            )
        return self._dynamic_request(
            session_id,
            "symbols.list",
            {"module_base": module_base, "limit": limit},
            timeout=timeout,
        )
    def symbols_resolve(
        self,
        session_id: str,
        expression: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(expression, str) or not expression:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="expression must be a non-empty string",
                ),
            )
        return self._dynamic_request(
            session_id,
            "symbols.resolve",
            {"expression": expression},
            timeout=timeout,
        )
    def modules_dump(
        self,
        session_id: str,
        base: int,
        *,
        size: int | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Dump one loaded module image range into a session artifact (paused-only)."""
        if type(base) is not int or base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="base must be a positive integer"),
            )
        if size is not None and (type(size) is not int or size <= 0):
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="size must be a positive integer"),
            )
        if size is not None and size > MAX_MODULE_DUMP_BYTES:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="dump_too_large",
                    message="requested dump exceeds the configured maximum",
                    details={
                        "size": size,
                        "max_dump_bytes": MAX_MODULE_DUMP_BYTES,
                    },
                ),
            )
        output_path: Path | None = None
        try:
            if not session_id or Path(session_id).name != session_id:
                raise ValueError("invalid session id for artifact path")
            directory = self.settings.artifact_root.expanduser().resolve() / "dump" / session_id
            directory.mkdir(parents=True, exist_ok=True)
            # Checked before writing, the way trace.start does. Nothing prunes
            # the artifact root, so a long-running deployment reaches a full
            # volume as a matter of course -- and without this the dump fails
            # partway through as an OSError, which reaches the caller as an
            # internal_error naming neither the disk nor the artifact root.
            wanted = size if size is not None else MAX_MODULE_DUMP_BYTES
            free_bytes = shutil.disk_usage(directory).free
            if free_bytes < wanted:
                raise XdbgRpcError(
                    "insufficient_disk_space",
                    "not enough free space for the requested dump",
                    details={
                        "available_disk_bytes": free_bytes,
                        "required_bytes": wanted,
                        "artifact_root": str(self.settings.artifact_root),
                    },
                )
            output_path = (directory / f"dumped-module-{base:x}-{uuid4().hex}.bin").resolve()
            params: JsonObject = {
                "base": base,
                "output_path": str(output_path),
            }
            if size is not None:
                params["size"] = size
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                self._require_snapshot_fresh_locked(runtime, operation="modules.dump")
                if "modules.dump" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide modules.dump",
                        details={"capability": "modules.dump"},
                    )
                if "modules.list" in runtime.worker.capabilities:
                    before = runtime.worker.request("modules.list", timeout=min(timeout, 30.0))
                    if not _module_base_present(before, base):
                        raise XdbgRpcError(
                            "module_not_found",
                            "module is not loaded at the requested base (pre-dump)",
                            details={"base": base, "race": "pre_dump"},
                            retryable=True,
                        )
                dumped = runtime.worker.request(
                    "modules.dump",
                    params,
                    timeout=min(timeout, 30.0),
                )
                if "modules.list" in runtime.worker.capabilities:
                    after = runtime.worker.request("modules.list", timeout=min(timeout, 30.0))
                    if not _module_base_present(after, base):
                        with suppress(OSError):
                            output_path.unlink(missing_ok=True)
                        raise XdbgRpcError(
                            "module_unloaded_during_dump",
                            "module disappeared while dumping; re-read modules.list",
                            details={"base": base, "race": "post_dump"},
                            retryable=True,
                        )
            data = dict(dumped)
            returned_path = data.get("output_path", output_path)
            try:
                resolved = Path(str(returned_path)).expanduser().resolve()
            except (OSError, RuntimeError, ValueError) as exc:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "modules.dump returned an invalid artifact path",
                ) from exc
            if resolved != output_path:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "modules.dump returned an artifact outside its requested path",
                    details={"expected": str(output_path), "actual": str(returned_path)},
                )
            if not output_path.is_file():
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="artifact_missing",
                        message="modules.dump did not produce the expected artifact file",
                        details={"output_path": str(output_path)},
                    ),
                )
            actual_size = output_path.stat().st_size
            if actual_size > wanted:
                raise XdbgRpcError(
                    "dump_too_large",
                    "modules.dump produced an artifact larger than requested",
                    details={
                        "actual_bytes": actual_size,
                        "max_dump_bytes": wanted,
                    },
                )
            data["output_path"] = str(output_path)
            data["actual_size"] = actual_size
            data["sha256"] = file_sha256(output_path)
            data["artifact_kind"] = "module_dump"
            data["stage_label"] = STAGE_DUMPED
            data["stage_note"] = (
                "dumped only; UI-visible debuggee does not upgrade to iat-rebuilt/runnable"
            )
            path = data.get("output_path")
            sha = data.get("sha256")
            if isinstance(path, str) and isinstance(sha, str):
                art = self.record_artifact(
                    session_id=session_id,
                    kind=str(data.get("artifact_kind") or "module_dump"),
                    path=path,
                    sha256=sha,
                    source="modules.dump",
                )
                data["artifact_id"] = art["id"]
                _timeline_append(
                    self,
                    session_id,
                    "artifact.registered",
                    "module dump registered",
                    artifact_id=art["id"],
                )
            return _success(data, session_id=session_id, backend=BackendKind.X64DBG.value)
        except XdbgRpcError as exc:
            if output_path is not None:
                with suppress(OSError):
                    output_path.unlink(missing_ok=True)
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if output_path is not None:
                with suppress(OSError):
                    output_path.unlink(missing_ok=True)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
    def pe_headers_runtime(
        self,
        session_id: str,
        base: int,
        *,
        save_artifact: bool = True,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Read paused-only runtime PE headers; optionally preserve a header artifact."""
        if type(base) is not int or base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="base must be a positive integer"),
            )
        try:
            params: JsonObject = {"base": base}
            header_path: Path | None = None
            if save_artifact:
                if not session_id or Path(session_id).name != session_id:
                    raise ValueError("invalid session id for artifact path")
                directory = self.settings.artifact_root.expanduser().resolve() / "dump" / session_id
                directory.mkdir(parents=True, exist_ok=True)
                header_path = directory / f"pe-headers-{base:x}-{uuid4().hex}.bin"
                params["output_path"] = str(header_path)
            result = self._dynamic_request(
                session_id,
                "pe.headers.runtime",
                params,
                timeout=timeout,
            )
            if result.ok and result.data is not None and header_path is not None:
                data = dict(result.data)
                if header_path.is_file():
                    data["header_artifact"] = str(header_path)
                    data["header_sha256"] = file_sha256(header_path)
                    # Registered like the module dump beside it: a bare path is
                    # one nothing can read back and collection cannot reclaim.
                    data.update(
                        _register_capture(
                            self,
                            session_id,
                            header_path,
                            kind="pe_headers",
                            source="pe.headers.runtime",
                            payload={},
                        )
                    )
                return Result[JsonObject](ok=True, data=data, meta=result.meta)
            if (
                not result.ok
                and result.error is not None
                and result.error.code in {"method_not_found", "capability_unavailable"}
            ):
                # Fallback: memory.read + Python parser (pre-rebuild native binary).
                read = self.dynamic_memory_read(session_id, base, 0x1000)
                if not read.ok or read.data is None:
                    return result
                hex_data = str(read.data.get("data", ""))
                try:
                    image = bytes.fromhex(hex_data)
                    headers = parse_runtime_headers(image)
                except (ValueError, PeRebuildError) as exc:
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="invalid_pe",
                            message=str(exc),
                        ),
                        meta=read.meta,
                    )
                headers["base"] = base
                headers["source"] = "memory.read_fallback"
                if save_artifact and header_path is not None:
                    header_end = int(headers.get("header_bytes", min(len(image), 0x1000)))
                    _atomic_write_bytes(header_path, image[:header_end])
                    headers["header_artifact"] = str(header_path)
                    headers["header_sha256"] = file_sha256(header_path)
                return _success(headers, session_id=session_id, backend=BackendKind.X64DBG.value)
            return result
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
    def imports_scan(
        self,
        session_id: str,
        module_base: int,
        *,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Scan for candidate IAT ranges; never auto-selects a single winner."""
        if type(module_base) is not int or module_base <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="module_base must be a positive integer",
                ),
            )
        if mode not in {"all", "consecutive", "sparse", "call_site"}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="mode must be consecutive|sparse|call_site|all",
                ),
            )
        params: JsonObject = {
            "module_base": module_base,
            "max_candidates": max_candidates,
            "mode": mode,
        }
        if search_start is not None:
            params["search_start"] = search_start
        if search_size is not None:
            params["search_size"] = search_size
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                self._require_snapshot_fresh_locked(runtime, operation="imports.scan")
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        return self._dynamic_request(
            session_id,
            "imports.scan",
            params,
            timeout=timeout,
        )
    def imports_read(
        self,
        session_id: str,
        iat_va: int,
        size: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Read one caller-confirmed IAT range and resolve thunks against exports."""
        if type(iat_va) is not int or iat_va <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="iat_va must be a positive integer"),
            )
        if type(size) is not int or size <= 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="size must be a positive integer"),
            )
        return self._dynamic_request(
            session_id,
            "imports.read",
            {"iat_va": iat_va, "size": size},
            timeout=timeout,
        )
    def module_catalog(self, session_id: str) -> Result[JsonObject]:
        try:
            runtime, module_result, _ = self._runtime_module_snapshot(session_id)
            catalog = RuntimeModuleCatalog.from_result(module_result)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                runtime.snapshot_resync_required = False
            return _success(
                catalog.to_dict(),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
                snapshot="current",
            )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
    def module_resolve(
        self,
        session_id: str,
        selector: ModuleSelector,
    ) -> Result[JsonObject]:
        return self._explicit_module_operation(session_id, selector, source=None)
    def breakpoints_hardware_set(
        self,
        session_id: str,
        address: int,
        *,
        bp_type: str = "x",
        size: int = 1,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if type(address) is not int or address < 0:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="address must be a non-negative integer",
                ),
            )
        if bp_type not in {"r", "w", "x", "rw", "access", "write", "execute"}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="type must be r|w|x"),
            )
        if size not in {1, 2, 4, 8}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="size must be 1|2|4|8"),
            )
        return self._dynamic_request(
            session_id,
            "breakpoints.hardware.set",
            {"address": address, "type": bp_type, "size": size},
            timeout=timeout,
        )
    def breakpoints_hardware_remove(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.hardware.remove",
            {"address": address},
            timeout=timeout,
        )
    def breakpoints_hardware_list(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "breakpoints.hardware.list", timeout=timeout)
    def breakpoints_memory_set(
        self,
        session_id: str,
        address: int,
        *,
        bp_type: str = "a",
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if bp_type not in {"a", "r", "w", "x", "access", "read", "write", "execute", "rwx"}:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="type must be a|r|w|x"),
            )
        return self._dynamic_request(
            session_id,
            "breakpoints.memory.set",
            {"address": address, "type": bp_type},
            timeout=timeout,
        )
    def breakpoints_memory_remove(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.memory.remove",
            {"address": address},
            timeout=timeout,
        )
    def breakpoints_memory_list(
        self,
        session_id: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "breakpoints.memory.list", timeout=timeout)
    def breakpoints_condition_set(
        self,
        session_id: str,
        address: int,
        expression: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(expression, str) or not expression or len(expression) > 512:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="expression must be a non-empty string up to 512 bytes",
                ),
            )
        if any(ch in expression for ch in ';|&\n\r"\\'):
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_params",
                    message="expression contains unsupported characters",
                ),
            )
        return self._dynamic_request(
            session_id,
            "breakpoints.condition.set",
            {"address": address, "expression": expression},
            timeout=timeout,
        )
    def breakpoints_condition_get(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "breakpoints.condition.get",
            {"address": address},
            timeout=timeout,
        )
    def patches_list(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        return self._dynamic_request(session_id, "patches.list", timeout=timeout)
    def patches_apply(
        self,
        session_id: str,
        address: int,
        data: str,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(data, str) or not data:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="data must be non-empty hex"),
            )
        return self._dynamic_request(
            session_id,
            "patches.apply",
            {"address": address, "data": data},
            timeout=timeout,
        )
    def patches_restore(
        self,
        session_id: str,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        return self._dynamic_request(
            session_id,
            "patches.restore",
            {"address": address},
            timeout=timeout,
        )
    def _runtime_module_snapshot(
        self,
        session_id: str,
    ) -> tuple[_BackendRuntime, JsonObject, JsonObject]:
        runtime = self._runtime(session_id, BackendKind.X64DBG)
        with runtime.lock:
            self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
            if "modules.list" not in runtime.worker.capabilities:
                raise XdbgRpcError(
                    "capability_unavailable",
                    "backend does not provide modules.list",
                    details={"capability": "modules.list"},
                )
            modules = runtime.worker.request("modules.list", timeout=30.0)
            metadata = runtime.worker.metadata
            runtime.snapshot_resync_required = False
        return runtime, modules, metadata
    def _require_snapshot_fresh_locked(
        self,
        runtime: _BackendRuntime,
        *,
        operation: str,
    ) -> None:
        if runtime.snapshot_resync_required:
            raise XdbgRpcError(
                "event_gap_resync_required",
                "debug events were dropped; re-read modules.list/state before continuing",
                details={
                    "operation": operation,
                    "next": ["modules.list", "dynamic.state"],
                },
                retryable=True,
            )
