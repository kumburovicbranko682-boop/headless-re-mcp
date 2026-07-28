"""Static analysis operations extracted from AnalysisService (thin facade target)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.core.models import BackendKind, Result, RpcError

from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]

_MAX_STATIC_INLINE_TEXT = 64 * 1024
_MAX_STATIC_BATCH_COMMANDS = 32
_FATAL_WORKER_ERRORS = frozenset(
    {
        "analyzer_window_detected",
        "rpc_peer_mismatch",
        "rpc_protocol_error",
        "rpc_transport_error",
        "worker_exited",
        "worker_protocol_error",
    }
)


class StaticAnalysisMixin:
    """Mixin providing static_* MCP surface methods for AnalysisService."""

    def static_functions(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.functions",
            "functions",
            {"offset": offset, "limit": limit},
        )

    def static_strings(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        max_length: int = 4096,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.strings",
            "strings",
            {"offset": offset, "limit": limit, "max_length": max_length},
        )

    def static_decompile(
        self,
        session_id: str,
        *,
        address: int | None = None,
    ) -> Result[JsonObject]:
        params: JsonObject = {}
        if address is not None:
            params["address"] = address
        result = self._static_request(
            session_id,
            "static.decompile",
            "decompile",
            params,
        )
        if not result.ok or result.data is None:
            return result
        return _success(
            self._maybe_spill_static_text(
                session_id,
                dict(result.data),
                kind="decompile",
                text_key="code",
            ),
            session_id=session_id,
            backend=BackendKind.IDA.value,
        )

    def static_metadata(self, session_id: str) -> Result[JsonObject]:
        return self._static_request(session_id, "static.metadata", "metadata", {})

    def static_segments(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.segments",
            "segments",
            {"offset": offset, "limit": limit},
        )

    def static_imports(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.imports",
            "imports",
            {"offset": offset, "limit": limit},
        )

    def static_exports(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.exports",
            "exports",
            {"offset": offset, "limit": limit},
        )

    def static_entrypoints(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.entrypoints",
            "entrypoints",
            {"offset": offset, "limit": limit},
        )

    def static_disassemble(
        self,
        session_id: str,
        *,
        address: int,
        count: int = 32,
        max_bytes: int = 4096,
    ) -> Result[JsonObject]:
        result = self._static_request(
            session_id,
            "static.disassemble",
            "disassemble",
            {"address": address, "count": count, "max_bytes": max_bytes},
        )
        if not result.ok or result.data is None:
            return result
        data = dict(result.data)
        instructions = data.get("instructions")
        if isinstance(instructions, list):
            rendered = "\n".join(
                str(item.get("text", "")) for item in instructions if isinstance(item, dict)
            )
            if len(rendered) > _MAX_STATIC_INLINE_TEXT:
                spilled = self._maybe_spill_static_text(
                    session_id,
                    {
                        **data,
                        "text": rendered,
                    },
                    kind="disassemble",
                    text_key="text",
                )
                summary_instructions = instructions[:16]
                return _success(
                    {
                        **spilled,
                        "instructions": summary_instructions,
                        "returned": len(summary_instructions),
                        "truncated": True,
                        "full_instruction_count": len(instructions),
                    },
                    session_id=session_id,
                    backend=BackendKind.IDA.value,
                )
        return result

    def static_xrefs_to(
        self,
        session_id: str,
        *,
        address: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.xrefs_to",
            "xrefs_to",
            {"address": address, "offset": offset, "limit": limit},
        )

    def static_xrefs_from(
        self,
        session_id: str,
        *,
        address: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.xrefs_from",
            "xrefs_from",
            {"address": address, "offset": offset, "limit": limit},
        )

    def static_callers(
        self,
        session_id: str,
        *,
        address: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.callers",
            "callers",
            {"address": address, "offset": offset, "limit": limit},
        )

    def static_callees(
        self,
        session_id: str,
        *,
        address: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.callees",
            "callees",
            {"address": address, "offset": offset, "limit": limit},
        )

    def static_basic_blocks(
        self,
        session_id: str,
        *,
        address: int,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.basic_blocks",
            "basic_blocks",
            {"address": address, "offset": offset, "limit": limit},
        )

    def static_cfg(self, session_id: str, *, address: int) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.cfg",
            "cfg",
            {"address": address},
        )

    def static_globals(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.globals",
            "globals",
            {"offset": offset, "limit": limit},
        )

    def static_names(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.names",
            "names",
            {"offset": offset, "limit": limit},
        )

    def static_types(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.types",
            "types",
            {"offset": offset, "limit": limit},
        )

    def static_structs(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.structs",
            "structs",
            {"offset": offset, "limit": limit},
        )

    def static_enums(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.enums",
            "enums",
            {"offset": offset, "limit": limit},
        )

    def static_bytes_read(
        self,
        session_id: str,
        *,
        address: int,
        size: int = 64,
    ) -> Result[JsonObject]:
        return self._static_request(
            session_id,
            "static.bytes.read",
            "bytes_read",
            {"address": address, "size": size},
        )

    def static_search_bytes(
        self,
        session_id: str,
        *,
        pattern: str,
        start: int | None = None,
        end: int | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        params: JsonObject = {
            "pattern": pattern,
            "offset": offset,
            "limit": limit,
        }
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        return self._static_request(
            session_id,
            "static.search.bytes",
            "search_bytes",
            params,
        )

    def static_search_text(
        self,
        session_id: str,
        *,
        text: str,
        start: int | None = None,
        end: int | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        params: JsonObject = {"text": text, "offset": offset, "limit": limit}
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        return self._static_request(
            session_id,
            "static.search.text",
            "search_text",
            params,
        )

    def static_search_immediate(
        self,
        session_id: str,
        *,
        value: int,
        start: int | None = None,
        end: int | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        params: JsonObject = {"value": value, "offset": offset, "limit": limit}
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        return self._static_request(
            session_id,
            "static.search.immediate",
            "search_immediate",
            params,
        )

    def static_name_set(
        self,
        session_id: str,
        *,
        address: int,
        name: str,
    ) -> Result[JsonObject]:
        result = self._static_request(
            session_id,
            "static.name.set",
            "name_set",
            {"address": address, "name": name},
        )
        return self._record_static_patch(session_id, "name.set", result)

    def static_comment_set(
        self,
        session_id: str,
        *,
        address: int,
        comment: str,
        repeatable: bool = False,
    ) -> Result[JsonObject]:
        result = self._static_request(
            session_id,
            "static.comment.set",
            "comment_set",
            {
                "address": address,
                "comment": comment,
                "repeatable": repeatable,
            },
        )
        return self._record_static_patch(session_id, "comment.set", result)

    def static_type_apply(
        self,
        session_id: str,
        *,
        address: int,
        type: str,
    ) -> Result[JsonObject]:
        result = self._static_request(
            session_id,
            "static.type.apply",
            "type_apply",
            {"address": address, "type": type},
        )
        return self._record_static_patch(session_id, "type.apply", result)

    def static_function_create(
        self,
        session_id: str,
        *,
        address: int,
    ) -> Result[JsonObject]:
        result = self._static_request(
            session_id,
            "static.function.create",
            "function_create",
            {"address": address},
        )
        return self._record_static_patch(session_id, "function.create", result)

    def static_function_delete(
        self,
        session_id: str,
        *,
        address: int,
    ) -> Result[JsonObject]:
        result = self._static_request(
            session_id,
            "static.function.delete",
            "function_delete",
            {"address": address},
        )
        return self._record_static_patch(session_id, "function.delete", result)

    def static_bytes_patch(
        self,
        session_id: str,
        *,
        address: int,
        hex: str | None = None,
        base64: str | None = None,
    ) -> Result[JsonObject]:
        params: JsonObject = {"address": address}
        if hex is not None:
            params["hex"] = hex
        if base64 is not None:
            params["base64"] = base64
        result = self._static_request(
            session_id,
            "static.bytes.patch",
            "bytes_patch",
            params,
        )
        return self._record_static_patch(session_id, "bytes.patch", result)

    def static_batch(
        self,
        session_id: str,
        *,
        commands: list[JsonObject],
    ) -> Result[JsonObject]:
        if type(commands) is not list:
            return _failure(
                ValueError("commands must be a list"),
                session_id=session_id,
                backend=BackendKind.IDA.value,
            )
        if len(commands) > _MAX_STATIC_BATCH_COMMANDS:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="invalid_argument",
                    message=(f"static.batch is limited to {_MAX_STATIC_BATCH_COMMANDS} commands"),
                    details={
                        "count": len(commands),
                        "max_items": _MAX_STATIC_BATCH_COMMANDS,
                    },
                ),
            )
        return self._static_request(
            session_id,
            "static.batch",
            "batch",
            {"commands": commands},
        )

    def _static_patch_dir(self, session_id: str) -> Path:
        directory = (
            self.settings.artifact_root.expanduser().resolve() / "static" / session_id / "patches"
        )
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _record_static_patch(
        self,
        session_id: str,
        operation: str,
        result: Result[JsonObject],
    ) -> Result[JsonObject]:
        if not result.ok or result.data is None:
            return result
        payload = dict(result.data)
        directory = self._static_patch_dir(session_id)
        artifact_path = directory / f"{operation.replace('.', '-')}-{uuid4().hex}.json"
        record = {
            "session_id": session_id,
            "operation": operation,
            "payload": payload,
        }
        artifact_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        payload["patch_artifact"] = str(artifact_path)
        try:
            from headless_re_mcp.core.store.timeline import (
                append_session_timeline,
                session_timeline_path,
            )

            append_session_timeline(
                session_timeline_path(self.settings.artifact_root, session_id),
                event=f"static.{operation}",
                message=f"static write {operation}",
                details={
                    "operation": operation,
                    "patch_artifact": str(artifact_path),
                    "address": payload.get("address"),
                },
            )
            payload["timeline_event"] = f"static.{operation}"
        except OSError:
            payload["timeline_write_failed"] = True
        return _success(
            payload,
            session_id=session_id,
            backend=BackendKind.IDA.value,
        )

    def _maybe_spill_static_text(
        self,
        session_id: str,
        data: JsonObject,
        *,
        kind: str,
        text_key: str,
    ) -> JsonObject:
        text = data.get(text_key)
        if not isinstance(text, str) or len(text) <= _MAX_STATIC_INLINE_TEXT:
            return data
        directory = (
            self.settings.artifact_root.expanduser().resolve() / "static" / session_id / "oversized"
        )
        directory.mkdir(parents=True, exist_ok=True)
        artifact_path = directory / f"{kind}-{uuid4().hex}.txt"
        artifact_path.write_text(text, encoding="utf-8")
        preview = text[:1024]
        spilled = dict(data)
        spilled[text_key] = preview
        spilled["artifact"] = str(artifact_path)
        spilled["artifact_bytes"] = len(text.encode("utf-8"))
        spilled["truncated"] = True
        spilled["preview_chars"] = len(preview)
        return spilled

    def _static_request(
        self,
        session_id: str,
        capability: str,
        command: str,
        params: JsonObject,
    ) -> Result[JsonObject]:
        try:
            runtime = self._runtime(session_id, BackendKind.IDA)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.IDA, runtime)
                if capability not in runtime.worker.capabilities:
                    raise IdaWorkerError(
                        "capability_unavailable",
                        f"backend does not provide {capability}",
                        details={"capability": capability},
                    )
                data = runtime.worker.request(command, params)
            return _success(data, session_id=session_id, backend=BackendKind.IDA.value)
        except IdaWorkerError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.IDA)
            return _failure(exc, session_id=session_id, backend=BackendKind.IDA.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.IDA.value)

