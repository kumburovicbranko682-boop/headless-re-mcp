"""JavaScript / WebAssembly static-analysis service methods.

These operate on a local file path (a downloaded bundle or .wasm module), so
they are usable both standalone and against a web session's saved artifacts.
For structural WASM decompilation, point a ghidra.* call (with the
ghidra-wasm-plugin installed) at the same .wasm file.
"""

from __future__ import annotations

import shutil
from contextlib import suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from headless_re_mcp.backends.jsre import (
    JsClient,
    JsReError,
    WasmClient,
    parse_wasm_calls,
    parse_wasm_data,
    parse_wasm_elements,
    parse_wasm_exports,
    parse_wasm_functions,
    parse_wasm_globals,
    parse_wasm_imports,
    parse_wasm_memory,
    parse_wasm_names,
    parse_wasm_sections,
    parse_wasm_strings,
    parse_wasm_tables,
)
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import (
    JSRE_UNPACK_MAX_BYTES,
    JSRE_UNPACK_MAX_ENTRIES,
    prune_capped_dir,
)
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]

# js.unpack_bundle writes artifact_root/jsre/unpack-<uuid>/ and never
# registers it: the tool keys by a file path, and the artifact table needs
# a session_id. Retention therefore never sees the tree. Measured: 20
# unpacks of 100 x 10 KiB files left 19.5 MiB that nothing could reclaim.
_MAX_JSRE_UNPACK_DIRS = 8


def prune_jsre_unpack_dirs(root: Path, *, keep: int = _MAX_JSRE_UNPACK_DIRS) -> None:
    """Drop the oldest unpack trees once the jsre directory is full."""
    try:
        dirs = [
            path
            for path in root.iterdir()
            if path.is_dir() and path.name.startswith("unpack-")
        ]
    except OSError:
        return
    extra = len(dirs) - max(0, keep)
    if extra <= 0:
        return

    def _mtime(path: Path) -> int:
        try:
            return path.stat().st_mtime_ns
        except OSError:
            return 0

    dirs.sort(key=_mtime)
    for stale in dirs[:extra]:
        with suppress(OSError):
            shutil.rmtree(stale)


def _as_rpc(exc: JsReError) -> XdbgRpcError:
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


class JsReAnalysisMixin:
    settings: Settings

    def _jsre_out_dir(self, name: str) -> Path:
        root = self.settings.artifact_root.expanduser().resolve() / "jsre"
        root.mkdir(parents=True, exist_ok=True)
        return root / f"{name}-{uuid4().hex}"

    def js_deobfuscate(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            data = JsClient(getattr(self.settings, "webcrack", None)).deobfuscate(
                Path(path), timeout=timeout
            )
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def js_beautify(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            data = JsClient(getattr(self.settings, "webcrack", None)).beautify(
                Path(path), timeout=timeout
            )
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def js_unpack_bundle(
        self,
        path: str,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> Result[JsonObject]:
        out_dir: Path | None = None
        try:
            out_dir = self._jsre_out_dir("unpack")
            data = JsClient(getattr(self.settings, "webcrack", None)).unpack_bundle(
                Path(path), out_dir, timeout=timeout, offset=offset, limit=limit
            )
            prune_capped_dir(
                out_dir.parent,
                max_entries=JSRE_UNPACK_MAX_ENTRIES,
                max_bytes=JSRE_UNPACK_MAX_BYTES,
            )
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
        finally:
            if out_dir is not None:
                prune_jsre_unpack_dirs(out_dir.parent)

    def wasm_wat(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).wat(
                Path(path), timeout=timeout
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_info(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).info(
                Path(path), timeout=timeout
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_imports(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_imports(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_exports(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_exports(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_sections(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_sections(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_names(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_names(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_functions(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_functions(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_strings(
        self,
        path: str,
        offset: int = 0,
        limit: int = 100,
        min_length: int = 4,
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_strings(
                Path(path), offset=offset, limit=limit, min_length=min_length
            )
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_globals(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_globals(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_data(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_data(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_memory(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_memory(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_tables(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_tables(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_elements(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_elements(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_calls(
        self, path: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            data = parse_wasm_calls(Path(path), offset=offset, limit=limit)
            return _success(data, backend="jsre")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
