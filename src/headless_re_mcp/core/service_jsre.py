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

from headless_re_mcp.backends.jsre import JsClient, JsReError, WasmClient
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import (
    JSRE_SPILL_MAX_BYTES,
    JSRE_SPILL_MAX_ENTRIES,
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

    def _jsre_spill_dir(self) -> Path:
        """Where the text tools write their full output when it overflows inline.

        A sibling of the unpack trees, kept separate so prune_jsre_unpack_dirs
        (which keys on the ``unpack-`` prefix) never touches these files.
        """
        root = self.settings.artifact_root.expanduser().resolve() / "jsre" / "spill"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _prune_spill(self, spill_dir: Path) -> None:
        prune_capped_dir(
            spill_dir,
            max_entries=JSRE_SPILL_MAX_ENTRIES,
            max_bytes=JSRE_SPILL_MAX_BYTES,
        )

    def js_deobfuscate(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            spill = self._jsre_spill_dir()
            data = JsClient(getattr(self.settings, "webcrack", None)).deobfuscate(
                Path(path), timeout=timeout, spill_dir=spill
            )
            self._prune_spill(spill)
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def js_beautify(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            spill = self._jsre_spill_dir()
            data = JsClient(getattr(self.settings, "webcrack", None)).beautify(
                Path(path), timeout=timeout, spill_dir=spill
            )
            self._prune_spill(spill)
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def js_strings(
        self,
        path: str,
        min_length: int = 1,
        category: str = "",
        contains: str = "",
        offset: int = 0,
        limit: int = 200,
    ) -> Result[JsonObject]:
        try:
            data = JsClient(getattr(self.settings, "webcrack", None)).strings(
                Path(path),
                min_length=min_length,
                category=category,
                contains=contains,
                offset=offset,
                limit=limit,
            )
            return _success(data, backend="jsre")
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
            spill = self._jsre_spill_dir()
            data = WasmClient(getattr(self.settings, "wabt", None)).wat(
                Path(path), timeout=timeout, spill_dir=spill
            )
            self._prune_spill(spill)
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_decompile(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            spill = self._jsre_spill_dir()
            data = WasmClient(getattr(self.settings, "wabt", None)).decompile(
                Path(path), timeout=timeout, spill_dir=spill
            )
            self._prune_spill(spill)
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_info(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        try:
            spill = self._jsre_spill_dir()
            data = WasmClient(getattr(self.settings, "wabt", None)).info(
                Path(path), timeout=timeout, spill_dir=spill
            )
            self._prune_spill(spill)
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_summary(self, path: str, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).summary(
                Path(path), timeout=timeout
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_names(self, path: str, timeout: float = 30.0) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).names(
                Path(path), timeout=timeout
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_functions(
        self,
        path: str,
        offset: int = 0,
        limit: int = 200,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).functions(
                Path(path),
                offset=offset,
                limit=limit,
                timeout=timeout,
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_strings(
        self,
        path: str,
        min_length: int = 4,
        offset: int = 0,
        limit: int = 200,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).strings(
                Path(path),
                min_length=min_length,
                offset=offset,
                limit=limit,
                timeout=timeout,
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def wasm_data(
        self,
        path: str,
        segment: int = 0,
        offset: int = 0,
        limit: int = 65536,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).data(
                Path(path),
                segment=segment,
                offset=offset,
                limit=limit,
                timeout=timeout,
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
