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
    JSRE_UNPACK_MAX_BYTES,
    JSRE_UNPACK_MAX_ENTRIES,
    prune_capped_dir,
)
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.results import _failure, _success, backend_error_as_rpc
from headless_re_mcp.core.service_ext import _ensure_repository

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
    return backend_error_as_rpc(exc)


class JsReAnalysisMixin:
    settings: Settings

    def _jsre_out_dir(self, name: str) -> Path:
        root = self.settings.artifact_root.expanduser().resolve() / "jsre"
        root.mkdir(parents=True, exist_ok=True)
        return root / f"{name}-{uuid4().hex}"

    def _jsre_spill_root(self) -> Path:
        """The scratch area a one-shot's oversized output spills into.

        Shared with js.unpack_bundle's unpack-<uuid>/ trees: one capped
        directory keyed by nothing (these tools take a file path, not a session),
        so the artifact table never registers it and only prune_capped_dir keeps
        it bounded. deob/wat/objdump spills land here as files alongside those
        trees and share the same count/byte ceiling.
        """
        root = self.settings.artifact_root.expanduser().resolve() / "jsre"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _prune_jsre_spills(self, root: Path) -> None:
        prune_capped_dir(
            root,
            max_entries=JSRE_UNPACK_MAX_ENTRIES,
            max_bytes=JSRE_UNPACK_MAX_BYTES,
        )

    def js_deobfuscate(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        spill_root = self._jsre_spill_root()
        try:
            data = JsClient(getattr(self.settings, "webcrack", None)).deobfuscate(
                Path(path), timeout=timeout, spill_dir=spill_root
            )
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
        finally:
            self._prune_jsre_spills(spill_root)

    def js_beautify(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        spill_root = self._jsre_spill_root()
        try:
            data = JsClient(getattr(self.settings, "webcrack", None)).beautify(
                Path(path), timeout=timeout, spill_dir=spill_root
            )
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
        finally:
            self._prune_jsre_spills(spill_root)

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
            result: Result[JsonObject] = _success(data, backend="webcrack")
        except JsReError as exc:
            result = _failure(_as_rpc(exc))
        except BaseException as exc:
            result = _failure(exc)
        finally:
            if out_dir is not None:
                prune_jsre_unpack_dirs(out_dir.parent)
        self._audit_unpack_bundle(path, result)
        return result

    def _audit_unpack_bundle(self, path: str, result: Result[JsonObject]) -> None:
        """Record a session-less bundle unpack in the audit log, best-effort.

        js.unpack_bundle writes an unpack-<uuid>/ tree under artifact_root/jsre/
        but keys by a file path, not a session, so -- exactly like
        device.pull/screenshot -- the artifact table (which needs a session_id)
        never registers it and it owns no timeline. This audit line is therefore
        the only provenance the unpacked tree ever gets: which bundle was
        unpacked, where it landed and how many files it produced. Best-effort so
        a bookkeeping failure cannot fail an unpack that already wrote to disk;
        a failed call is recorded with its error code, and only structural
        fields (the output dir and file count) are copied -- the store redacts
        regardless.
        """
        if result.ok and isinstance(result.data, dict):
            summary: JsonObject = {
                name: result.data.get(name) for name in ("output_dir", "file_count")
            }
        else:
            summary = {}
            if result.error is not None:
                summary["code"] = result.error.code
        with suppress(Exception):
            _ensure_repository(self).append_audit(
                session_id=None,
                action="js.unpack_bundle",
                params_summary={"path": path},
                ok=result.ok,
                result_summary=summary,
            )

    def wasm_wat(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        spill_root = self._jsre_spill_root()
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).wat(
                Path(path), timeout=timeout, spill_dir=spill_root
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
        finally:
            self._prune_jsre_spills(spill_root)

    def wasm_info(self, path: str, timeout: float = 120.0) -> Result[JsonObject]:
        spill_root = self._jsre_spill_root()
        try:
            data = WasmClient(getattr(self.settings, "wabt", None)).info(
                Path(path), timeout=timeout, spill_dir=spill_root
            )
            return _success(data, backend="wabt")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
        finally:
            self._prune_jsre_spills(spill_root)
