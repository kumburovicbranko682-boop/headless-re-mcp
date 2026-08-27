"""JavaScript / WebAssembly static-analysis service methods.

These operate on a local file path (a downloaded bundle or .wasm module), so
they are usable both standalone and against a web session's saved artifacts.
For structural WASM decompilation, point a ghidra.* call (with the
ghidra-wasm-plugin installed) at the same .wasm file.
"""

from __future__ import annotations

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
from headless_re_mcp.core.results import _failure, _success

JsonObject = dict[str, Any]

# js.unpack_bundle writes artifact_root/jsre/unpack-<uuid>/ and never registers
# it: the tool keys by a file path, and the artifact table needs a session_id, so
# the retention walker never sees the tree. Measured without a bound: 20 unpacks
# of 100 x 10 KiB files left 19.5 MiB nothing could reclaim. The directory is
# capped in place by prune_capped_dir (JSRE_UNPACK_MAX_ENTRIES / _BYTES, keeping
# the newest tree), run on every path in js_unpack_bundle so a run that failed
# after webcrack wrote a partial tree is bounded too, not just a clean unpack.


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
            return _success(data, backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)
        finally:
            # In the finally, not only on success: a timeout or a webcrack error
            # can still leave a partial tree on disk, and pruning only on the
            # clean path let those accumulate up to the count cap with no byte
            # bound. prune_capped_dir keeps the newest tree either way.
            if out_dir is not None:
                prune_capped_dir(
                    out_dir.parent,
                    max_entries=JSRE_UNPACK_MAX_ENTRIES,
                    max_bytes=JSRE_UNPACK_MAX_BYTES,
                )

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
