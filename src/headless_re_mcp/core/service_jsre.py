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
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _register_capture

JsonObject = dict[str, Any]

# js.* tools are session-independent, but the artifact table still needs a
# session key. A reserved id keeps unpack trees listable and reclaimable.
_JSRE_CAPTURE_SESSION = "jsre"


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

    def js_unpack_bundle(self, path: str, timeout: float = 300.0) -> Result[JsonObject]:
        try:
            out_dir = self._jsre_out_dir("unpack")
            data = JsClient(getattr(self.settings, "webcrack", None)).unpack_bundle(
                Path(path), out_dir, timeout=timeout
            )
            return _success(self._register_unpack_tree(out_dir, data), backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def _register_unpack_tree(self, out_dir: Path, payload: JsonObject) -> JsonObject:
        """Register every file the unpack wrote so retention can see them.

        A bare output_dir is a dead end: nothing on the tool surface opens a
        path, and garbage collection only collects rows. Measured: 2500 files,
        0 registered, artifacts.read by path failed.
        """
        ids: list[str] = []
        artifact_error: str | None = None
        if out_dir.is_dir():
            for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
                extra = _register_capture(
                    self,
                    _JSRE_CAPTURE_SESSION,
                    path,
                    kind="js_unpack",
                    source="js.unpack_bundle",
                    payload={},
                )
                if extra.get("artifact_id"):
                    ids.append(str(extra["artifact_id"]))
                elif artifact_error is None and extra.get("artifact_error"):
                    artifact_error = str(extra["artifact_error"])
        result = {**payload, "artifact_ids": ids}
        if artifact_error is not None:
            result["artifact_error"] = artifact_error
        return result

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
