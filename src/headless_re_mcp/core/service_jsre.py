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
from headless_re_mcp.core.service_ext import _record_artifact
from headless_re_mcp.core.session import file_sha256

_JSRE_ARTIFACT_SESSION = "jsre"

JsonObject = dict[str, Any]


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
            return _success(self._register_jsre_tree(out_dir, data), backend="webcrack")
        except JsReError as exc:
            return _failure(_as_rpc(exc))
        except BaseException as exc:
            return _failure(exc)

    def _register_jsre_tree(self, out_dir: Path, payload: JsonObject) -> JsonObject:
        """Register every unpacked file so retention can see the tree.

        js.unpack_bundle writes a fresh uuid directory and returns bare paths.
        Measured: 8 unpacks left 541 KiB / 241 files, artifacts.list total=0,
        artifacts.gc collected 0. The files are cheap to regenerate, so they
        belong in the table the collector already walks. Registration must not
        fail the unpack -- the tree exists either way.
        """
        if not out_dir.is_dir():
            return payload
        registered = 0
        try:
            for path in out_dir.rglob("*"):
                if not path.is_file():
                    continue
                _record_artifact(
                    self,
                    session_id=_JSRE_ARTIFACT_SESSION,
                    kind="js_unpack",
                    path=path,
                    sha256=file_sha256(path),
                    source="js.unpack_bundle",
                    size=path.stat().st_size,
                )
                registered += 1
        except BaseException as exc:  # noqa: BLE001 - reported, never raised
            return {
                **payload,
                "registered": registered,
                "artifact_error": str(exc),
            }
        return {
            **payload,
            "registered": registered,
            "artifact_session": _JSRE_ARTIFACT_SESSION,
        }

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
