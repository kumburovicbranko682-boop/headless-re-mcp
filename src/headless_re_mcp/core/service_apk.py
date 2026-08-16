"""APK static-analysis service methods (androguard + jadx).

These mirror the static.* surface so the same knowledge/report machinery works
for Android targets. androguard runs in-process; jadx is a bounded subprocess
into a per-session artifact directory, exactly like the Ghidra adapter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk import ApkClient, ApkError
from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.jadx import JadxClient, JadxError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, TargetKind
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import (
    _record_artifact,
    _record_backend,
    _register_capture,
    _timeline_append,
)
from headless_re_mcp.core.session import SessionRegistry, file_sha256

JsonObject = dict[str, Any]


def _as_rpc(exc: ApkError | JadxError | ApktoolError) -> XdbgRpcError:
    return XdbgRpcError(exc.code, exc.message, details=dict(exc.details))


class ApkAnalysisMixin:
    """Bounded APK static analysis, attached to APK-target sessions."""

    settings: Settings
    registry: SessionRegistry

    def _apk_binary(self, session_id: str) -> Path:
        session = self.registry.get(session_id)
        return session.require_target(TargetKind.APK)

    def _jadx_out_dir(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ApkError("invalid_params", "invalid session id")
        root = self.settings.artifact_root.expanduser().resolve()
        return root / "jadx" / session_id

    def apk_open(self, session_id: str) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().open(binary)
            _record_backend(self, session_id, "apk", endpoint="androguard")
            _timeline_append(
                self, session_id, "apk.open", "apk parsed", package=data.get("package")
            )
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_manifest(self, session_id: str) -> Result[JsonObject]:
        return self._apk_call(session_id, "manifest")

    def apk_permissions(self, session_id: str, limit: int = 500) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().permissions(binary, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_certificates(self, session_id: str) -> Result[JsonObject]:
        return self._apk_call(session_id, "certificates")

    def apk_components(self, session_id: str, limit: int = 500) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().components(binary, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_native_libs(self, session_id: str, limit: int = 500) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().native_libs(binary, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_classes(self, session_id: str, offset: int = 0, limit: int = 100) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().classes(binary, offset=offset, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_methods(
        self, session_id: str, class_name: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().methods(binary, class_name, offset=offset, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_strings(self, session_id: str, offset: int = 0, limit: int = 200) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().strings(binary, offset=offset, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_xrefs(self, session_id: str, method_name: str, limit: int = 100) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().xrefs(binary, method_name, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_decompile(
        self, session_id: str, class_name: str, timeout: float = 300.0
    ) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            client = JadxClient(getattr(self.settings, "jadx", None))
            out_dir = self._jadx_out_dir(session_id)
            data = client.decompile(binary, out_dir, class_name, timeout=timeout)
            data = self._register_jadx_tree(session_id, out_dir, data, source="apk.decompile")
            _record_backend(self, session_id, "apk", endpoint=str(out_dir))
            _timeline_append(
                self, session_id, "apk.decompile", "jadx decompiled class", class_name=class_name
            )
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, JadxError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_export_sources(
        self, session_id: str, timeout: float = 300.0, no_imports: bool = False
    ) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            client = JadxClient(getattr(self.settings, "jadx", None))
            out_dir = self._jadx_out_dir(session_id)
            data = client.export_sources(binary, out_dir, timeout=timeout, no_imports=no_imports)
            data = self._register_jadx_tree(
                session_id, out_dir, data, source="apk.export_sources"
            )
            _record_backend(self, session_id, "apk", endpoint=str(out_dir))
            _timeline_append(self, session_id, "apk.export_sources", "jadx exported sources")
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, JadxError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _apktool_client(self) -> ApktoolClient:
        return ApktoolClient(
            getattr(self.settings, "apktool", None),
            getattr(self.settings, "apksigner", None),
        )

    def _repack_dir(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ApkError("invalid_params", "invalid session id")
        root = self.settings.artifact_root.expanduser().resolve() / "apktool" / session_id
        root.mkdir(parents=True, exist_ok=True)
        return root

    def apk_decode(
        self, session_id: str, timeout: float = 600.0, no_resources: bool = False
    ) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            out_dir = self._repack_dir(session_id) / "decoded"
            data = self._apktool_client().decode(
                binary, out_dir, timeout=timeout, no_resources=no_resources
            )
            data = self._register_apktool_tree(
                session_id, out_dir, data, source="apk.decode"
            )
            _record_backend(self, session_id, "apk", endpoint=str(out_dir))
            _timeline_append(self, session_id, "apk.decode", "apktool decoded apk")
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, ApktoolError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_repack(
        self, session_id: str, decoded_dir: str = "", timeout: float = 600.0
    ) -> Result[JsonObject]:
        try:
            self._apk_binary(session_id)
            root = self._repack_dir(session_id)
            source = Path(decoded_dir).expanduser() if decoded_dir.strip() else root / "decoded"
            out_apk = root / "repacked.apk"
            data = self._apktool_client().build(source, out_apk, timeout=timeout)
            # Measured: 8 create/repack/close cycles left 8 APKs and 320 KiB,
            # with artifacts.list total=0 and artifacts.gc collected=0.
            data = _register_capture(
                self,
                session_id,
                out_apk,
                kind="apktool_repack",
                source="apk.repack",
                payload=data,
            )
            _timeline_append(self, session_id, "apk.repack", "apktool rebuilt apk")
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, ApktoolError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_sign(
        self,
        session_id: str,
        apk_path: str = "",
        keystore: str = "",
        keystore_password: str = "",
        key_alias: str = "",
        timeout: float = 300.0,
    ) -> Result[JsonObject]:
        try:
            self._apk_binary(session_id)
            root = self._repack_dir(session_id)
            source = Path(apk_path).expanduser() if apk_path.strip() else root / "repacked.apk"
            out_apk = root / "signed.apk"
            data = self._apktool_client().sign(
                source,
                out_apk,
                keystore=Path(keystore).expanduser() if keystore.strip() else None,
                keystore_password=keystore_password,
                key_alias=key_alias,
                timeout=timeout,
            )
            # Measured: 8 create/sign/close cycles left 8 APKs and 320 KiB,
            # with artifacts.list total=0 and artifacts.gc collected=0.
            data = _register_capture(
                self,
                session_id,
                out_apk,
                kind="apktool_signed",
                source="apk.sign",
                payload=data,
            )
            _timeline_append(self, session_id, "apk.sign", "apksigner signed apk")
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, ApktoolError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _register_apktool_tree(
        self, session_id: str, out_dir: Path, payload: JsonObject, *, source: str
    ) -> JsonObject:
        """Register apktool decode output so a closed session does not leave a dead tree.

        Measured: 8 create/decode/close cycles left 168 files and 321 KiB,
        with artifacts.list total=0 and artifacts.gc collected=0, against a
        15 KiB budget. The tree is cheap to regenerate, so it belongs in the
        table the collector already walks. Registration must not fail decode.
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
                    session_id=session_id,
                    kind="apktool_decode",
                    path=path,
                    sha256=file_sha256(path),
                    source=source,
                    size=path.stat().st_size,
                )
                registered += 1
        except BaseException as exc:  # noqa: BLE001 - reported, never raised
            return {**payload, "registered": registered, "artifact_error": str(exc)}
        return {**payload, "registered": registered}

    def _register_jadx_tree(
        self, session_id: str, out_dir: Path, payload: JsonObject, *, source: str
    ) -> JsonObject:
        """Register jadx output so a closed session does not leave a dead tree.

        Measured: 8 create/export/close cycles left 8 directories, 160 Java
        files and 320 KiB, with artifacts.list total=0. The sources are cheap
        to regenerate, so they belong in the table the collector already walks.
        Registration must not fail the decompile.
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
                    session_id=session_id,
                    kind="jadx_source",
                    path=path,
                    sha256=file_sha256(path),
                    source=source,
                    size=path.stat().st_size,
                )
                registered += 1
        except BaseException as exc:  # noqa: BLE001 - reported, never raised
            return {**payload, "registered": registered, "artifact_error": str(exc)}
        return {**payload, "registered": registered}

    def _apk_call(self, session_id: str, op: str) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            method = getattr(ApkClient(), op)
            data = method(binary)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
