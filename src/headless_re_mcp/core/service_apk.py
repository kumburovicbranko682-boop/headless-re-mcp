"""APK static-analysis service methods (androguard + jadx).

These mirror the static.* surface so the same knowledge/report machinery works
for Android targets. androguard runs in-process; jadx is a bounded subprocess
into a per-session artifact directory, exactly like the Ghidra adapter.
"""

from __future__ import annotations

import shutil
from contextlib import suppress
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk import ApkClient, ApkError
from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.jadx import JadxClient, JadxError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, _dir_size
from headless_re_mcp.core.models import Result, SessionState, TargetKind
from headless_re_mcp.core.results import _failure, _success, backend_error_as_rpc
from headless_re_mcp.core.service_ext import (
    _record_backend,
    _register_capture,
    _timeline_append,
)
from headless_re_mcp.core.session import InvalidStateTransition, SessionRegistry

JsonObject = dict[str, Any]


def _refuse_oversized_tree(path: Path, *, kind: str, error_type: type) -> None:
    if not path.exists():
        return
    try:
        size = _dir_size(path) if path.is_dir() else int(path.stat().st_size)
    except OSError:
        return
    if size <= UNREGISTERED_CAPTURE_MAX_BYTES:
        return
    with suppress(OSError):
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    raise error_type(
        "too_large",
        f"{kind} tree exceeds capture cap",
        size=size,
        cap=UNREGISTERED_CAPTURE_MAX_BYTES,
    )


def _as_rpc(exc: ApkError | JadxError | ApktoolError) -> XdbgRpcError:
    return backend_error_as_rpc(exc)


class ApkAnalysisMixin:
    """Bounded APK static analysis, attached to APK-target sessions."""

    settings: Settings
    registry: SessionRegistry

    def _apk_binary(self, session_id: str) -> Path:
        session = self.registry.get(session_id)
        if session.state in {
            SessionState.CLOSING,
            SessionState.CLOSED,
            SessionState.FAILED,
        }:
            raise InvalidStateTransition(
                f"apk tools cannot run in {session.state.value} state"
            )
        return session.require_target(TargetKind.APK)

    def _jadx_out_dir(self, session_id: str) -> Path:
        from headless_re_mcp.core.service import _is_safe_session_segment

        if not _is_safe_session_segment(session_id):
            raise ApkError("invalid_params", "invalid session id")
        root = self.settings.artifact_root.expanduser().resolve()
        return root / "jadx" / session_id

    def _apk_capture_dir(self, session_id: str) -> Path:
        # Where apk.manifest spills an oversized manifest. Computed, not created:
        # the common (non-truncated) manifest read must not litter an empty dir,
        # so the backend mkdirs this only on the rare spill.
        from headless_re_mcp.core.service import _is_safe_session_segment

        if not _is_safe_session_segment(session_id):
            raise ApkError("invalid_params", "invalid session id")
        root = self.settings.artifact_root.expanduser().resolve()
        return root / "apk" / session_id

    def apk_open(self, session_id: str) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().open(binary)
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"apk.open cannot run in {session.state.value} state"
                )
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
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().manifest(binary, spill_dir=self._apk_capture_dir(session_id))
            # Only the oversized-manifest branch produced a spill file; register
            # it so artifacts.read can open the full XML and retention can reclaim
            # it, exactly as web.dom.snapshot does for a spilled DOM.
            spill = data.get("manifest_xml_path")
            if isinstance(spill, str):
                data = _register_capture(
                    self,
                    session_id,
                    Path(spill),
                    kind="apk_manifest",
                    source="apk.manifest",
                    payload=data,
                )
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_permissions(self, session_id: str) -> Result[JsonObject]:
        return self._apk_call(session_id, "permissions")

    def apk_certificates(self, session_id: str) -> Result[JsonObject]:
        return self._apk_call(session_id, "certificates")

    def apk_components(self, session_id: str) -> Result[JsonObject]:
        return self._apk_call(session_id, "components")

    def apk_native_libs(self, session_id: str) -> Result[JsonObject]:
        return self._apk_call(session_id, "native_libs")

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

    def apk_xrefs(
        self, session_id: str, method_name: str, offset: int = 0, limit: int = 100
    ) -> Result[JsonObject]:
        try:
            binary = self._apk_binary(session_id)
            data = ApkClient().xrefs(binary, method_name, offset=offset, limit=limit)
            return _success(data, session_id=session_id, backend="apk")
        except ApkError as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def apk_decompile(
        self, session_id: str, class_name: str, timeout: float = 300.0
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"apk.decompile cannot run in {session.state.value} state"
                )
            binary = self._apk_binary(session_id)
            client = JadxClient(getattr(self.settings, "jadx", None))
            out_dir = self._jadx_out_dir(session_id)
            data = client.decompile(binary, out_dir, class_name, timeout=timeout)
            _refuse_oversized_tree(out_dir, kind="jadx", error_type=JadxError)
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"apk.decompile cannot run in {session.state.value} state"
                    )
            except BaseException:
                # close already ran _forget_session_work_dirs; a tree written
                # after that is invisible to the next close and to artifacts.gc.
                with suppress(OSError):
                    if out_dir.is_dir():
                        shutil.rmtree(out_dir)
                raise
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
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"apk.export_sources cannot run in {session.state.value} state"
                )
            binary = self._apk_binary(session_id)
            client = JadxClient(getattr(self.settings, "jadx", None))
            out_dir = self._jadx_out_dir(session_id)
            data = client.export_sources(binary, out_dir, timeout=timeout, no_imports=no_imports)
            _refuse_oversized_tree(out_dir, kind="jadx", error_type=JadxError)
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"apk.export_sources cannot run in {session.state.value} state"
                    )
            except BaseException:
                # close already ran _forget_session_work_dirs; a tree written
                # after that is invisible to the next close and to artifacts.gc.
                with suppress(OSError):
                    if out_dir.is_dir():
                        shutil.rmtree(out_dir)
                raise
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
        from headless_re_mcp.core.service import _is_safe_session_segment

        if not _is_safe_session_segment(session_id):
            raise ApkError("invalid_params", "invalid session id")
        root = self.settings.artifact_root.expanduser().resolve() / "apktool" / session_id
        root.mkdir(parents=True, exist_ok=True)
        return root

    def apk_decode(
        self, session_id: str, timeout: float = 600.0, no_resources: bool = False
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"apk.decode cannot run in {session.state.value} state"
                )
            binary = self._apk_binary(session_id)
            root = self._repack_dir(session_id)
            out_dir = root / "decoded"
            data = self._apktool_client().decode(
                binary, out_dir, timeout=timeout, no_resources=no_resources
            )
            _refuse_oversized_tree(out_dir, kind="apktool", error_type=ApktoolError)
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"apk.decode cannot run in {session.state.value} state"
                    )
            except BaseException:
                # close already ran _forget_session_work_dirs; a tree written
                # after that is invisible to the next close and to artifacts.gc.
                with suppress(OSError):
                    shutil.rmtree(root)
                raise
            _record_backend(self, session_id, "apk", endpoint=str(out_dir))
            _timeline_append(self, session_id, "apk.decode", "apktool decoded apk")
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, ApktoolError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

    def _require_session_path(self, session_id: str, path: Path, *, what: str) -> Path:
        from headless_re_mcp.core.service import _session_owns_artifact_path

        resolved = path.expanduser().resolve()
        if not _session_owns_artifact_path(self.settings.artifact_root, session_id, resolved):
            raise ApkError(
                "invalid_params",
                f"{what} must be inside the session artifact tree",
                path=str(resolved),
            )
        return resolved

    def apk_repack(
        self, session_id: str, decoded_dir: str = "", timeout: float = 600.0
    ) -> Result[JsonObject]:
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"apk.repack cannot run in {session.state.value} state"
                )
            self._apk_binary(session_id)
            root = self._repack_dir(session_id)
            source = Path(decoded_dir).expanduser() if decoded_dir.strip() else root / "decoded"
            source = self._require_session_path(session_id, source, what="decoded_dir")
            out_apk = root / "repacked.apk"
            data = self._apktool_client().build(source, out_apk, timeout=timeout)
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"apk.repack cannot run in {session.state.value} state"
                    )
            except BaseException:
                # close already ran _forget_session_work_dirs; a rebuild written
                # after that is invisible to the next close and to artifacts.gc.
                with suppress(OSError):
                    shutil.rmtree(root)
                raise
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
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"apk.sign cannot run in {session.state.value} state"
                )
            self._apk_binary(session_id)
            root = self._repack_dir(session_id)
            source = Path(apk_path).expanduser() if apk_path.strip() else root / "repacked.apk"
            source = self._require_session_path(session_id, source, what="apk_path")
            out_apk = root / "signed.apk"
            keystore_path = (
                self._require_session_path(
                    session_id, Path(keystore).expanduser(), what="keystore"
                )
                if keystore.strip()
                else None
            )
            data = self._apktool_client().sign(
                source,
                out_apk,
                keystore=keystore_path,
                keystore_password=keystore_password,
                key_alias=key_alias,
                timeout=timeout,
            )
            try:
                session = self.registry.get(session_id)
                if session.state in {
                    SessionState.CLOSING,
                    SessionState.CLOSED,
                    SessionState.FAILED,
                }:
                    raise InvalidStateTransition(
                        f"apk.sign cannot run in {session.state.value} state"
                    )
            except BaseException:
                # close already ran _forget_session_work_dirs; a signed APK
                # written after that is invisible to the next close and to
                # artifacts.gc.
                with suppress(OSError):
                    shutil.rmtree(root)
                raise
            _timeline_append(self, session_id, "apk.sign", "apksigner signed apk")
            return _success(data, session_id=session_id, backend="apk")
        except (ApkError, ApktoolError) as exc:
            return _failure(_as_rpc(exc), session_id=session_id)
        except BaseException as exc:
            return _failure(exc, session_id=session_id)

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
