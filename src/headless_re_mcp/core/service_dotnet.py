""".NET inspect / deobfuscate / IL / verify ops."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from headless_re_mcp.core.models import Result, RpcError, SessionState
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _register_capture
from headless_re_mcp.core.session import InvalidStateTransition, file_sha256
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError, inspect_dotnet
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.dotnet.metadata_enum import (
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError

if TYPE_CHECKING:
    from collections.abc import Callable

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.session import SessionRegistry

JsonObject = dict[str, Any]


def _detection_timeout(timeout: float) -> float:
    from headless_re_mcp.core.service import _detection_timeout as real

    return real(timeout)


def _session_owns_artifact_path(artifact_root: Path, session_id: str, target: Path) -> bool:
    from headless_re_mcp.core.service import _session_owns_artifact_path as real

    return real(artifact_root, session_id, target)


def _session_artifact_roots(artifact_root: Path, session_id: str) -> tuple[Path, ...]:
    from headless_re_mcp.core.service import _session_artifact_roots as real

    return real(artifact_root, session_id)


class DotnetAnalysisMixin:
    """.NET inspect / deobfuscate / IL / verify ops.

    The members below are supplied by ``AnalysisService``, which this mixes into.
    """

    settings: Settings
    registry: SessionRegistry
    _de4dot_runner: Callable[..., Any]
    _net_reactor_slayer_runner: Callable[..., Any]

    def dotnet_inspect(
        self,
        session_id: str,
        *,
        require_verified: bool = False,
    ) -> Result[JsonObject]:
        """Inspect CLR headers/metadata; does not run deobfuscators."""
        try:
            session = self.registry.get(session_id)
            if type(require_verified) is not bool:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="require_verified must be a boolean",
                    ),
                )
            report = inspect_dotnet(session.require_pe(), require_verified=require_verified)
            return _success(
                report.to_dict(),
                session_id=session_id,
                backend="dotnet",
            )
        except DotnetInspectError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=exc.code, message=str(exc), details=exc.details),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

    def dotnet_deobfuscate(
        self,
        session_id: str,
        *,
        timeout: float = 120.0,
    ) -> Result[JsonObject]:
        """Run configured de4dot into a session artifact; never overwrite input."""
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"dotnet.deobfuscate cannot run in {session.state.value} state"
                )
            session.require_pe()
            if self.settings.de4dot is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="de4dot CLI is not configured",
                        details={
                            "hint": ("set HEADLESS_RE_DE4DOT to a GPL-licensed de4dot executable")
                        },
                    ),
                )
            inspect = inspect_dotnet(session.require_pe(), require_verified=True)
            current_sha = file_sha256(session.require_pe())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )
            out_dir = self.settings.artifact_root.expanduser().resolve() / "dotnet" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"de4dot-{uuid4().hex}.exe"
            result = self._de4dot_runner(
                self.settings.de4dot,
                session.require_pe(),
                out_path,
                input_sha256=session.sha256,
                timeout=_detection_timeout(timeout),
            )
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"dotnet.deobfuscate cannot run in {session.state.value} state"
                )
            after = inspect_dotnet(result.output_path, require_verified=True)
            # Measured: a 2048-byte de4dot-*.exe listed total=0, gc
            # removed=0, and survived close_all.
            return _success(
                _register_capture(
                    self,
                    session_id,
                    Path(result.output_path),
                    kind="dotnet_deobfuscated",
                    source="dotnet.deobfuscate",
                    payload={
                        "de4dot": result.to_dict(),
                        "before": inspect.to_dict(),
                        "after": after.to_dict(),
                        "input_unchanged": file_sha256(session.require_pe()) == session.sha256,
                        "claims_universal_unpack": False,
                        "stats": {
                            "before": (
                                inspect.metadata_stats.to_dict()
                                if inspect.metadata_stats is not None
                                else None
                            ),
                            "after": (
                                after.metadata_stats.to_dict()
                                if after.metadata_stats is not None
                                else None
                            ),
                            "before_kind": inspect.kind.value,
                            "after_kind": after.kind.value,
                            "note": (
                                "counts from CLR metadata table row counts "
                                "(TypeDef/Method/Field/ManifestResource) and heap sizes"
                            ),
                        },
                    },
                ),
                session_id=session_id,
                backend="dotnet",
            )
        except (DotnetInspectError, De4dotError) as exc:
            code = getattr(exc, "code", "dotnet_failed")
            details = getattr(exc, "details", {}) or {}
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=str(code), message=str(exc), details=dict(details)),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

    def dotnet_reactor_unpack(
        self,
        session_id: str,
        *,
        timeout: float = 120.0,
    ) -> Result[JsonObject]:
        """Optional NETReactorSlayer unpack into a session artifact; never overwrite input."""
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"dotnet.reactor.unpack cannot run in {session.state.value} state"
                )
            session.require_pe()
            if self.settings.net_reactor_slayer is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="NETReactorSlayer CLI is not configured",
                        details={
                            "hint": (
                                "set HEADLESS_RE_NET_REACTOR_SLAYER to a GPL-3.0 "
                                "NETReactorSlayer CLI; authorized Reactor samples only"
                            )
                        },
                    ),
                )
            inspect = inspect_dotnet(session.require_pe(), require_verified=True)
            current_sha = file_sha256(session.require_pe())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )
            out_dir = self.settings.artifact_root.expanduser().resolve() / "dotnet" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"nrs-{uuid4().hex}.exe"
            result = self._net_reactor_slayer_runner(
                self.settings.net_reactor_slayer,
                session.require_pe(),
                out_path,
                input_sha256=session.sha256,
                timeout=_detection_timeout(timeout),
            )
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"dotnet.reactor.unpack cannot run in {session.state.value} state"
                )
            after = inspect_dotnet(result.output_path, require_verified=True)
            # Measured: a 2048-byte nrs-*.exe listed total=0, gc removed=0,
            # and survived close_all.
            return _success(
                _register_capture(
                    self,
                    session_id,
                    Path(result.output_path),
                    kind="dotnet_reactor_unpacked",
                    source="dotnet.reactor.unpack",
                    payload={
                        "net_reactor_slayer": result.to_dict(),
                        "before": inspect.to_dict(),
                        "after": after.to_dict(),
                        "input_unchanged": file_sha256(session.require_pe()) == session.sha256,
                        "claims_universal_unpack": False,
                        "authorized_samples_only": True,
                        "stats": {
                            "before": (
                                inspect.metadata_stats.to_dict()
                                if inspect.metadata_stats is not None
                                else None
                            ),
                            "after": (
                                after.metadata_stats.to_dict()
                                if after.metadata_stats is not None
                                else None
                            ),
                            "before_kind": inspect.kind.value,
                            "after_kind": after.kind.value,
                        },
                    },
                ),
                session_id=session_id,
                backend="dotnet",
            )
        except (DotnetInspectError, NetReactorSlayerError) as exc:
            code = getattr(exc, "code", "dotnet_failed")
            details = getattr(exc, "details", {}) or {}
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=str(code), message=str(exc), details=dict(details)),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

    def dotnet_enumerate(
        self,
        session_id: str,
        kind: str,
        *,
        offset: int = 0,
        limit: int = 64,
        require_verified: bool = True,
    ) -> Result[JsonObject]:
        """Paginated metadata enumeration (dotnet_metadata; not ida_idalib)."""
        try:
            session = self.registry.get(session_id)
            page = enumerate_metadata(
                session.require_pe(),
                kind,
                offset=offset,
                limit=limit,
                require_verified=require_verified,
            )
            return _success(page.to_dict(), session_id=session_id, backend="dotnet")
        except DotnetInspectError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=exc.code, message=str(exc), details=exc.details),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

    def dotnet_il(
        self,
        session_id: str,
        method_token: int,
        *,
        require_verified: bool = True,
    ) -> Result[JsonObject]:
        """Bounded CIL subset disassembly for a MethodDef token."""
        try:
            session = self.registry.get(session_id)
            payload = disassemble_method_il(
                session.require_pe(),
                method_token,
                require_verified=require_verified,
            )
            return _success(payload, session_id=session_id, backend="dotnet")
        except DotnetInspectError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=exc.code, message=str(exc), details=exc.details),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

    def dotnet_xrefs(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 64,
        require_verified: bool = True,
    ) -> Result[JsonObject]:
        """Weak MemberRef xref listing (not a full callgraph)."""
        try:
            session = self.registry.get(session_id)
            page = list_memberref_xrefs(
                session.require_pe(),
                offset=offset,
                limit=limit,
                require_verified=require_verified,
            )
            return _success(page.to_dict(), session_id=session_id, backend="dotnet")
        except DotnetInspectError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=exc.code, message=str(exc), details=exc.details),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

    def dotnet_verify(
        self,
        session_id: str,
        path: str,
        *,
        require_verified: bool = True,
    ) -> Result[JsonObject]:
        """Re-inspect a .NET artifact with the built-in CLR metadata checker."""
        try:
            self.registry.get(session_id)
            # path is schema-typed as a string, but the agent and OpenAI-bridge
            # transports bind it from model output with no pydantic coercion. Path()
            # raises a raw TypeError on a non-str, non-PathLike value (an int, list,
            # dict, ...), which the outer except BaseException would file as a logged
            # internal_error incident rather than the invalid_params the sibling
            # out-of-tree path check below already returns for a bad path.
            if not isinstance(path, str):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="path must be a string",
                        details={"session_id": session_id},
                    ),
                )
            target = Path(path).expanduser().resolve(strict=True)
            owned = _session_owns_artifact_path(
                self.settings.artifact_root,
                session_id,
                target,
            )
            if not owned:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message=(
                            "path must be inside the current session artifact "
                            "directory (dotnet/unpack/dump/detection)"
                        ),
                        details={
                            "path": str(target),
                            "session_id": session_id,
                            "allowed_roots": [
                                str(root)
                                for root in _session_artifact_roots(
                                    self.settings.artifact_root,
                                    session_id,
                                )
                            ],
                        },
                    ),
                )
            report = inspect_dotnet(target, require_verified=require_verified)
            return _success(
                {
                    "verify": report.to_dict(),
                    "ok": report.verified_clr,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="dotnet",
            )
        except DotnetInspectError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code=exc.code, message=str(exc), details=exc.details),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="dotnet")

