"""Application-service composition used by the public compatibility façade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.repository import AnalysisRepository
from headless_re_mcp.core.runtime_state import (
    BackendRuntimeOwner,
    DebuggeeStateOwner,
    TraceStateOwner,
    UnpackStateOwner,
    WorkflowStateOwner,
)
from headless_re_mcp.core.session import SessionNotFound


def _page_bound(value: object, name: str) -> int:
    """Coerce one paging bound to int, or raise ValueError for the caller.

    Both repositories (in-memory and sqlite) fed offset/limit straight to
    ``int(...)`` and only then clamped. The list.* schemas type both as
    integers, but the agent and OpenAI-bridge transports bind them from model
    output with no pydantic coercion, so a null/list/dict raised TypeError --
    filed as an internal_error incident by the service's ``except
    BaseException`` -- an inf (a JSON 1e400 parsed to float) raised
    OverflowError the same way, and a non-numeric string raised a ValueError
    whose "invalid literal for int()" text echoed the caller's value back.
    Coerce here, at the one place both stores share, so a bad page window is
    the invalid_request caller fault it is instead of a store crash, while the
    numeric strings and floats int() already accepted still work. A bool is an
    int subclass but never a real page coordinate.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


class ServicePort(Protocol):
    """Narrow callable surface delegated by domain-specific application services."""

    def __getattribute__(self, name: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class RuntimeApplicationService:
    """Own backend lifecycle coordination and runtime command dispatch."""

    facade: ServicePort
    state: BackendRuntimeOwner[Any]

    def open_static(self, session_id: str) -> Result[dict[str, Any]]:
        return cast(Result[dict[str, Any]], self.facade._open_static(session_id))

    def open_dynamic(self, session_id: str) -> Result[dict[str, Any]]:
        return cast(Result[dict[str, Any]], self.facade._open_dynamic(session_id))

    def close_session(self, session_id: str) -> Result[dict[str, Any]]:
        return cast(Result[dict[str, Any]], self.facade._close_session(session_id))

    def call(self, operation: str, *args: object, **kwargs: object) -> Any:
        return getattr(self.facade, operation)(*args, **kwargs)


@dataclass(frozen=True, slots=True)
class DynamicApplicationService:
    """Own debuggee run-control coordination and state projection."""

    facade: ServicePort
    debuggee: DebuggeeStateOwner

    def state(self, session_id: str) -> Result[dict[str, Any]]:
        return cast(Result[dict[str, Any]], self.facade._dynamic_state(session_id))

    def call(self, operation: str, *args: object, **kwargs: object) -> Any:
        return getattr(self.facade, operation)(*args, **kwargs)


@dataclass(frozen=True, slots=True)
class InteractionApplicationService:
    """Own PID-bounded UI interaction orchestration."""

    facade: ServicePort

    def call(self, operation: str, *args: object, **kwargs: object) -> Any:
        return getattr(self.facade, operation)(*args, **kwargs)

    def windows_list(
        self, session_id: str, **kwargs: object
    ) -> Result[dict[str, Any]]:
        return cast(
            Result[dict[str, Any]],
            self.facade._ui_windows_list(session_id, **kwargs),
        )


@dataclass(frozen=True, slots=True)
class ArtifactApplicationService:
    """Own artifact, timeline, audit, and persistence interactions."""

    facade: ServicePort
    repository: AnalysisRepository

    def list_artifacts(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> Any:
        offset = _page_bound(offset, "offset")
        limit = _page_bound(limit, "limit")
        return self.repository.list_artifacts(session_id, offset=offset, limit=limit)

    def describe_artifact(self, artifact_id: str) -> Any:
        return self.repository.describe_artifact(artifact_id)

    def record_knowledge(
        self,
        *,
        session_id: str,
        kind: str,
        key: str,
        value: dict[str, Any],
    ) -> Any:
        return self.repository.record_knowledge(
            session_id=session_id,
            kind=kind,
            key=key,
            value=value,
        )

    def list_knowledge(
        self,
        session_id: str,
        *,
        kind: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> Any:
        offset = _page_bound(offset, "offset")
        limit = _page_bound(limit, "limit")
        return self.repository.list_knowledge(
            session_id,
            kind=kind,
            offset=offset,
            limit=limit,
        )

    def gc_artifacts(self, *, max_total_bytes: int) -> Any:
        return self.repository.gc_artifacts(max_total_bytes=max_total_bytes)

    def list_timeline(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> Any:
        """Read one session's timeline, or say the session is not there.

        Asking about a session that does not exist used to answer ok with an
        empty list, which reads as "that analysis did nothing" rather than
        "there is no such analysis". An agent holding an id from before a
        restart would take the first for an answer. Every other session-scoped
        call reports session_not_found, and a KeyError is what produces it.
        """
        offset = _page_bound(offset, "offset")
        limit = _page_bound(limit, "limit")
        page = self.repository.list_timeline(session_id, offset=offset, limit=limit)
        if isinstance(page, dict) and page.get("exists") is False:
            raise SessionNotFound.for_id(session_id)
        return page

    def list_audit(
        self,
        session_id: str | None = None,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> Any:
        offset = _page_bound(offset, "offset")
        limit = _page_bound(limit, "limit")
        return self.repository.list_audit(session_id, offset=offset, limit=limit)

    def call(self, operation: str, *args: object, **kwargs: object) -> Any:
        return getattr(self.facade, operation)(*args, **kwargs)


@dataclass(frozen=True, slots=True)
class ApplicationServices:
    """Static composition root exposed by ``AnalysisService`` as a compatibility façade."""

    runtime: RuntimeApplicationService
    dynamic: DynamicApplicationService
    interaction: InteractionApplicationService
    artifacts: ArtifactApplicationService
    workflow_state: WorkflowStateOwner[Any]
    unpack_state: UnpackStateOwner[Any]
    trace_state: TraceStateOwner[Any]
