"""Loopback Web command adapter backed by the shared command catalog."""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandCatalog, CommandTransport
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class WebCommandAdapter:
    """Validate the bounded Web write surface before invoking the façade."""

    def __init__(
        self,
        service: AnalysisService,
        catalog: CommandCatalog = COMMAND_CATALOG,
    ) -> None:
        self._service = service
        self._catalog = catalog

    @property
    def write_methods(self) -> frozenset[str]:
        return self._catalog.write_names(CommandTransport.WEB)

    def invoke_write(self, action: str, body: JsonObject) -> Result[JsonObject]:
        spec = self._catalog.get(action)
        if (
            spec is None
            or CommandTransport.WEB not in spec.transports
            or not spec.write
        ):
            raise KeyError(action)
        session_id = body.get("session_id")
        method = getattr(self._service, spec.service_method)
        if action == "artifacts.gc":
            max_bytes = int(body.get("max_total_bytes") or (512 * 1024 * 1024))
            return cast(Result[JsonObject], method(max_total_bytes=max_bytes))
        if not isinstance(session_id, str):
            raise ValueError("session_id_required")
        return cast(Result[JsonObject], method(session_id))
