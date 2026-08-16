from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field  # noqa: F401 - used by Annotated Field constraints

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_frida_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="frida.attach")
    def frida_attach(session_id: str) -> dict[str, Any]:
        return _dump(analysis.frida_attach(session_id))

    @tools.tool(name="frida.modules")
    def frida_modules(
        session_id: str, limit: Annotated[int, Field(ge=1, le=256)] = 64
    ) -> dict[str, Any]:
        """List loaded modules for the authorized pid.

        Read `total` and `has_more` rather than assuming the page is complete.
        """
        return _dump(analysis.frida_modules(session_id, limit=limit))

    @tools.tool(name="frida.exports")
    def frida_exports(
        session_id: str,
        module_name: str,
        limit: Annotated[int, Field(ge=1, le=512)] = 64,
    ) -> dict[str, Any]:
        return _dump(analysis.frida_exports(session_id, module_name, limit=limit))

    @tools.tool(name="frida.memory.read")
    def frida_memory_read(
        session_id: str, address: int, size: Annotated[int, Field(ge=1, le=262144)] = 16
    ) -> dict[str, Any]:
        return _dump(analysis.frida_memory_read(session_id, address, size))

    @tools.tool(name="frida.hook.template")
    def frida_hook_template(session_id: str, template: str = "noop") -> dict[str, Any]:
        return _dump(analysis.frida_hook_template(session_id, template=template))

    @tools.tool(name="frida.devices")
    def frida_devices() -> dict[str, Any]:
        """Enumerate Frida devices (local, USB, remote)."""
        return _dump(analysis.frida_devices())

    @tools.tool(name="frida.device.connect")
    def frida_device_connect(
        session_id: str, device_id: str = "usb", endpoint: str = ""
    ) -> dict[str, Any]:
        """Bind a Frida device to the session (device_id usb/local/<id>, or endpoint host:port)."""
        return _dump(
            analysis.frida_device_connect(session_id, device_id=device_id, endpoint=endpoint)
        )

    @tools.tool(name="frida.server.ensure")
    def frida_server_ensure(
        session_id: str,
        serial: str,
        server_binary: str = "",
        port: Annotated[int, Field(ge=1, le=65535)] = 27042,
    ) -> dict[str, Any]:
        """Push and start frida-server on a rooted device/emulator via adb (best-effort)."""
        return _dump(
            analysis.frida_server_ensure(session_id, serial, server_binary=server_binary, port=port)
        )

    @tools.tool(name="frida.applications")
    def frida_applications(
        session_id: str, limit: Annotated[int, Field(ge=1, le=1000)] = 256
    ) -> dict[str, Any]:
        """List installed applications on the session's connected device."""
        return _dump(analysis.frida_applications(session_id, limit=limit))

    @tools.tool(name="frida.spawn")
    def frida_spawn(session_id: str, package: str) -> dict[str, Any]:
        """Spawn and resume a package on the device, authorizing its pid for this session."""
        return _dump(analysis.frida_spawn(session_id, package))

    @tools.tool(name="frida.java.classes")
    def frida_java_classes(
        session_id: str,
        name_filter: str = "",
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        pid: int = 0,
    ) -> dict[str, Any]:
        """Enumerate loaded Java classes on the authorized device pid (ART only)."""
        return _dump(
            analysis.frida_java_classes(session_id, name_filter=name_filter, limit=limit, pid=pid)
        )

    @tools.tool(name="frida.java.methods")
    def frida_java_methods(
        session_id: str,
        class_name: str,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        pid: int = 0,
    ) -> dict[str, Any]:
        """List declared methods of a Java class on the authorized device pid (ART only)."""
        return _dump(analysis.frida_java_methods(session_id, class_name, limit=limit, pid=pid))

    return tools.bindings
