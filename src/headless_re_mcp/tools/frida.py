from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import Field  # noqa: F401 - used by Annotated Field constraints

from headless_re_mcp.backends.frida import HOOK_TEMPLATE_NAMES
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder

# Built from the client's canned-template dict so the tool accepts exactly the
# templates that exist -- see HOOK_TEMPLATE_NAMES. re.escape guards a future
# name that is not a bare identifier; today's are, so the pattern is unchanged.
_HOOK_TEMPLATE_PATTERN = "^(" + "|".join(re.escape(name) for name in HOOK_TEMPLATE_NAMES) + ")$"


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_frida_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="frida.attach")
    def frida_attach(session_id: str) -> dict[str, Any]:
        """Probe-attach Frida to the session debuggee and detach before returning.

        This is not a lasting Frida session: attached is true only for the probe,
        and note says it detached immediately. Limited to the debuggee pid.
        Answers with pid, attached, device and note. There is no session,
        handle or session_id field.
        """
        return _dump(analysis.frida_attach(session_id))

    @tools.tool(name="frida.modules")
    def frida_modules(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 64,
    ) -> dict[str, Any]:
        """List modules in the session debuggee via a short-lived Frida probe.

        Answers with modules (name, base, size, path), count for this page,
        total, offset, and has_more so a page that filled the limit is not
        read as the whole list. Advance offset by the returned count to read
        the next page while has_more is true. Limited to the debuggee pid.
        """
        return _dump(analysis.frida_modules(session_id, offset=offset, limit=limit))

    @tools.tool(name="frida.exports")
    def frida_exports(
        session_id: str,
        module_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=512)] = 64,
    ) -> dict[str, Any]:
        """List exports of one named module in the session debuggee via a Frida probe.

        Answers with found, module, base, and exports (name, address, type),
        plus count for this page, total, offset, and has_more so a page that
        filled the limit is not read as the whole export table. Advance offset
        by the returned count to read the next page while has_more is true (a
        real module's export table runs to thousands of symbols). Limited to the
        debuggee pid.
        """
        return _dump(
            analysis.frida_exports(
                session_id, module_name, offset=offset, limit=limit
            )
        )

    @tools.tool(name="frida.memory.read")
    def frida_memory_read(
        session_id: str, address: int, size: Annotated[int, Field(ge=1, le=262144)] = 16
    ) -> dict[str, Any]:
        """Read up to 256 KiB from the session debuggee via a Frida probe.

        Answers with data holding the hex string and encoding naming the form,
        alongside address and size. Limited to the debuggee pid.
        """
        return _dump(analysis.frida_memory_read(session_id, address, size))

    @tools.tool(name="frida.hook.template")
    def frida_hook_template(
        session_id: str,
        template: Annotated[
            str,
            Field(pattern=_HOOK_TEMPLATE_PATTERN),
        ] = "noop",
    ) -> dict[str, Any]:
        """Load a canned Frida probe template and destroy it before returning.

        Nothing stays hooked: persisted is false and note says so. A device
        session uses its last authorized pid; a PE session uses the debuggee.
        Answers with pid, template, loaded, device, persisted and note.
        There is no hooked, handle or session field.
        """
        return _dump(analysis.frida_hook_template(session_id, template=template))

    @tools.tool(name="frida.devices")
    def frida_devices() -> dict[str, Any]:
        """Enumerate Frida devices (local, USB, remote).

        Answers with devices (id, name, type) and count. There is no items
        field.
        """
        return _dump(analysis.frida_devices())

    @tools.tool(name="frida.device.connect")
    def frida_device_connect(
        session_id: str, device_id: str = "usb", endpoint: str = ""
    ) -> dict[str, Any]:
        """Bind a Frida device to the session (device_id usb/local/<id>, or endpoint host:port).

        Answers with connected and device (id, name, type). There is no top-level device_id or
        ok field. device holds the bound device info; looking for device_id
        after a successful connect reads as a bind that returned no device.
        """
        return _dump(
            analysis.frida_device_connect(session_id, device_id=device_id, endpoint=endpoint)
        )

    @tools.tool(name="frida.server.ensure")
    def frida_server_ensure(
        session_id: str,
        serial: str,
        server_binary: str = "",
        port: Annotated[int, Field(ge=1, le=65535)] = 27042,
        bind_host: str = "127.0.0.1",
    ) -> dict[str, Any]:
        """Push and start frida-server on a rooted device/emulator via adb (best-effort).

        Answers with running, pushed and port, plus note when the process is
        not visible. There is no ok field, no started field and no server field.
        Envelope success with running false means the process is not visible.
        bind_host is the interface frida-server listens on; it defaults to
        127.0.0.1, reachable over the USB/adb transport or an adb forward but
        not from the network. Pass 0.0.0.0 only to reach it by device IP.
        """
        return _dump(
            analysis.frida_server_ensure(
                session_id, serial, server_binary=server_binary, port=port, bind_host=bind_host
            )
        )

    @tools.tool(name="frida.applications")
    def frida_applications(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 256,
    ) -> dict[str, Any]:
        """List installed applications on the session's connected device.

        Answers with applications (identifier, name, pid), count, total, offset,
        and has_more so a page that filled the limit is not read as the whole
        device. Advance offset by the returned count to read the next page while
        has_more is true. The list field is applications, not apps or packages.
        """
        return _dump(analysis.frida_applications(session_id, offset=offset, limit=limit))

    @tools.tool(name="frida.spawn")
    def frida_spawn(session_id: str, package: str) -> dict[str, Any]:
        """Spawn and resume a package on the device, authorizing its pid for this session.

        Answers with pid, package and device. There is no process_id or spawned
        field.
        """
        return _dump(analysis.frida_spawn(session_id, package))

    @tools.tool(name="frida.java.classes")
    def frida_java_classes(
        session_id: str,
        name_filter: str = "",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        pid: int = 0,
    ) -> dict[str, Any]:
        """Enumerate loaded Java classes on the authorized device pid (ART only).

        Answers with classes (sorted), count for this page, total, offset, and
        has_more so a page that filled the limit is not read as every loaded
        class. Advance offset by the returned count to read the next page while
        has_more is true (an ART app has tens of thousands of loaded classes).
        Use name_filter to narrow the set. scan_capped is present when the target
        held more than the probe's 50k enumeration ceiling, so total is a floor.
        """
        return _dump(
            analysis.frida_java_classes(
                session_id, name_filter=name_filter, offset=offset, limit=limit, pid=pid
            )
        )

    @tools.tool(name="frida.java.methods")
    def frida_java_methods(
        session_id: str,
        class_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        pid: int = 0,
    ) -> dict[str, Any]:
        """List declared methods of a Java class on the authorized device pid (ART only).

        Answers with methods (sorted), class_name, found, count for this page,
        total, offset, and has_more so a page that filled the limit is not read
        as every declared method. Advance offset by the returned count to read
        the next page while has_more is true (a generated or framework class can
        declare hundreds of methods). found is false when the class is not loaded
        on the target, which an empty methods list alone cannot distinguish from
        a loaded class that declares none of its own.
        """
        return _dump(
            analysis.frida_java_methods(
                session_id, class_name, offset=offset, limit=limit, pid=pid
            )
        )

    return tools.bindings
