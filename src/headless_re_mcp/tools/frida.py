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
        limit: Annotated[int, Field(ge=1, le=256)] = 64,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List modules in the session target via a short-lived Frida probe.

        Answers with modules (name, base, size, path), count for this page,
        total, and has_more so a page that filled the limit is not read as
        the whole list. name_filter keeps only modules whose name contains
        that substring (case-sensitive), applied before the cap so total is
        the match count -- the only way to reach a module past the first 256,
        and the name frida.exports then needs. The target is the connected
        device's authorized pid when this session has one (frida.device.connect
        + frida.spawn); otherwise the local debuggee.
        """
        return _dump(analysis.frida_modules(session_id, limit=limit, name_filter=name_filter))

    @tools.tool(name="frida.exports")
    def frida_exports(
        session_id: str,
        module_name: str,
        limit: Annotated[int, Field(ge=1, le=512)] = 64,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List exports of one named module in the session debuggee via a Frida probe.

        Answers with found, module, base, and exports (name, address, type),
        plus count and has_more so a page that filled the limit is not read
        as the whole export table. name_filter keeps only exports whose name
        contains that substring (case-sensitive), applied before the cap, so a
        target symbol (e.g. SSL_write) in a big module is findable rather than
        buried past the limit. The target is the connected device's authorized
        pid when this session has one (frida.device.connect + frida.spawn);
        otherwise the local debuggee.
        """
        return _dump(
            analysis.frida_exports(
                session_id, module_name, limit=limit, name_filter=name_filter
            )
        )

    @tools.tool(name="frida.imports")
    def frida_imports(
        session_id: str,
        module_name: str,
        limit: Annotated[int, Field(ge=1, le=512)] = 64,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List the imports one named module resolves, via a short-lived Frida probe.

        The dependency side of frida.exports: which external symbols a native
        module actually calls (libc, libdl, JNI), the first read on an
        unfamiliar .so. Answers with found, module, base, and imports (name,
        type, module -- the providing library, address when bound), plus count
        and has_more so a page that filled the limit is not read as the whole
        import table.         name_filter keeps only imports whose name contains that
        substring (case-sensitive), applied before the cap so a target (e.g.
        dlopen, JNI_OnLoad) is findable rather than buried. The target is the
        connected device's authorized pid when this session has one
        (frida.device.connect + frida.spawn); otherwise the local debuggee.
        """
        return _dump(
            analysis.frida_imports(
                session_id, module_name, limit=limit, name_filter=name_filter
            )
        )

    @tools.tool(name="frida.memory.ranges")
    def frida_memory_ranges(
        session_id: str,
        protection: Annotated[str, Field(pattern="^[r-][w-][x-]$")] = "r--",
        limit: Annotated[int, Field(ge=1, le=256)] = 64,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List the target's mapped memory ranges via a short-lived Frida probe.

        The map that makes frida.memory.read usable: read needs an address, and
        this is how you find which ones are mapped, what they permit, and what is
        backing them (Process.enumerateRanges). Answers with ranges (base, size,
        protection like 'rw-' or 'r-x', file -- the mapped path or '' for
        anonymous), count for this page, total, and has_more so a page that filled
        the limit is not read as the whole map. protection is a three-character
        r/w/x mask where '-' is a wildcard, passed to the enumerator: the default
        'r--' lists the readable regions read can touch, 'rw-' narrows to writable
        ones (where a decrypted key or token lands at runtime), '--x' to
        executable code, '---' to everything. name_filter then keeps only ranges
        whose backing file path contains that substring (case-sensitive), applied
        before the cap so a specific library's mapping (e.g. libssl) is reachable
        rather than buried past the limit -- there is no offset. The target is the
        connected device's authorized pid when this session has one
        (frida.device.connect + frida.spawn); otherwise the local debuggee. The
        list field is ranges. Read-only.
        """
        return _dump(
            analysis.frida_memory_ranges(
                session_id, protection=protection, limit=limit, name_filter=name_filter
            )
        )

    @tools.tool(name="frida.memory.read")
    def frida_memory_read(
        session_id: str, address: int, size: Annotated[int, Field(ge=1, le=262144)] = 16
    ) -> dict[str, Any]:
        """Read up to 256 KiB from the session target via a Frida probe.

        Answers with data holding the hex string and encoding naming the form,
        alongside address and size. The target is the connected device's
        authorized pid when this session has one (frida.device.connect +
        frida.spawn); otherwise the local debuggee. address must be an integer
        in [0, 2**64); an unmapped or protected address is a backend_error, not
        a successful empty read.
        """
        return _dump(analysis.frida_memory_read(session_id, address, size))

    @tools.tool(name="frida.hook.template")
    def frida_hook_template(
        session_id: str,
        template: Annotated[
            str,
            Field(pattern="^(noop|android_ssl_unpin|android_crypto_monitor|android_root_bypass)$"),
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
    ) -> dict[str, Any]:
        """Push and start frida-server on a rooted device/emulator via adb (best-effort).

        Answers with running, pushed and port, plus note when the process is
        not visible. There is no ok field, no started field and no server field.
        Envelope success with running false means the process is not visible.
        """
        return _dump(
            analysis.frida_server_ensure(session_id, serial, server_binary=server_binary, port=port)
        )

    @tools.tool(name="frida.applications")
    def frida_applications(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 256,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List installed applications on the session's connected device.

        Answers with applications (identifier, name, pid), count, total, and
        has_more so a page that filled the limit is not read as the whole
        device. The list field is applications, not apps or packages.
        name_filter keeps only apps whose identifier or name contains that
        substring (case-insensitive), applied before the cap so a target app
        past the first `limit` on a full device is findable; total is then the
        match count.
        """
        return _dump(
            analysis.frida_applications(session_id, limit=limit, name_filter=name_filter)
        )

    @tools.tool(name="frida.processes")
    def frida_processes(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 256,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List running processes on the session's connected device (frida).

        frida.applications lists what is installed; this lists what is running --
        every live process, not just the app ones -- so an app id becomes an
        attachable target. The pid here is frida's own (the device this session
        is bound to), the value frida.attach and the frida.*_device hooks take
        directly; that is the difference from device.processes, which reads adb
        ps and is Android-only. Answers with processes, count, total, and
        has_more so a page that filled the limit is not read as the whole device.
        Each processes row is {pid, name}; rows are ordered by pid. The list
        field is processes, not procs or tasks, and the field to hand frida is
        pid. name_filter keeps only processes whose name contains that substring
        (case-insensitive), applied before the cap so a target past the first
        `limit` on a busy device is findable (there is no offset); total is then
        the match count. Read-only: it only enumerates.
        """
        return _dump(
            analysis.frida_processes(session_id, limit=limit, name_filter=name_filter)
        )

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
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        pid: int = 0,
    ) -> dict[str, Any]:
        """Enumerate loaded Java classes on the authorized device pid (ART only).

        Answers with classes, count, and has_more so a page that filled the
        limit is not read as every loaded class.
        """
        return _dump(
            analysis.frida_java_classes(session_id, name_filter=name_filter, limit=limit, pid=pid)
        )

    @tools.tool(name="frida.java.methods")
    def frida_java_methods(
        session_id: str,
        class_name: str,
        name_filter: str = "",
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        pid: int = 0,
    ) -> dict[str, Any]:
        """List declared methods of a Java class on the authorized device pid (ART only).

        Answers with methods, class_name, count, and has_more so a page that
        filled the limit is not read as every declared method. name_filter
        keeps only methods whose signature contains that substring
        (case-sensitive), applied before the cap, so a target method
        (e.g. doFinal, checkLicense) on a large class is findable rather than
        buried past the limit.
        """
        return _dump(
            analysis.frida_java_methods(
                session_id, class_name, name_filter=name_filter, limit=limit, pid=pid
            )
        )

    return tools.bindings
