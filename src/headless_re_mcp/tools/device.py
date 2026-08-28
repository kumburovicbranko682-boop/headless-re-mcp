"""Protocol-independent device.* tool definitions (ADB device control).

No raw-shell tool is exposed on purpose: every device capability is a named,
argument-checked operation, mirroring the debugger surface's refusal to offer a
generic ``dynamic.command``.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_device_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="device.list")
    def device_list() -> dict[str, Any]:
        """List ADB devices and emulators visible to the local adb server.

        Answers with devices (serial and state), count, and has_more. Offline
        and unauthorized serials are included; a missing device is not the
        same as an offline one.
        """
        return _dump(analysis.device_list())

    @tools.tool(name="device.connect")
    def device_connect(
        host: str = "127.0.0.1",
        port: Annotated[int, Field(ge=1, le=65535)] = 5555,
    ) -> dict[str, Any]:
        """Connect to an emulator over TCP (LDPlayer 5555, MuMu 7555, Nox 62001).

        Answers with endpoint, result and connected. connected is true only
        when adb reported a connection. There is no ok, serial or host field.
        A refused TCP connect is an envelope failure, not connected false.
        """
        return _dump(analysis.device_connect(host=host, port=port))

    @tools.tool(name="device.info")
    def device_info(serial: str) -> dict[str, Any]:
        """Return model, SDK, release, and ABI for one device serial.

        Answers with serial, state, model, device, sdk, release and abi.
        There is no SDK, ABI, android_version or version field.
        """
        return _dump(analysis.device_info(serial))

    @tools.tool(name="device.properties")
    def device_properties(
        serial: str, limit: Annotated[int, Field(ge=1, le=2000)] = 500
    ) -> dict[str, Any]:
        """Return getprop key/value pairs for a device.

        Answers with properties (the name-to-value map), count, and has_more
        so a page that filled the cap is not read as every property. There
        is no props or items field.
        """
        return _dump(analysis.device_properties(serial, limit=limit))

    @tools.tool(name="device.packages")
    def device_packages(
        serial: str,
        third_party_only: bool = False,
        limit: Annotated[int, Field(ge=1, le=2000)] = 500,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List installed package names, optionally only third-party ones.

        Answers with packages, count, has_more, and third_party_only so a
        page that filled the cap is not read as every package. name_filter
        keeps only packages whose name contains that substring
        (case-insensitive), applied before the cap so a target package past
        the first `limit` on a device with hundreds installed is still
        findable. The filter runs in-process, not in the on-device pm command,
        so it cannot inject a shell token.
        """
        return _dump(
            analysis.device_packages(
                serial,
                third_party_only=third_party_only,
                limit=limit,
                name_filter=name_filter,
            )
        )

    @tools.tool(name="device.package_paths")
    def device_package_paths(serial: str, package: str) -> dict[str, Any]:
        """Locate an installed package's APK(s) on the device (pm path).

        The bridge from the device line to the static apk line: given a package
        id from device.packages, this returns its on-device APK path(s) so
        device.pull can fetch the file and the apk.* tools can analyse it --
        rather than needing the original APK by hand. Answers with package,
        paths (the base APK plus every split -- the per-density/language/abi
        config APKs an app installed from a bundle carries), count, base_apk
        (the member named base.apk, or the first path when none is), split (true
        when there is more than one path), and paths_truncated when the list hit
        its 64-entry cap. A package that is not installed is not_found; an
        invalid package id is invalid_params. The id is passed as a single argv
        token to pm path, never interpolated into a shell string, so it cannot
        inject a shell command. There is no path field; the list is paths and
        the one to pull first is base_apk.
        """
        return _dump(analysis.device_package_paths(serial, package))

    @tools.tool(name="device.install")
    def device_install(
        serial: str, apk_path: str, reinstall: bool = True
    ) -> dict[str, Any]:
        """Install a local APK onto the device (reinstall keeps data).

        Answers with installed (true/false, or null when it could not be
        verified), path and serial, plus package when the APK's id was
        readable. A return from adb is not by itself a successful install.
        """
        return _dump(analysis.device_install(serial, apk_path, reinstall=reinstall))

    @tools.tool(name="device.uninstall")
    def device_uninstall(serial: str, package: str) -> dict[str, Any]:
        """Uninstall a package from the device.

        Answers with uninstalled (true/false, or null when it could not be
        verified) and package. A return from adb is not by itself removal.
        """
        return _dump(analysis.device_uninstall(serial, package))

    @tools.tool(name="device.launch")
    def device_launch(serial: str, package: str) -> dict[str, Any]:
        """Launch a package's main launcher activity.

        Answers with launched (true/false, or null when the foreground could
        not be read), package, and foreground when known.
        """
        return _dump(analysis.device_launch(serial, package))

    @tools.tool(name="device.force_stop")
    def device_force_stop(serial: str, package: str) -> dict[str, Any]:
        """Force-stop a running package.

        Answers with stopped (true/false, or null when the process list could
        not be read), package, and remaining_pids when known.
        """
        return _dump(analysis.device_force_stop(serial, package))

    @tools.tool(name="device.current_activity")
    def device_current_activity(serial: str) -> dict[str, Any]:
        """Return the current foreground package and activity.

        Answers with package and activity. There is no foreground, current,
        component or app field.
        """
        return _dump(analysis.device_current_activity(serial))

    @tools.tool(name="device.logcat")
    def device_logcat(
        serial: str,
        lines: Annotated[int, Field(ge=1, le=5000)] = 200,
        min_priority: str = "",
    ) -> dict[str, Any]:
        """Return the last N lines of logcat (non-streaming snapshot).

        Answers with lines, requested, and truncated when the dump was cut
        at the character cap. min_priority (one of V, D, I, W, E, F) keeps only
        that log level and above via logcat's own filterspec, so the last N
        lines are the last N matching ones -- pass E to pull just errors from a
        noisy device. An unknown level is invalid_params.
        """
        return _dump(analysis.device_logcat(serial, lines=lines, min_priority=min_priority))

    @tools.tool(name="device.screenshot")
    def device_screenshot(serial: str) -> dict[str, Any]:
        """Capture a device screenshot to a PNG under artifact_root/device/.

        Answers with path, serial and size. The file is not a registered artifact
        -- artifacts.read cannot open it -- only the newest 32 device captures
        are kept, and a file over 64 MiB is deleted and refused.
        """
        return _dump(analysis.device_screenshot(serial))

    @tools.tool(name="device.pull")
    def device_pull(serial: str, remote_path: str) -> dict[str, Any]:
        """Pull a device file to artifact_root/device/.

        Answers with remote, local and size. The file is not a registered artifact
        -- artifacts.read cannot open it -- only the newest 32 device captures
        are kept, and a file over 64 MiB is deleted and refused.
        """
        return _dump(analysis.device_pull(serial, remote_path))

    @tools.tool(name="device.push")
    def device_push(serial: str, local_path: str, remote_path: str) -> dict[str, Any]:
        """Push a local file to a path on the device.

        Answers with local, remote and size. Files over the capture cap are
        refused rather than copied onto the device.
        """
        return _dump(analysis.device_push(serial, local_path, remote_path))

    @tools.tool(name="device.forward")
    def device_forward(serial: str, local: str, remote: str) -> dict[str, Any]:
        """Set an adb forward (e.g. tcp:27042 -> tcp:27042 for frida-server).

        Answers with local and remote. Forwards stay on the adb server until
        close_all or device.forward_remove; this process refuses a new one once
        the table is full -- device.forwards shows what is held and
        device.forward_remove frees a slot.
        """
        return _dump(analysis.device_forward(serial, local, remote))

    @tools.tool(name="device.forwards")
    def device_forwards() -> dict[str, Any]:
        """List the adb forwards this process created and still holds.

        Answers with forwards (each {serial, local, remote}), count, and cap.
        This is the reservation table device.forward counts against: when a
        forward is refused with "too many adb forwards", this shows what is held
        so a slot can be freed with device.forward_remove instead of close_all.
        A forward set by another tool or an earlier process is not listed -- it
        is this process's own table, not adb's global forward list -- and it is
        read from memory, so no serial is taken and it never touches a device.
        """
        return _dump(analysis.device_forwards())

    @tools.tool(name="device.forward_remove")
    def device_forward_remove(serial: str, local: str) -> dict[str, Any]:
        """Remove one adb forward, freeing a slot against the forward cap.

        The per-forward inverse of the close_all teardown: pass the same local
        endpoint device.forward was given (e.g. tcp:27042) to drop just that
        forward. Answers with serial, local, and removed -- removed is true when
        this process was tracking the forward, false when it was not. The call
        still asks adb to drop it either way, so removing one that is already
        gone is an idempotent no-op, not an error.
        """
        return _dump(analysis.device_forward_remove(serial, local))

    return tools.bindings
