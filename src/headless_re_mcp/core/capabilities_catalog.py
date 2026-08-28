from __future__ import annotations

from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.doctor import DoctorReport, run_doctor

JsonObject = dict[str, Any]

_CORE_CAPABILITIES: tuple[JsonObject, ...] = (
    {
        "id": "ida.idalib",
        "backend": "ida",
        "status_probe": "ida_idalib",
        "tools": ["static.open", "static.functions", "static.decompile"],
        "summary": "IDA 9.x idalib static analysis",
    },
    {
        "id": "x64dbg.headless",
        "backend": "x64dbg",
        "status_probe": "x64dbg_headless_binaries",
        "tools": ["dynamic.open", "dynamic.launch", "memory.regions"],
        "summary": "Official x64dbg headless RPC",
        "platform": "windows",
    },
    {
        "id": "ui.win32",
        "backend": "ui",
        "status_probe": "win32_ui",
        "tools": [
            "ui.windows.list",
            "ui.click",
            "ui.click_at",
            "ui.window.close",
            "ui.screenshot",
            "ui.virtual_desktop.snapshot",
            "ui.virtual_desktop.capture",
            "ui.ocr",
            "ui.drive_to_event",
        ],
        "summary": "PID-bounded Win32/UIA/OCR/SendInput UI automation (background PostMessage close/click)",
        "platform": "windows",
        "optional": True,
    },
    {
        "id": "detect.die",
        "backend": "die",
        "status_probe": "diec",
        "tools": ["detect.scan"],
        "summary": "Detect It Easy CLI",
    },
    {
        "id": "unpack.upx",
        "backend": "upx",
        "status_probe": "upx",
        "tools": ["unpack.upx.test", "unpack.upx.unpack"],
        "summary": "Official UPX adapter",
    },
    {
        "id": "dotnet.de4dot",
        "backend": "dotnet",
        "status_probe": "de4dot",
        "tools": ["dotnet.deobfuscate", "dotnet.enumerate"],
        "summary": "Bounded .NET deobfuscation",
    },
    {
        "id": "r2.pipe",
        "backend": "radare2",
        "status_probe": "radare2",
        "tools": ["r2.open", "r2.info", "r2.functions", "r2.strings", "r2.imports", "r2.exports", "r2.disasm", "r2.xrefs"],
        "summary": "radare2/rizin whitelist pipe",
        "optional": True,
    },
    {
        "id": "ghidra.headless",
        "backend": "ghidra",
        "status_probe": "ghidra",
        "tools": ["ghidra.analyze", "ghidra.functions", "ghidra.symbols", "ghidra.xrefs", "ghidra.decompile"],
        "summary": "Ghidra analyzeHeadless",
        "optional": True,
    },
    {
        "id": "frida.session",
        "backend": "frida",
        "status_probe": "frida",
        "tools": ["frida.attach", "frida.modules", "frida.exports", "frida.memory.read", "frida.hook.template"],
        "summary": "Session-bound Frida hooks",
        "optional": True,
    },
    {
        "id": "windbg.cdb",
        "backend": "windbg",
        "status_probe": "windbg",
        "tools": ["windbg.open_dump", "windbg.threads", "windbg.modules", "windbg.disasm", "windbg.attach", "windbg.live_threads", "windbg.live_modules", "windbg.live_disasm"],
        "summary": "cdb dump analysis + optional user-mode probe",
        "optional": True,
        "platform": "windows",
    },
    {
        "id": "apk.androguard",
        "backend": "apk",
        "status_probe": "androguard",
        # certificates/components/native_libs go through the same ApkClient parse
        # layer (_apk_call) as manifest/permissions, so they share the androguard
        # probe. They were omitted here while the rest of the parse surface was
        # listed, which left capabilities.describe under-reporting what the
        # androguard line offers; keep the whole in-process parse surface listed.
        "tools": [
            "apk.open",
            "apk.manifest",
            "apk.permissions",
            "apk.certificates",
            "apk.components",
            "apk.native_libs",
            "apk.classes",
            "apk.methods",
            "apk.strings",
            "apk.xrefs",
        ],
        "summary": "In-process APK static analysis via androguard",
        "optional": True,
    },
    {
        "id": "apk.jadx",
        "backend": "apk",
        "status_probe": "jadx",
        "tools": ["apk.decompile", "apk.export_sources"],
        "summary": "jadx Java decompilation (requires jadx + JRE)",
        "optional": True,
    },
    {
        "id": "apk.apktool",
        "backend": "apk",
        "status_probe": "apktool",
        "tools": ["apk.decode", "apk.repack"],
        "summary": "apktool decode/rebuild of resources and smali (requires a JRE)",
        "optional": True,
    },
    {
        # apk.sign is gated on apksigner, not apktool: the client's sign() checks
        # signer_available (apksigner) independently of apktool, so a host with
        # apktool but no apksigner (or vice versa) makes them diverge. Keying this
        # on its own probe stops capabilities.search advertising apk.sign as ready
        # when only apktool is present, or hiding it when only apksigner is.
        "id": "apk.apksigner",
        "backend": "apk",
        "status_probe": "apksigner",
        "tools": ["apk.sign"],
        "summary": "apksigner APK re-signing (requires a JRE)",
        "optional": True,
    },
    {
        "id": "device.adb",
        "backend": "adb",
        "status_probe": "adbutils",
        # Every device.* tool routes through AdbBackend, whose _client() raises
        # capability_unavailable without adbutils, so the whole surface rides the
        # adbutils probe. The list once named only six of the fifteen; the query
        # (info/properties/packages/current_activity), lifecycle (uninstall/
        # force_stop) and file/port (pull/push/forward) tools were omitted while
        # their siblings were advertised, leaving capabilities.describe under-
        # reporting the device line. Keep the whole adbutils-gated surface listed.
        "tools": [
            "device.list",
            "device.connect",
            "device.info",
            "device.properties",
            "device.packages",
            "device.install",
            "device.uninstall",
            "device.launch",
            "device.force_stop",
            "device.current_activity",
            "device.logcat",
            "device.screenshot",
            "device.pull",
            "device.push",
            "device.forward",
        ],
        "summary": "Bounded ADB device/emulator control (no raw shell)",
        "optional": True,
    },
    {
        "id": "frida.device",
        "backend": "frida",
        "status_probe": "frida",
        # frida.applications resolves a device through FridaClient._need() like
        # frida.devices/spawn/java.*, so it is frida-module-gated and belongs on
        # this probe; it was the one enumeration tool left off the list.
        # frida.server.ensure is deliberately NOT here: it pushes and starts
        # frida-server purely over adb and never imports the frida module, so it
        # is gated by adbutils, not frida -- see the frida.server capability.
        "tools": [
            "frida.devices",
            "frida.device.connect",
            "frida.applications",
            "frida.spawn",
            "frida.java.classes",
            "frida.java.methods",
        ],
        "summary": "USB/emulator/remote Frida with per-session target authorization",
        "optional": True,
    },
    {
        # frida.server.ensure sets up frida-server, but its only hard dependency
        # is adbutils: it pushes the binary and su-starts it over adb (see
        # AdbBackend.ensure_frida_server) and never touches the frida Python
        # module -- that module is needed later for attach/spawn, not to ensure.
        # Keying this on the adbutils probe, not frida, is the same probe-vs-gating
        # split that gave apk.sign its own apk.apksigner entry: otherwise
        # capabilities.search would advertise it ready on a host with frida but no
        # adbutils, a call that then fails capability_unavailable.
        "id": "frida.server",
        "backend": "frida",
        "status_probe": "adbutils",
        "tools": ["frida.server.ensure"],
        "summary": "Push and start frida-server on a rooted device/emulator over adb",
        "optional": True,
    },
    {
        "id": "web.cdp",
        "backend": "web",
        "status_probe": "playwright",
        # console/wasm.list/dom.snapshot/har.export are the same CDP observation
        # surface as network.*/scripts/screenshot and ride the same Playwright
        # probe; they were left off the list while their siblings were advertised.
        # web.close is a lifecycle op (no capability lists a close), so it stays
        # out. web.wasm.list is CDP live-module enumeration -- distinct from the
        # wabt static line under wasm.wabt -- and belongs here.
        "tools": [
            "web.open",
            "web.navigate",
            "web.network.list",
            "web.network.get",
            "web.har.export",
            "web.console",
            "web.scripts",
            "web.script.source",
            "web.wasm.list",
            "web.dom.snapshot",
            "web.screenshot",
        ],
        "summary": "Chrome DevTools Protocol driving via Playwright",
        "optional": True,
    },
    {
        "id": "jsre.webcrack",
        "backend": "web",
        "status_probe": "webcrack",
        "tools": ["js.deobfuscate", "js.beautify", "js.unpack_bundle"],
        "summary": "JavaScript deobfuscation and bundle unpacking via webcrack",
        "optional": True,
    },
    {
        "id": "wasm.wabt",
        "backend": "web",
        "status_probe": "wabt",
        "tools": ["wasm.wat"],
        "summary": "WebAssembly text (wat) conversion via wabt wasm2wat",
        "optional": True,
    },
    {
        # wasm.info runs wasm-objdump, which WasmClient resolves independently of
        # wasm2wat and guards with its own capability_unavailable degrade path, so
        # a host with wasm2wat but not wasm-objdump makes the two diverge. Keying
        # wasm.info on the wasm-objdump probe stops capabilities.search advertising
        # it ready when only wasm2wat is present -- a call that then fails
        # capability_unavailable -- the same probe-vs-gating split as apk.sign.
        "id": "wasm.objdump",
        "backend": "web",
        "status_probe": "wabt_objdump",
        "tools": ["wasm.info"],
        "summary": "WebAssembly section/detail dump via wabt wasm-objdump",
        "optional": True,
    },
    {
        "id": "proxy.mitmproxy",
        "backend": "proxy",
        "status_probe": "mitmproxy",
        "tools": ["proxy.start", "proxy.flows", "proxy.flow.get", "proxy.replay", "proxy.export_har", "proxy.ca.install_android"],
        "summary": "In-process HTTP(S) interception via mitmproxy (Web + Android)",
        "optional": True,
    },
)

def _probe_status(report: DoctorReport, name: str | None) -> str:
    if name is None:
        return "ready"
    for probe in report.probes:
        if probe.name == name:
            return probe.status.value
    return "missing"


def list_capabilities(
    settings: Settings | None = None,
    *,
    backend: str | None = None,
    status: str | None = None,
) -> list[JsonObject]:
    report = run_doctor(settings)
    items: list[JsonObject] = []
    for item in _CORE_CAPABILITIES:
        entry = dict(item)
        entry["status"] = _probe_status(report, item.get("status_probe"))
        if backend and entry["backend"] != backend:
            continue
        if status and entry["status"] != status:
            continue
        items.append(entry)
    return items


def describe_capability(
    capability_id: str, settings: Settings | None = None
) -> JsonObject | None:
    for item in list_capabilities(settings):
        if item["id"] == capability_id:
            return item
    return None
