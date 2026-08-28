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
        "tools": ["r2.open", "r2.info", "r2.functions", "r2.strings", "r2.strings_all", "r2.imports", "r2.exports", "r2.sections", "r2.symbols", "r2.entrypoints", "r2.disasm", "r2.disasm_function", "r2.xrefs", "r2.read", "r2.search", "r2.libs", "r2.relocations", "r2.resolve"],
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
        "tools": ["apk.open", "apk.manifest", "apk.permissions", "apk.classes", "apk.class_summary", "apk.subclasses", "apk.class_xrefs", "apk.methods", "apk.method_bytecode", "apk.method_refs", "apk.fields", "apk.strings", "apk.xrefs", "apk.string_xrefs", "apk.field_xrefs", "apk.extract_native_lib"],
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
        "tools": ["apk.decode", "apk.repack", "apk.sign"],
        "summary": "apktool decode/rebuild plus apksigner re-signing (requires a JRE)",
        "optional": True,
    },
    {
        "id": "device.adb",
        "backend": "adb",
        "status_probe": "adbutils",
        "tools": ["device.list", "device.connect", "device.install", "device.launch", "device.logcat", "device.screenshot"],
        "summary": "Bounded ADB device/emulator control (no raw shell)",
        "optional": True,
    },
    {
        "id": "frida.device",
        "backend": "frida",
        "status_probe": "frida",
        "tools": ["frida.devices", "frida.device.connect", "frida.spawn", "frida.java.classes", "frida.java.methods"],
        "summary": "USB/emulator/remote Frida with per-session target authorization",
        "optional": True,
    },
    {
        "id": "web.cdp",
        "backend": "web",
        "status_probe": "playwright",
        "tools": ["web.open", "web.navigate", "web.network.list", "web.network.get", "web.ws.list", "web.ws.frames", "web.cookies", "web.storage", "web.frames", "web.scripts", "web.script.source", "web.screenshot"],
        "summary": "Chrome DevTools Protocol driving via Playwright",
        "optional": True,
    },
    {
        "id": "jsre.webcrack",
        "backend": "web",
        "status_probe": "webcrack",
        "tools": ["js.deobfuscate", "js.beautify", "js.strings", "js.unpack_bundle"],
        "summary": "JavaScript deobfuscation and bundle unpacking via webcrack",
        "optional": True,
    },
    {
        "id": "wasm.wabt",
        "backend": "web",
        "status_probe": "wabt",
        "tools": ["wasm.decompile", "wasm.info", "wasm.wat", "wasm.summary", "wasm.names", "wasm.strings", "wasm.data"],
        "summary": "WebAssembly inspection via wabt (wasm2wat, wasm-objdump, wasm-decompile)",
        "optional": True,
    },
    {
        "id": "proxy.mitmproxy",
        "backend": "proxy",
        "status_probe": "mitmproxy",
        "tools": ["proxy.start", "proxy.flows", "proxy.stats", "proxy.search", "proxy.flow.get", "proxy.ws.frames", "proxy.ws.search", "proxy.replay", "proxy.export_har", "proxy.ca.install_android"],
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
