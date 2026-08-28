"""Protocol-independent macho.* tool definitions (macOS/iOS binary triage)."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_macho_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="macho.summary")
    def macho_summary(path: str) -> dict[str, Any]:
        """Summarise a Mach-O binary (macOS/iOS executable or dylib), stdlib-only.

        With PE covered by a whole tool line and ELF by elf.summary/elf.symbols,
        Mach-O -- a macOS dylib, an iOS app's main binary, a Mach-O malware
        sample -- was the one native format that could not be opened here at
        all. This reads one by path with no external tool: the offline
        otool -h -l / vtool triage.

        A thin image answers with bits, endianness, cpu (x86-64, AArch64, ...),
        filetype (executable / dylib / bundle / ...), flags and pie; the
        segments (name, vmaddr, sizes, prot like r-x, section count); the
        linked dylibs, install name (id_dylib) and rpaths; the uuid, the
        entry_offset (LC_MAIN), the target platform with min_os/sdk versions;
        symbol_count and stripped; signed (LC_CODE_SIGNATURE present) and
        encrypted (LC_ENCRYPTION_INFO cryptid, the iOS store-encryption flag).
        A universal (fat) binary answers with fat=true and one such summary per
        architecture slice. Bad load commands become warnings, never faults. A
        file that is not a Mach-O is invalid_params (a Java class file sharing
        the 0xcafebabe magic is called out), one over 128 MiB too_large.
        """
        return _dump(analysis.macho_summary(path))

    return tools.bindings
