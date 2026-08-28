"""Protocol-independent elf.* tool definitions (native ELF binary triage)."""

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


def build_elf_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="elf.summary")
    def elf_summary(path: str) -> dict[str, Any]:
        """Summarise an ELF binary (Linux executable or .so) with the stdlib.

        Native code is a real reverse-engineering target -- an Android app's
        lib/**/*.so, a Linux executable, an ELF malware sample -- but opening one
        needed r2 or Ghidra. This reads a standalone ELF by path with no external
        tool: the offline readelf -h -S -d triage.

        Answers with class (ELF32/ELF64), bitness, endianness, os_abi, type
        (executable / shared object / ...), machine (x86-64, AArch64, ARM, ...),
        entry, flags, section_count and program_header_count; a bounded sections
        list (name, type, flags like AX/WA, addr, offset, size); the shared
        library dependencies (needed), the soname and the run-time search path
        (runpath/rpath) read from .dynamic; and stripped (no .symtab). warnings
        carries any table offset that left the file. A file that is not an ELF is
        invalid_params, one over 128 MiB too_large.
        """
        return _dump(analysis.elf_summary(path))

    return tools.bindings
