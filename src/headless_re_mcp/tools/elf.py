"""Protocol-independent elf.* tool definitions (native ELF binary triage)."""

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

    @tools.tool(name="elf.symbols")
    def elf_symbols(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        """List an ELF's dynamic symbols (imports/exports) with the stdlib.

        The dynamic symbol table (.dynsym) is the binary's link surface: the
        functions it imports from shared libraries and the ones it exports for
        others to call -- and unlike .symtab it survives stripping. This reads
        it by path with no external tool: the offline nm -D triage.

        Answers with one page of symbols (name, bind GLOBAL/WEAK/LOCAL, type
        FUNC/OBJECT/..., value, size, shndx) plus imported/exported booleans
        per symbol, and imported_listed / exported_listed / symbols_total /
        has_more so pages can be walked with offset/limit. A binary with no
        .dynsym (statically linked) is an empty listing with a warning. A file
        that is not an ELF is invalid_params, one over 128 MiB too_large.
        """
        return _dump(analysis.elf_symbols(path, offset=offset, limit=limit))

    @tools.tool(name="elf.segments")
    def elf_segments(path: str) -> dict[str, Any]:
        """List an ELF's program headers (loadable segments) with the stdlib.

        Where elf.summary reads the section table (the linker's view), this
        reads the program header table -- the segments the kernel actually maps
        -- with no external tool: the offline readelf -l triage.

        Answers with one entry per segment (type LOAD/DYNAMIC/INTERP/GNU_STACK/
        GNU_RELRO/..., rwx flags, file offset, vaddr/paddr, filesz/memsz, align)
        and the security posture an analyst reads first: interp (the dynamic
        linker path from PT_INTERP), nx (non-executable stack, from
        PT_GNU_STACK; null when the binary has no GNU_STACK), relro (PT_GNU_RELRO
        present) and writable_executable (a loadable segment that is both W and
        X -- a W^X violation). A program header past end of file is a warning. A
        file that is not an ELF is invalid_params, one over 128 MiB too_large.
        """
        return _dump(analysis.elf_segments(path))

    return tools.bindings
