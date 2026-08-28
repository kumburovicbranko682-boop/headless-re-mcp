"""Protocol-independent macho.* tool definitions (macOS/iOS binary triage)."""

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

    @tools.tool(name="macho.symbols")
    def macho_symbols(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        """List a Mach-O's symbols (imports/exports) with the stdlib.

        The LC_SYMTAB nlist table is the binary's link surface: the functions
        and objects it imports from other dylibs (undefined external entries)
        and the ones it exports for others to link (defined external entries).
        This reads it by path with no external tool: the offline nm -m triage.

        Answers with one page of symbols (name, type undefined/section/absolute/
        indirect or debug, external, value) plus imported/exported booleans per
        symbol; an imported symbol also carries library_ordinal and the resolved
        library it comes from (a dylib path, or self/executable/dynamic_lookup).
        imported_listed / exported_listed / symbols_total / has_more let pages be
        walked with offset/limit. A fat binary is read on its first architecture
        slice (arch and available_arches are reported); an image with no
        LC_SYMTAB is an empty listing with a warning. A file that is not a
        Mach-O is invalid_params, one over 128 MiB too_large.
        """
        return _dump(analysis.macho_symbols(path, offset=offset, limit=limit))

    @tools.tool(name="macho.signature")
    def macho_signature(path: str) -> dict[str, Any]:
        """Decode a Mach-O's embedded code signature with the stdlib.

        macho.summary only says whether LC_CODE_SIGNATURE is present; this
        opens the SuperBlob it points at and reads what an analyst asks first
        about a macOS/iOS sample -- who signed it and under what rules -- with
        no external tool: the offline codesign -dvv --entitlements view.

        Answers with the CodeDirectory identity: identifier (the signing
        identifier), team_id (the Apple Developer team -- the practical "who"),
        cdhash (the truncated digest of the CodeDirectory, what notarization
        and threat-intel lookups key on), hash_type/hash_size, code_limit,
        page_size and the decoded flags (ADHOC, HARD, KILL, RESTRICT,
        ENFORCEMENT, LIBRARY_VALIDATION, RUNTIME, LINKER_SIGNED). The verdicts
        are stated directly: adhoc, hardened_runtime, linker_signed, plus
        cms_signature_size (0 means no certificate chain -- ad-hoc; nonzero
        means a real CMS signature is attached) and has_requirements /
        has_der_entitlements. The entitlements XML plist is parsed into a
        bounded dict -- get-task-allow, sandbox and keychain exceptions live
        here. An unsigned image is signed=false with a warning; a fat binary
        is read on its first architecture slice (arch and available_arches
        reported). A file that is not a Mach-O is invalid_params, one over
        128 MiB too_large.
        """
        return _dump(analysis.macho_signature(path))

    @tools.tool(name="macho.strings")
    def macho_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=256)] = 4,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        section: str | None = None,
    ) -> dict[str, Any]:
        """Extract a Mach-O's printable strings, labelled by section, stdlib-only.

        A bare ``strings`` flattens the file into one anonymous list; this
        keeps the two-level provenance an analyst reasons with, reading the
        binary by path with no external tool.

        Each run of printable bytes at least min_length long is reported with
        the segment and section it came from -- __TEXT,__cstring for C string
        constants, __TEXT,__objc_methname for Objective-C selectors,
        __TEXT,__objc_classname for class names, __TEXT,__const for other
        literals -- plus its file offset and virtual address (vaddr). Pass
        section to scan just one section, by full "__TEXT,__cstring" label or
        bare "__cstring" name. Zerofill/bss sections have no file content and
        are skipped; a fat binary is read on its first architecture slice (arch
        and available_arches reported). sections_scanned lists what was read;
        strings_total is capped (truncated flags the cap) and paged with
        offset/limit (has_more). A file that is not a Mach-O is invalid_params,
        one over 128 MiB too_large.
        """
        return _dump(
            analysis.macho_strings(
                path, min_length=min_length, offset=offset, limit=limit, section=section
            )
        )

    return tools.bindings
