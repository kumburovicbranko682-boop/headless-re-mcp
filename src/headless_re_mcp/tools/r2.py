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


def build_r2_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="r2.info")
    def r2_info(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Binary identity as radare2 prints it.

        Runs ``i`` (not JSON). Answers with raw holding that text, plus
        truncated, output_bytes and returned_bytes when the text was cut at
        the 1_000_000-byte buffer. There are no format, arch, bits,
        endianness or entry fields; architecture and image_base come from
        the PE header, not from this listing.
        """
        return _dump(analysis.r2_info(session_id, timeout=timeout))

    @tools.tool(name="r2.open")
    def r2_open(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """One-shot check that radare2 can open the session binary.

        Runs identity only (``i``) and exits. Answers with opened, binary,
        info (the ``i`` text, not a raw field), and note. Subsequent r2
        tools reopen the file in a new process; r2.functions is what runs
        the analysis pass. A longer timeout here does not buy analysis for
        anyone else. Requires radare2 on PATH or HEADLESS_RE_R2.
        """
        return _dump(analysis.r2_open(session_id, timeout=timeout))

    @tools.tool(name="r2.functions")
    def r2_functions(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Functions radare2 found.

        Answers with items, each carrying name, offset, size and address
        (va/rva/module), plus count. There is no functions field. Read
        items_truncated when the list filled the cap.
        """
        return _dump(analysis.r2_functions(session_id, timeout=timeout))

    @tools.tool(name="r2.strings")
    def r2_strings(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Strings radare2 recovered.

        Answers with items, each carrying string, section, type, vaddr and
        address (va/rva/module), plus count. There is no integer address
        field. Read items_truncated, items_total and items_limit when the
        list filled the cap (4096). There is no strings, truncated or
        has_more field.
        """
        return _dump(analysis.r2_strings(session_id, timeout=timeout))

    @tools.tool(name="r2.imports")
    def r2_imports(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Imported symbols with the library each resolves to.

        Answers with items, each carrying name, lib, plt and address
        (va/rva/module), plus count. There is no integer address field.
        Read items_truncated, items_total and items_limit when the
        list filled the cap (4096). There is no imports, truncated or
        has_more field.
        """
        return _dump(analysis.r2_imports(session_id, timeout=timeout))

    @tools.tool(name="r2.exports")
    def r2_exports(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Exported symbols with their addresses.

        Answers with items, each carrying name, vaddr and address
        (va/rva/module), plus count. There is no integer address field.
        Read items_truncated, items_total and items_limit when the
        list filled the cap (4096). There is no exports, truncated or
        has_more field.
        """
        return _dump(analysis.r2_exports(session_id, timeout=timeout))

    @tools.tool(name="r2.sections")
    def r2_sections(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Section layout radare2 reads from the binary.

        Runs ``iSj``. Answers with items, each carrying name, size (the bytes
        on disk), vsize (the bytes once mapped), paddr (file offset), vaddr and
        perm (the rwx string, e.g. ``-r-x``), plus address (va/rva/module)
        built from vaddr, and count. This is where .text/.data/.rodata live and
        how big and how permissioned each is -- the map you read before picking
        an address for r2.disasm or r2.strings. There is no integer address
        field. Read items_truncated, items_total and items_limit when the list
        filled the cap (4096). There is no sections, truncated or has_more
        field.
        """
        return _dump(analysis.r2_sections(session_id, timeout=timeout))

    @tools.tool(name="r2.symbols")
    def r2_symbols(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Full symbol table radare2 reads from the binary.

        Runs ``isj``. Answers with items, each carrying name, realname, type
        (FUNC/OBJ/SECTION/FILE...), bind (GLOBAL/LOCAL/WEAK), size, vaddr,
        paddr and is_imported, plus address (va/rva/module) built from vaddr,
        and count. This is the superset r2.imports and r2.exports each slice:
        it lists local and static symbols too, so it is where a stripped-vs-not
        judgement and the FUNC entries that never made the export table live.
        There is no integer address field. Read items_truncated, items_total
        and items_limit when the list filled the cap (4096). There is no
        symbols, truncated or has_more field.
        """
        return _dump(analysis.r2_symbols(session_id, timeout=timeout))

    @tools.tool(name="r2.disasm")
    def r2_disasm(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        count: Annotated[int, Field(ge=1, le=512)] = 32,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble count instructions at address, as radare2 decodes them.

        Answers with items holding those instructions, plus address
        (va/rva/module), address_va (the integer that was asked) and count.
        There is no integer address field.
        """
        return _dump(analysis.r2_disasm(session_id, address, count=count, timeout=timeout))

    @tools.tool(name="r2.xrefs")
    def r2_xrefs(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """References to address (who calls or reads it), as radare2 resolved them.

        Answers with items, each carrying from (the referencing site), type
        and from_address, plus address (va/rva/module) and address_va (the
        integer that was asked). This is refs-to: radare2's axtj honors the
        seek, so the list is the callers of that address, not a program-wide
        dump; outgoing refs (what this address itself references) are not
        listed -- read them off r2.disasm instead. Read items_truncated,
        items_total and items_limit when the list filled the cap (4096). There
        is no integer address, xrefs, truncated or has_more field.
        """
        return _dump(analysis.r2_xrefs(session_id, address, timeout=timeout))
    return tools.bindings
