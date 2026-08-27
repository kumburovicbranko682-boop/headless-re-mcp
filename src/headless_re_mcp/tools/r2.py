from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder

# The analysis passes the r2 command allowlist permits. "aa" is shallow and
# fast; it misses functions only reachable through a call (stripped binaries)
# and data refs built by multi-instruction address materialisation (ARM
# adrp/add). "aac" follows calls, "aar" recovers data refs, "aaa" runs the
# full umbrella -- slower, but what stripped/ARM targets need.
AnalysisPass = Literal["aa", "aac", "aar", "aaa"]


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
        (va/rva/module), plus count. The payload also names module, image_base
        and architecture once at the top level -- the same coordinate frame the
        ghidra tools report, so the two engines line up on rva/module. There is
        no functions field. Read items_truncated when the list filled the cap.
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

    @tools.tool(name="r2.disasm")
    def r2_disasm(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        count: Annotated[int, Field(ge=1, le=512)] = 32,
        analysis_pass: AnalysisPass = "aa",
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble count instructions at address, as radare2 decodes them.

        Answers with items holding those instructions, plus address
        (va/rva/module), address_va (the integer that was asked) and count.
        There is no integer address field. analysis_pass picks the analysis
        run first: the default aa decodes fine but leaves call targets in
        stripped binaries unnamed; aaa recovers fcn.<addr>/str.<text> names.
        """
        return _dump(
            analysis.r2_disasm(
                session_id, address, count=count, analysis=analysis_pass, timeout=timeout
            )
        )

    @tools.tool(name="r2.xrefs")
    def r2_xrefs(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        analysis_pass: AnalysisPass = "aa",
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """References to and from address, as radare2 resolved them.

        Answers with items, each carrying from, to, type, from_address and
        to_address, plus address (va/rva/module) and address_va (the integer
        that was asked). Read items_truncated, items_total and items_limit
        when the list filled the cap (4096). There is no integer address,
        xrefs, truncated or has_more field. analysis_pass picks the analysis
        run first; the default aa graph omits edges only a deeper pass (aaa)
        finds, e.g. in stripped binaries or ARM literal-pool loads.
        """
        return _dump(
            analysis.r2_xrefs(session_id, address, analysis=analysis_pass, timeout=timeout)
        )

    @tools.tool(name="r2.xrefs_to")
    def r2_xrefs_to(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        analysis_pass: AnalysisPass = "aa",
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """References that target address (radare2 axtj), inbound only.

        Unlike r2.xrefs, whose axj list is the whole binary's graph and ignores
        the address for filtering, this answers "who references this address":
        items carry from, type, from_address, and the enclosing function in
        fcn_addr and fcn_name, plus address (va/rva/module) and address_va (the
        integer that was asked). Read items_truncated, items_total and
        items_limit when the list filled the cap (4096). There is no integer
        address, xrefs, truncated or has_more field. analysis_pass picks the
        analysis run first: with the default aa, references from code that only
        a deeper pass discovers (stripped binaries, ARM adrp/add string loads)
        are missing; aaa recovers them at the cost of a slower run.
        """
        return _dump(
            analysis.r2_xrefs_to(session_id, address, analysis=analysis_pass, timeout=timeout)
        )

    @tools.tool(name="r2.xrefs_from")
    def r2_xrefs_from(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        analysis_pass: AnalysisPass = "aa",
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """References made from the function at address (radare2 axffj), outbound.

        The complement of r2.xrefs_to: it answers "what does this function call
        and touch", walking the whole function body (not the single instruction
        axfj reads). Items name the target in name and type and carry the
        referencing site at (mapped to at_address) and the target ref (mapped to
        ref_address, and to the item's address), plus address (va/rva/module)
        and address_va (the integer that was asked). Read items_truncated,
        items_total and items_limit when the list filled the cap (4096). There
        is no integer address, xrefs, truncated or has_more field. analysis_pass
        picks the analysis run first: the default aa never analyzes a function
        reachable only through a call, so on stripped binaries the walk finds no
        function and returns nothing; aaa recovers the body and its edges.
        """
        return _dump(
            analysis.r2_xrefs_from(session_id, address, analysis=analysis_pass, timeout=timeout)
        )
    return tools.bindings
