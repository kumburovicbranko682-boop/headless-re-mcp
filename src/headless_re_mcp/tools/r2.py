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
        """The binary's sections/segments: its memory layout, as radare2 reads them.

        The static counterpart to frida.memory.ranges (which maps a live
        process) and the ELF/Mach-O/PE equivalent of a PE section table: the
        regions the loader lays down, so a caller knows which span an address
        falls in, where code (r-x) ends and data begins, and which section a
        string or symbol lives in. Answers with items -- each carrying name,
        size (virtual size), vsize, paddr (file offset), vaddr, perm (the
        rwx permission string) and address (va/rva/module) -- plus count. There
        is no integer address field. Read items_truncated, items_total and
        items_limit when the list filled the cap (4096). There is no sections,
        truncated or has_more field. Read-only; reopens the binary one-shot like
        the other r2 tools.
        """
        return _dump(analysis.r2_sections(session_id, timeout=timeout))

    @tools.tool(name="r2.symbols")
    def r2_symbols(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """The binary's full symbol table, the superset r2.imports/exports sample.

        r2.imports lists only the relocations pulled from other libraries and
        r2.exports only the dynamic export table; this is the whole symbol table
        (is), so on a non-stripped ELF/Mach-O it also surfaces the local and
        internal symbols neither of those shows -- named local functions, data
        objects, debug symbols -- which is the function/name inventory to reach
        for when analysis-derived r2.functions (aflj) leaves you with unnamed
        blobs. Answers with items, each carrying name (and realname when r2
        demangled it), type (FUNC/OBJ/SECTION/...), bind (GLOBAL/LOCAL/WEAK),
        size, is_imported, vaddr and address (va/rva/module), plus count. There
        is no integer address field. Read items_truncated, items_total and
        items_limit when the list filled the cap (4096). There is no symbols,
        truncated or has_more field. Read-only; reopens the binary one-shot like
        the other r2 tools.
        """
        return _dump(analysis.r2_symbols(session_id, timeout=timeout))

    @tools.tool(name="r2.endpoints")
    def r2_endpoints(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_paths: bool = True,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Extract network endpoints (URLs, hosts, paths) from the strings r2 recovered.

        The native-binary counterpart to apk.endpoints / js.endpoints /
        dotnet.endpoints: the shared URL/path recogniser run over the same strings
        r2.strings lists (radare2 izj), answering "what backends does this
        ELF/Mach-O/PE talk to" without an analyst grepping the raw dump.
        Deduplicated and aggregated by occurrence. Answers with endpoints (each
        {value, kind (url|path), scheme, host, source (the containing string,
        truncated with source_truncated when cut), count, and -- when r2 gave
        them -- vaddr and address (va/rva/module) of that string, so r2.xrefs /
        r2.disasm can pivot to the code that loads it}), plus count, total,
        offset, has_more, hosts (the distinct URL host set, hosts_truncated when
        over the cap), and scan_capped (r2 returned more than 4096 strings so the
        underlying list was itself cut). include_paths (default true) also
        surfaces whole-string request paths (/api/..., /v1/users); set false for
        URLs only. name_filter keeps only endpoints whose value or host contains
        that substring (case-insensitive), applied before paging so total is the
        match count. The list field is endpoints. Reopens the binary one-shot like
        the other r2 tools; requires radare2 on PATH or HEADLESS_RE_R2. Read-only.
        """
        return _dump(
            analysis.r2_endpoints(
                session_id,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_paths=include_paths,
                timeout=timeout,
            )
        )

    @tools.tool(name="r2.secrets")
    def r2_secrets(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_generic: bool = False,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Detect embedded credentials in the strings r2 recovered.

        The native-binary counterpart to apk.secrets / js.secrets /
        dotnet.secrets: the same shared high-precision detector table (AWS/Google/
        GitHub/Slack/Stripe/JWT/private-key/basic-auth-URL, plus an opt-in
        high-entropy catch-all) run over the strings r2.strings lists (radare2
        izj). Returns only the credential hits, deduplicated by (detector, value).
        Answers with secrets (each {detector, value (truncated with
        value_truncated when cut), source (the containing string, source_truncated
        when cut), count, and -- when r2 gave them -- vaddr and address
        (va/rva/module), so r2.xrefs can pivot to the code that uses the key}),
        plus count, total, offset, has_more, detectors (the distinct detector
        names present), and scan_capped (r2 returned more than 4096 strings so the
        underlying list was itself cut). include_generic adds a single
        generic_high_entropy match for a whole-string base64/hex token above the
        entropy floor when no specific detector claimed it (off by default to keep
        precision high). name_filter keeps only findings whose detector or value
        contains that substring (case-insensitive), before paging so total is the
        match count. The list field is secrets. Reopens the binary one-shot like
        the other r2 tools; requires radare2 on PATH or HEADLESS_RE_R2. Read-only.
        """
        return _dump(
            analysis.r2_secrets(
                session_id,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_generic=include_generic,
                timeout=timeout,
            )
        )

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
        """References to and from address, as radare2 resolved them.

        Answers with items, each carrying from, to, type, from_address and
        to_address, plus address (va/rva/module) and address_va (the integer
        that was asked). Read items_truncated, items_total and items_limit
        when the list filled the cap (4096). There is no integer address,
        xrefs, truncated or has_more field.
        """
        return _dump(analysis.r2_xrefs(session_id, address, timeout=timeout))
    return tools.bindings
