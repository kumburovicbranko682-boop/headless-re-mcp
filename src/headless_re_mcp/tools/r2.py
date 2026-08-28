from __future__ import annotations

from typing import Annotated, Any, Literal

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

    @tools.tool(name="r2.strings_all")
    def r2_strings_all(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Strings anywhere in the image, not only the ones r2 classified as data.

        r2.strings runs ``izj``, which lists strings only in the sections radare2
        flags as data -- so a URL baked into a code section, a marker in an
        appended overlay, a key in a packer stub, or a literal in a section r2 did
        not map as data is simply absent. This runs ``izzj``, r2's whole-binary
        scan, and is the native/cross-format twin of wasm.strings and js.strings:
        the broad "find every printable run in the file" pass you reach for when
        r2.strings comes back suspiciously thin or a string you can see in a hex
        view is missing. The trade is noise -- code decoded as text, padding runs
        -- so triage with r2.strings first and fall back here. Same row shape:
        items, each carrying string, section (often empty for a hit outside a
        named section), type, vaddr and address (va/rva/module), plus count. There
        is no integer address field. Read items_truncated, items_total and
        items_limit when the list filled the cap (4096); a whole-image scan hits
        that ceiling far sooner than r2.strings, so check it before reading the
        list as complete. There is no strings, truncated or has_more field.
        """
        return _dump(analysis.r2_strings_all(session_id, timeout=timeout))

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
        """Sections radare2 mapped, with their permissions.

        Runs ``iSj``. Answers with items, each carrying name, vaddr, paddr, size,
        vsize, perm and address (va/rva/module), plus count. perm is radare2's
        permission string (for example ``-r-x`` for executable code, ``-rw-``
        for writable data); a writable-and-executable section is the packing or
        injection tell an agent scans for. Read items_truncated, items_total and
        items_limit when the list filled the cap (4096). There is no sections,
        truncated or has_more field.
        """
        return _dump(analysis.r2_sections(session_id, timeout=timeout))

    @tools.tool(name="r2.symbols")
    def r2_symbols(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """The whole symbol table radare2 read, not just the exported names.

        Runs ``isj``. Answers with items, each carrying name, type (FUNC, OBJ,
        SECTION, ...), bind (LOCAL, GLOBAL, WEAK), size, vaddr, is_imported and
        address (va/rva/module), plus count. Unlike r2.exports, this includes
        LOCAL symbols an unstripped binary keeps (static helpers, compiler-
        emitted stubs) that are never exported, so a named function absent from
        the export table can still be found here. Imported entries are flagged
        is_imported and may carry radare2's placeholder address. Read
        items_truncated, items_total and items_limit when the list filled the
        cap (4096). There is no symbols, truncated or has_more field.
        """
        return _dump(analysis.r2_symbols(session_id, timeout=timeout))

    @tools.tool(name="r2.entrypoints")
    def r2_entrypoints(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Where execution can begin, as radare2 resolved it.

        Runs ``iej``. Answers with items, each carrying vaddr, paddr, baddr (the
        image base), type (``program`` for the real entry, plus ``init``/``fini``
        constructors where the format has them) and address (va/rva/module),
        plus count. The ``program`` entry is the first instruction that runs and
        the natural seed for r2.disasm on a stripped target with no named
        functions. Read items_truncated, items_total and items_limit when the
        list filled the cap (4096). There is no entrypoints, truncated or
        has_more field.
        """
        return _dump(analysis.r2_entrypoints(session_id, timeout=timeout))

    @tools.tool(name="r2.relocations")
    def r2_relocations(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Relocations: the addresses patched at load time, and by what.

        Runs ``irj``. A relocation is where the loader writes an address the
        linker could not fix statically -- a GOT/PLT slot bound to an imported
        function, an absolute pointer rebased for ASLR, an ifunc resolved at
        startup. This is what turns a bare ``call [rip+off]`` into ``call
        printf``, so it is the map an agent needs to read indirect calls, find
        the patch/hook points, and see which import lands at which slot. Answers
        with items, each carrying type (r2's reloc kind, e.g. SET_64 for a
        pointer set, ADD_64 for a relative rebase), vaddr, paddr, is_ifunc,
        address (va/rva/module), and name when the relocation resolves a named
        symbol (an import such as ``printf`` or a runtime helper) -- a relative
        rebase carries no name. There is no integer address field. Read
        items_truncated, items_total and items_limit when the list filled the
        cap (4096). There is no relocations, truncated or has_more field.
        """
        return _dump(analysis.r2_relocations(session_id, timeout=timeout))

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
        There is no integer address field. invalid_count says how many of those
        items were undecodable bytes (radare2 type "invalid" on 5.x, "ill" on
        6.x, no opcode): point this at data, padding or unmapped memory and every
        byte comes back as its own invalid item, so invalid_count == count means
        the address is not code.
        """
        return _dump(analysis.r2_disasm(session_id, address, count=count, timeout=timeout))

    @tools.tool(name="r2.xrefs")
    def r2_xrefs(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """References to and from address, as radare2 resolved them.

        Answers with items, each carrying from, to, type, direction ("to" when
        the row references address, "from" when address references it),
        from_address and to_address, plus address (va/rva/module) and address_va
        (the integer that was asked). Read items_truncated, items_total and
        items_limit when the list filled the cap (4096). There is no integer
        address, xrefs, truncated or has_more field.
        """
        return _dump(analysis.r2_xrefs(session_id, address, timeout=timeout))

    @tools.tool(name="r2.read")
    def r2_read(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        size: Annotated[int, Field(ge=1, le=65536)] = 64,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read size raw bytes at a virtual address, as radare2 maps them.

        Where r2.disasm decodes an address as code, this reads it as data: the
        global, jump table, or embedded key/blob a data xref points at has no
        opcodes, so r2.disasm returns a run of invalid rows there and only the
        raw bytes carry the content -- this is the r2 line's read-memory
        primitive, the static twin of frida.memory.read. Runs ``pxj``. Answers
        with data (lowercase hex, no separators), encoding ("hex"), count (bytes
        actually returned), size (bytes asked), address (va/rva/module) and
        address_va (the integer asked). count < size and short_read is set when
        the window ran off the end of the mapped region. There is no integer
        address field and no inline byte array; decode data from hex.
        """
        return _dump(analysis.r2_read(session_id, address, size=size, timeout=timeout))

    @tools.tool(name="r2.search")
    def r2_search(
        session_id: str,
        query: str,
        kind: Literal["text", "hex"] = "text",
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Find every occurrence of an exact byte pattern (or text) in the image.

        r2.strings only lists strings r2 auto-detected; this finds anything you
        name that it did not -- a file magic, a crypto constant, a marker split
        across the binary, a non-printable pattern -- the r2 twin of
        static.search.bytes/text. kind "text" UTF-8-encodes the query to a byte
        pattern; kind "hex" takes raw hex pairs (spaces and a 0x prefix are
        tolerated). Runs ``/xj``. Answers with items, each carrying addr, type,
        data (the matched bytes as hex) and address (va/rva/module), plus count
        and the echoed query, kind, pattern_hex and pattern_len. An absent
        pattern is a clean empty items list, not an error. Read items_truncated,
        items_total and items_limit when the hit list filled the cap (4096);
        r2's own hit count is capped there too so a short pattern cannot flood.
        Pivot from a hit with r2.read (bytes) or r2.disasm (code) at its addr.
        """
        return _dump(analysis.r2_search(session_id, query, kind=kind, timeout=timeout))

    @tools.tool(name="r2.disasm_function")
    def r2_disasm_function(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble the whole function at an address, as radare2 bounds it.

        Where r2.disasm reads a fixed count of instructions linearly, this reads
        a function: r2's analysis decides where it ends, and each op's disasm
        names its call targets and referenced data (``call sym.foo``, ``lea ...
        str.bar``) instead of raw operands -- the r2 line's function view, the
        seam from r2.functions (pick a function by its offset) to reading what it
        does. Runs ``pdfj``. Answers with name, size, address (va/rva/module),
        address_va, ops and count. Each op carries addr, opcode, disasm, bytes,
        type, size and address (va/rva/module). invalid_count is how many ops r2
        could not decode. An address not inside a known function comes back as a
        clean empty ops list (count 0), not an error. Read ops_truncated,
        ops_total and ops_limit when the function was longer than the cap (4096).
        """
        return _dump(analysis.r2_disasm_function(session_id, address, timeout=timeout))

    @tools.tool(name="r2.resolve")
    def r2_resolve(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Map a raw address back to its function and nearest symbol.

        The reverse of every other r2 reader: r2.xrefs, r2.relocations,
        r2.search, r2.read and the disassemblers all emit addresses; this turns
        one back into "what lives here". Give it an address (a search hit, an
        xref target, a relocation slot, a pointer read out of the data) and it
        answers with the function it falls inside and the nearest named flag at
        or before it -- the equivalent of reading ``main + 16`` or ``str.foo``
        off a listing, even when r2 never turned that spot into a function.

        Runs ``afij`` and ``fdj``. Answers with address (va/rva/module),
        address_va, function and flag. ``function`` is {name, addr (the function
        start), size, delta (address - addr, i.e. bytes into the function),
        signature and type when r2 has them, address (va/rva/module of the
        start)}, or null when the address is not inside any analysed function.
        ``flag`` is {name, realname when it differs, addr (the flag's own
        address) and address when known, delta (address - the flag's addr)}, or
        null when the image has no flags to resolve against. delta 0 means the
        address sits exactly on that function/flag.
        """
        return _dump(analysis.r2_resolve(session_id, address, timeout=timeout))

    @tools.tool(name="r2.callgraph")
    def r2_callgraph(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        direction: Literal["callees", "callers", "both"] = "both",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Direct callees and callers of the function at an address.

        Where r2.xrefs answers one address and r2.disasm_function reads a whole
        body, this collapses a function to its call-graph neighbours: the
        functions it calls (callees) and the functions that call it (callers),
        each resolved to a name and a call-site address instead of a raw pointer.
        It is the native twin of apk.method_xrefs -- the seam from r2.functions
        (pick a function) or r2.resolve (map a hit to its function) to "what does
        this reach, and who reaches it". address may sit anywhere inside a
        function, not only on its entry. direction "callees", "callers" or "both"
        (default) chooses which edges to return.

        Runs ``aa`` then ``aflj`` once and builds the graph from r2's own
        per-function callrefs (outbound) and codexrefs (inbound). Answers with
        function ({name, addr, size, address} of the resolved node, or null when
        address is not inside any analysed function), direction, and edges. Each
        edge carries direction ("callee"/"caller"), name (the function at the
        other end), addr (its start, or the raw endpoint when it resolved to no
        function), address (va/rva/module), call_site_va and call_site (the call
        instruction), type (CALL/CODE as r2 tags it) and resolved (false when the
        endpoint fell outside every analysed function). edges are deduplicated by
        endpoint and call site and sorted; count, total, offset and has_more page
        them, callees_total and callers_total count each direction across the
        whole graph, and scan_capped is set once the 20000-edge ceiling was hit.
        A leaf that nothing calls (or that calls nothing) is a clean empty edges
        list, not an error.
        """
        return _dump(
            analysis.r2_callgraph(
                session_id,
                address,
                direction=direction,
                offset=offset,
                limit=limit,
                timeout=timeout,
            )
        )

    @tools.tool(name="r2.libs")
    def r2_libs(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Shared libraries the binary links against.

        Where r2.imports names the individual symbols pulled from other
        libraries, this answers the coarser dependency question -- which shared
        objects the loader must resolve at all: the DT_NEEDED entries of an ELF,
        the linked dylibs of a Mach-O, the imported DLLs of a PE. It is the
        native/cross-format twin of a PE's imported-module list and a fast triage
        read (a musl-only binary, an unexpected OpenSSL/curl dependency, a stray
        extra .so) before walking per-symbol imports. Runs ``ilj``. Answers with
        items, each carrying name, plus count. There is no address field -- a
        DT_NEEDED name has no load address until the loader resolves it. A fully
        static binary that links nothing is a clean empty list, not an error.
        Read items_truncated, items_total and items_limit when the list filled
        the cap (4096).
        """
        return _dump(analysis.r2_libs(session_id, timeout=timeout))
    return tools.bindings
