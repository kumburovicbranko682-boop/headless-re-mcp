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


def build_ghidra_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="ghidra.analyze")
    def ghidra_analyze(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Run Ghidra headless import and analysis, then delete the project.

        Answers with project_dir, stdout_excerpt and note.
        There is no functions field and no analysis field. The other ghidra tools
        do not read what this produced. Each of ghidra.functions, ghidra.symbols,
        ghidra.xrefs and ghidra.decompile imports the binary again under
        -deleteProject, so calling this first does not save them any work. Minutes
        on a large binary. Requires HEADLESS_RE_GHIDRA_HOME.
        """
        return _dump(analysis.ghidra_analyze(session_id, timeout=timeout))

    @tools.tool(name="ghidra.functions")
    def ghidra_functions(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Functions Ghidra found.

        Answers with items, each carrying name, entry and body_size, plus count
        and has_more so a page that filled the limit is not read as the whole list.
        """
        return _dump(analysis.ghidra_functions(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.symbols")
    def ghidra_symbols(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Symbols Ghidra recovered.

        Answers with items, each carrying name, address and type, plus count
        and has_more. The listing does not include a containing scope.
        """
        return _dump(analysis.ghidra_symbols(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.strings")
    def ghidra_strings(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Defined strings Ghidra recovered, in Ghidra's own address space.

        The r2.strings counterpart on the Ghidra line, and what closes the loop
        with the other ghidra tools: it lists the program's defined string data
        (those Ghidra's analysis marked as strings), so a caller can take a
        string's address straight to ghidra.xrefs to find who references it, then
        ghidra.decompile the referencing function -- a chain that was impossible
        before because string addresses could not be discovered inside Ghidra.
        Answers with items, each carrying address (Ghidra's address string, the
        form ghidra.xrefs expects), value (the string, cut at 2048 chars), type
        (the Ghidra data type, e.g. string/unicode) and length (the datum's byte
        length), plus count and has_more so a page that filled the limit is not
        read as the whole list. Only strings Ghidra defined are listed; undefined
        bytes that happen to be printable are not (use r2.strings for a raw scan).
        Imports the binary again under -deleteProject like the other ghidra tools;
        minutes on a large binary. Requires HEADLESS_RE_GHIDRA_HOME. Read-only.
        """
        return _dump(analysis.ghidra_strings(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.xrefs")
    def ghidra_xrefs(
        session_id: str,
        address: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """References to address, as Ghidra resolved them.

        Only incoming refs (getReferencesTo). Answers with items carrying from,
        to and type, plus count and has_more. Outgoing refs are not listed.
        """
        return _dump(analysis.ghidra_xrefs(session_id, address, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.decompile")
    def ghidra_decompile(
        session_id: str,
        address: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Ghidra's decompilation of the function at address.

        Answers with decompiled, and truncated when the C was cut at the
        buffer. A second reading of code IDA decompiled differently, or of
        code it could not.
        """
        return _dump(analysis.ghidra_decompile(session_id, address, timeout=timeout))

    @tools.tool(name="ghidra.endpoints")
    def ghidra_endpoints(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_paths: bool = True,
        scan_limit: Annotated[int, Field(ge=1, le=1024)] = 1024,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """URLs and API paths in the strings Ghidra defined.

        The ghidra.strings counterpart to r2.endpoints / dotnet.endpoints: the
        same URL/path recogniser the other lines use, run over the program's
        defined string data instead of a raw scan, so what it finds is anchored
        to a real datum. Each endpoint carries the Ghidra address of the string
        it came from -- the form ghidra.xrefs expects -- so a hit goes straight
        to who references it and then ghidra.decompile of that function.

        Answers with endpoints, each having value, kind (url or path), scheme,
        host, source (the containing string), address and count (how many defined
        strings held it); plus hosts (the distinct URL hosts), total, offset,
        has_more for paging, and scan_capped when more defined strings existed
        than scan_limit read. include_paths=false keeps only absolute URLs;
        name_filter keeps endpoints whose value or host contains it. scan_limit
        bounds how many defined strings are scanned (Ghidra's own cap is 1024).
        Imports the binary again under -deleteProject like the other ghidra
        tools; minutes on a large binary. Requires HEADLESS_RE_GHIDRA_HOME.
        Read-only.
        """
        return _dump(
            analysis.ghidra_endpoints(
                session_id,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_paths=include_paths,
                scan_limit=scan_limit,
                timeout=timeout,
            )
        )

    @tools.tool(name="ghidra.secrets")
    def ghidra_secrets(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_generic: bool = False,
        scan_limit: Annotated[int, Field(ge=1, le=1024)] = 1024,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Embedded credentials in the strings Ghidra defined.

        The ghidra.strings counterpart to r2.secrets / dotnet.secrets: the same
        high-precision detector table (AWS keys, GitHub/Slack/Stripe tokens,
        private-key headers, JWTs, ...) the other lines use, run over the
        program's defined string data. Each finding carries the Ghidra address of
        the string it sits in -- the form ghidra.xrefs expects -- so a leaked key
        leads straight to the code that loads it.

        Answers with secrets, each having detector, value (the matched
        credential), source (the containing string), address and count; plus
        detectors (the kinds that fired), total, offset, has_more for paging, and
        scan_capped when more defined strings existed than scan_limit read.
        include_generic=true adds the noisier entropy/assignment heuristics that
        are off by default; name_filter keeps findings whose detector or value
        contains it. scan_limit bounds how many defined strings are scanned
        (Ghidra's own cap is 1024). Imports the binary again under -deleteProject
        like the other ghidra tools; minutes on a large binary. Requires
        HEADLESS_RE_GHIDRA_HOME. Read-only.
        """
        return _dump(
            analysis.ghidra_secrets(
                session_id,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_generic=include_generic,
                scan_limit=scan_limit,
                timeout=timeout,
            )
        )
    return tools.bindings
