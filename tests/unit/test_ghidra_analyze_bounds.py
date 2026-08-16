"""ghidra.analyze used to cut the headless log without saying so."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ghidra.client import GhidraClient


class TestGhidraAnalyzeSaysWhenItStopped:
    """An analysis log that hit 8000 chars used to look complete.

    Measured: 20000-char stdout, excerpt length 8000, no truncated -- so a
    caller that only looks at stdout_excerpt thinks the log ended there.
    """

    def _client(self, tmp_path: Path, stdout: str) -> tuple[GhidraClient, Path, Path]:
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"MZ")
        project = tmp_path / "proj"
        client = GhidraClient()
        client.analyze = Path("/bin/true")
        client.java = Path("/bin/true")
        client._run_headless = lambda *args, **kwargs: (stdout, "", 0)  # type: ignore[method-assign]
        return client, binary, project

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        client, binary, project = self._client(tmp_path, "G" * 20_000)
        result = client.analyze_binary(binary, project)
        assert len(result["stdout_excerpt"]) == 8000
        assert result["stdout_excerpt"] == "G" * 8000
        assert result["truncated"] is True
        assert result["output_chars"] == 20_000
        assert result["returned_chars"] == 8000

    def test_a_short_log_is_complete(self, tmp_path: Path) -> None:
        client, binary, project = self._client(tmp_path, "ok")
        result = client.analyze_binary(binary, project)
        assert result["stdout_excerpt"] == "ok"
        assert "truncated" not in result


class TestGhidraAnalyzeDescriptionMatchesTheCut:
    """ghidra.analyze now cuts the log at 8000 chars, but the tool text hid that.

    Measured: 20000-char stdout, excerpt length 8000, truncated=true, while
    the description never mentioned the cut -- so a model treats the slice
    as the whole analysis log.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.ghidra import build_ghidra_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_ghidra_tools(service)}
            doc = tools["ghidra.analyze"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
