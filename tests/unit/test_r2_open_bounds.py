"""r2.open used to cut the identity text without saying so."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.r2.client import R2Client


class TestR2OpenSaysWhenItStopped:
    """An identity page that hit 8000 chars used to look complete.

    Measured: 20000-char raw, info length 8000, no truncated -- so a
    caller that only looks at info thinks the binary identity ended.
    """

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        binary = tmp_path / "t.exe"
        binary.write_bytes(b"MZ")
        client = R2Client(tmp_path / "r2")
        client.run = lambda *args, **kwargs: {"raw": "I" * 20_000}  # type: ignore[method-assign]
        result = client.open(binary)
        assert len(result["info"]) == 8000
        assert result["truncated"] is True
        assert result["output_chars"] == 20_000

    def test_a_short_identity_is_complete(self, tmp_path: Path) -> None:
        binary = tmp_path / "t.exe"
        binary.write_bytes(b"MZ")
        client = R2Client(tmp_path / "r2")
        client.run = lambda *args, **kwargs: {"raw": "ok"}  # type: ignore[method-assign]
        result = client.open(binary)
        assert result["info"] == "ok"
        assert "truncated" not in result


class TestR2OpenDescriptionMatchesTheCut:
    """r2.open now cuts info at 8000 chars, but the tool text hid that.

    Measured: 20000-char identity, info length 8000, truncated=true, while
    the description never mentioned the cut -- so a model treats the slice
    as the whole identity.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.r2 import build_r2_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_r2_tools(service)}
            doc = tools["r2.open"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc


class TestR2InfoDescriptionMatchesTheCut:
    """r2.info already cuts at 1000000 bytes, but the tool text hid that.

    Measured: 1000050-byte stdout, raw length 1000000, truncated=true, while
    the description never mentioned the cut -- so a model treats the slice
    as the whole identity.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.r2 import build_r2_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_r2_tools(service)}
            doc = tools["r2.info"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
