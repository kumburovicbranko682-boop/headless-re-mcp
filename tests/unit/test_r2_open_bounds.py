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
