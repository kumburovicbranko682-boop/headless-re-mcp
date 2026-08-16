"""An empty apktool build used to look rebuilt."""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.apktool.client as apktool_mod
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


class TestBuildDoesNotCallEmptyApkSuccess:
    """Exit 0 plus a 0-byte APK used to look rebuilt.

    Measured: _run returned 0, out_apk existed at 0 bytes, build() returned
    size=0 -- so a caller treats an empty file as a rebuilt package.
    """

    def _client(self, tmp_path: Path) -> tuple[ApktoolClient, Path, Path]:
        decoded = tmp_path / "out"
        decoded.mkdir()
        (decoded / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
        client = ApktoolClient(apktool=Path("/bin/true"))
        return client, decoded, tmp_path / "built.apk"

    def test_an_empty_apk_is_not_rebuilt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, decoded, out_apk = self._client(tmp_path)

        def fake_run(
            cmd: list[str], *, timeout: float, redact_from: int | None = None
        ) -> tuple[str, str, int]:
            del cmd, timeout, redact_from
            out_apk.write_bytes(b"")
            return ("", "", 0)

        monkeypatch.setattr(apktool_mod, "_run", fake_run)
        with pytest.raises(ApktoolError) as info:
            client.build(decoded, out_apk)
        assert info.value.code == "backend_error"

    def test_a_written_apk_is_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, decoded, out_apk = self._client(tmp_path)

        def fake_run(
            cmd: list[str], *, timeout: float, redact_from: int | None = None
        ) -> tuple[str, str, int]:
            del cmd, timeout, redact_from
            out_apk.write_bytes(b"PK\x03\x04")
            return ("", "", 0)

        monkeypatch.setattr(apktool_mod, "_run", fake_run)
        result = client.build(decoded, out_apk)
        assert result["size"] == 4
        assert result["signed"] is False
