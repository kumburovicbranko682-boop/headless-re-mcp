"""A decode that wrote no manifest used to look unpacked."""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.apktool.client as apktool_mod
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


class TestDecodeDoesNotCallEmptyTreeSuccess:
    """Exit 0 plus no AndroidManifest.xml used to look decoded.

    Measured: _run returned 0, out_dir empty, decode() returned
    decoded_dir with manifest=None -- so a caller treats an empty tree
    as this run's unpack and then rebuilds it.
    """

    def _client(self, tmp_path: Path) -> tuple[ApktoolClient, Path, Path]:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04")
        client = ApktoolClient(apktool=Path("/bin/true"))
        return client, apk, tmp_path / "decoded"

    def test_a_missing_manifest_is_not_decoded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, apk, out = self._client(tmp_path)

        def fake_run(
            cmd: list[str], *, timeout: float, redact_from: int | None = None
        ) -> tuple[str, str, int]:
            del cmd, timeout, redact_from
            out.mkdir(parents=True, exist_ok=True)
            return ("", "", 0)

        monkeypatch.setattr(apktool_mod, "_run", fake_run)
        with pytest.raises(ApktoolError) as info:
            client.decode(apk, out)
        assert info.value.code == "backend_error"

    def test_a_written_manifest_is_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, apk, out = self._client(tmp_path)

        def fake_run(
            cmd: list[str], *, timeout: float, redact_from: int | None = None
        ) -> tuple[str, str, int]:
            del cmd, timeout, redact_from
            out.mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
            (out / "smali").mkdir()
            return ("", "", 0)

        monkeypatch.setattr(apktool_mod, "_run", fake_run)
        result = client.decode(apk, out)
        assert result["manifest"] == str(out / "AndroidManifest.xml")
        assert result["smali_dirs"] == ["smali"]
