"""An empty apksigner output used to look signed."""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.apktool.client as apktool_mod
from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError


class TestSignDoesNotCallEmptyApkSuccess:
    """Exit 0 plus a 0-byte APK used to look signed.

    Measured: _run returned 0, out_apk existed at 0 bytes, sign() returned
    signed=true -- so a caller treats an empty file as a signed package.
    """

    def _client(self, tmp_path: Path) -> tuple[ApktoolClient, Path, Path, Path]:
        apk = tmp_path / "in.apk"
        apk.write_bytes(b"PK\x03\x04")
        store = tmp_path / "debug.keystore"
        store.write_bytes(b"ks")
        client = ApktoolClient(apksigner=Path("/bin/true"))
        return client, apk, store, tmp_path / "signed.apk"

    def test_an_empty_apk_is_not_signed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, apk, store, out_apk = self._client(tmp_path)

        def fake_run(
            cmd: list[str], *, timeout: float, redact_from: int | None = None
        ) -> tuple[str, str, int]:
            del cmd, timeout, redact_from
            out_apk.write_bytes(b"")
            return ("", "", 0)

        monkeypatch.setattr(apktool_mod, "_run", fake_run)
        with pytest.raises(ApktoolError) as info:
            client.sign(apk, out_apk, keystore=store, keystore_password="x", key_alias="a")
        assert info.value.code == "backend_error"

    def test_a_written_apk_is_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, apk, store, out_apk = self._client(tmp_path)

        def fake_run(
            cmd: list[str], *, timeout: float, redact_from: int | None = None
        ) -> tuple[str, str, int]:
            del cmd, timeout, redact_from
            out_apk.write_bytes(b"PK\x03\x04signed")
            return ("", "", 0)

        monkeypatch.setattr(apktool_mod, "_run", fake_run)
        result = client.sign(
            apk, out_apk, keystore=store, keystore_password="x", key_alias="a"
        )
        assert result["signed"] is True
        assert result["size"] > 0
