"""js.unpack_bundle must tell webcrack to overwrite its output directory.

The service hands the client a freshly-created per-call artifact directory, but
webcrack refuses to write into a directory that already exists unless passed
``--force``. Without it every unpack failed with "output directory already
exists" -- a bug the fake-tool unit tests missed because their stubs write into
whatever directory they are given. This pins the flag onto the argv.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient


def test_unpack_bundle_passes_force_and_keeps_the_output_flag(
    tmp_path: Path, monkeypatch: Any
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], *, timeout: float) -> tuple[str, str, int]:
        del timeout
        captured["cmd"] = list(cmd)
        out_dir = Path(cmd[cmd.index("-o") + 1])
        (out_dir / "deobfuscated.js").write_text("ok", encoding="utf-8")
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    out = tmp_path / "out"

    result = JsClient(executable=Path("/bin/true")).unpack_bundle(bundle, out, limit=10)

    assert result["file_count"] == 1
    cmd = captured["cmd"]
    assert "--force" in cmd
    # --force must not displace the output path it is meant to overwrite.
    assert cmd[cmd.index("-o") + 1] == str(out)
