"""batch.analyze mixed-target gate: non-PE samples are not failures, over real MCP.

batch.analyze is the unattended triage tool: point it at a folder of samples
and read succeeded/failed. Its open_static flag (the default) drives the
PE/IDA static backend, which does not apply to an APK or a web asset -- and
the batch used to fold that inapplicability into ok=false, so a mixed folder
reported every non-PE sample as failed even though its session was created
and its identity extracted. An operator reading that count would conclude the
APKs are broken.

This gate runs the real MCP stdio server (no fake service objects) and pins
the honest contract on a batch of one APK, one web asset and one missing
path, all with open_static=true:

- The APK entry is ok with a live session id, static_open=false and
  static_open_applicable=false, and no error. The session id is then proven
  live over the same MCP connection: session.get answers with target=apk and
  the identity metadata (ABIs, dex count, signature) that create extracted.
- The web entry gets the same treatment: ok, not-applicable, live session.
- The missing path stays a genuine failure (ok=false with a structured error
  naming the file), so "not applicable" has not been confused with "nothing
  can fail any more".
- succeeded/failed tally exactly the ok flags: 2/1.
"""

from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

mcp = pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

JsonObject = dict[str, Any]


def _build_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
    return path


def _structured(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


def _server_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    config_home = tmp_path / "config"
    config_home.mkdir(exist_ok=True)
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    return env


@pytest.mark.integration
@pytest.mark.asyncio
async def test_batch_analyze_mixed_targets_over_mcp(tmp_path: Path) -> None:
    apk = _build_apk(tmp_path / "sample.apk")
    web_asset = tmp_path / "bundle.js"
    web_asset.write_text("function greet(name){return 'hi '+name;}\n", encoding="utf-8")
    missing = tmp_path / "not-there.exe"

    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=_server_env(tmp_path),
        cwd=str(project_root),
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        batch = _structured(
            await client.call_tool(
                "batch.analyze",
                {
                    "binaries": [str(apk), str(web_asset), str(missing)],
                    "max_workers": 2,
                    "open_static": True,
                },
            )
        )
        assert batch["ok"] is True, batch
        data = batch["data"]
        assert data["count"] == 3

        by_name = {Path(str(entry["binary"])).name: entry for entry in data["entries"]}

        # The APK: created, identified, and honest that PE static does not apply.
        apk_entry = by_name["sample.apk"]
        assert apk_entry["ok"] is True, apk_entry
        assert apk_entry["session_id"], apk_entry
        assert apk_entry["static_open"] is False
        assert apk_entry["static_open_applicable"] is False
        assert "error" not in apk_entry, apk_entry

        # The web asset gets the same contract.
        web_entry = by_name["bundle.js"]
        assert web_entry["ok"] is True, web_entry
        assert web_entry["session_id"], web_entry
        assert web_entry["static_open_applicable"] is False

        # Not-applicable must not have eaten real failures: the missing path
        # is still one, with a structured error.
        missing_entry = by_name["not-there.exe"]
        assert missing_entry["ok"] is False, missing_entry
        assert missing_entry["session_id"] is None
        error = missing_entry.get("error")
        assert isinstance(error, dict) and error.get("code"), missing_entry

        # The tally is exactly the ok flags, so an operator can trust it.
        assert data["succeeded"] == 2, data
        assert data["failed"] == 1, data

        # "ok" is backed by a live session, not just a flag: the APK session
        # answers over the same MCP connection with its extracted identity.
        info = _structured(
            await client.call_tool(
                "session.get", {"session_id": str(apk_entry["session_id"])}
            )
        )
        assert info["ok"] is True, info
        session = info["data"]["session"]
        assert session["target"] == "apk"
        identity = session["metadata"]["apk"]
        assert set(identity["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert identity["dex_count"] == 1
        assert identity["signed_v1"] is True

        web_info = _structured(
            await client.call_tool(
                "session.get", {"session_id": str(web_entry["session_id"])}
            )
        )
        assert web_info["ok"] is True, web_info
        assert web_info["data"]["session"]["target"] != "pe"

        for entry in (apk_entry, web_entry):
            closed = _structured(
                await client.call_tool(
                    "session.close", {"session_id": str(entry["session_id"])}
                )
            )
            assert closed["ok"] is True, closed
