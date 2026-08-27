"""jsre must disclose when run_bounded's capture cap discarded tool output.

`_run` decodes what `run_bounded` captured, and `run_bounded` caps each stream
at DEFAULT_MAX_OUTPUT and throws away the rest, recording that in
`Completed.stdout_truncated`. The deobfuscate / wat / info payloads report
`bytes` (documented as the full output size) and `truncated` (the inline
_MAX_INLINE display cut, with `bytes` still exact). But when the capture cap
fired, `bytes` is only a floor and the excess is gone -- and `_run` used to
drop `stdout_truncated`, so a 40 MiB deobfuscation read back as exactly the
8 MiB ceiling with nothing to say the rest was lost. The fix surfaces
`output_capped` for that case; the input cap is 16 MiB while beautified JS and
WAT text routinely expand past the capture ceiling, so it is a real path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, WasmClient


def _completed(stdout: bytes, *, stdout_truncated: bool) -> Completed:
    return Completed(
        returncode=0,
        stdout=stdout,
        stderr=b"",
        stdout_truncated=stdout_truncated,
        stderr_truncated=False,
    )


def _js_client_capturing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, stdout: bytes, stdout_truncated: bool
) -> tuple[JsClient, Path]:
    source = tmp_path / "bundle.js"
    source.write_text("x")  # tiny, valid input under the 16 MiB cap
    monkeypatch.setattr(
        jsre_client,
        "run_bounded",
        lambda *args, **kwargs: _completed(stdout, stdout_truncated=stdout_truncated),
    )
    # The executable path is only spliced into the argv; run_bounded is stubbed,
    # so it need not exist. _require_input checks the input file, not the exe.
    return JsClient(executable=tmp_path / "webcrack"), source


def test_deobfuscate_flags_output_capped_when_capture_was_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A capture-capped run reports output_capped so bytes reads as a floor.

    run_bounded set stdout_truncated because it discarded output past its cap.
    The payload must carry output_capped=True alongside the still-True inline
    truncated, and bytes is the captured length -- a lower bound on the real
    size, not the exact figure the docstring otherwise promises.
    """
    captured = b"A" * (jsre_client._MAX_INLINE + 10)
    client, source = _js_client_capturing(
        monkeypatch, tmp_path, stdout=captured, stdout_truncated=True
    )

    payload = client.deobfuscate(source)

    assert payload["output_capped"] is True
    assert payload["truncated"] is True
    assert payload["bytes"] == len(captured)


def test_deobfuscate_omits_output_capped_when_the_capture_fit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No capture cut means bytes is exact, so output_capped stays absent.

    The inline text is still cut at _MAX_INLINE (truncated=True), but nothing
    beyond the capture ceiling was lost, so bytes is the true size and the
    output_capped flag must not appear -- it is added only when it fired,
    mirroring tool_failed.
    """
    captured = b"A" * (jsre_client._MAX_INLINE + 10)
    client, source = _js_client_capturing(
        monkeypatch, tmp_path, stdout=captured, stdout_truncated=False
    )

    payload = client.deobfuscate(source)

    assert "output_capped" not in payload
    assert payload["truncated"] is True
    assert payload["bytes"] == len(captured)


def test_wasm_wat_flags_output_capped_when_capture_was_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wasm2wat path threads the same flag: WAT text expands past the cap.

    A multi-megabyte module's text form easily overruns the capture ceiling,
    so wat must disclose output_capped exactly as the JS path does.
    """
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    captured = b"(module\n" + b" " * (jsre_client._MAX_INLINE + 10) + b")"
    monkeypatch.setattr(
        jsre_client,
        "run_bounded",
        lambda *args, **kwargs: _completed(captured, stdout_truncated=True),
    )
    client = WasmClient()
    # Bypass tool resolution (wasm2wat is not installed here); _require_input
    # only needs a non-None tool plus the wasm magic on the input, both set.
    client._wasm2wat = tmp_path / "wasm2wat"

    payload = client.wat(module)

    assert payload["output_capped"] is True
    assert payload["truncated"] is True
    assert payload["bytes"] == len(captured)


def test_bounded_output_adds_the_flag_only_when_capped() -> None:
    """_bounded_output gates output_capped on its argument, not on the text size."""
    capped = jsre_client._bounded_output("payload", "code", include_bytes=True, output_capped=True)
    assert capped["output_capped"] is True
    assert capped["bytes"] == len(b"payload")

    plain = jsre_client._bounded_output(
        "payload", "code", include_bytes=True, output_capped=False
    )
    assert "output_capped" not in plain
