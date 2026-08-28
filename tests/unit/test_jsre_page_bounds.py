"""js.unpack_bundle must reject non-integer page bounds as invalid_params.

The jsre.unpack schema types ``offset``/``limit`` as integers, but only the MCP
transport runs that pydantic validation: the agent and OpenAI-bridge transports
call the bound handler directly, so a hostile page argument reaches the backend
unchecked. Before the fix ``unpack_bundle`` fed the value straight to
``int(...)`` after running webcrack, so a float (inf from a JSON 1e400), nan,
null, a non-numeric string, or a container raised
OverflowError/ValueError/TypeError -- none a JsReError, so the service's
``except BaseException`` filed an internal_error incident for what is only a bad
page window. The guard now runs before webcrack, so a bad page also fails fast.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError

_HOSTILE = [
    math.inf,
    -math.inf,
    math.nan,
    None,
    "abc",
    "",
    {},
    [],
    True,
    False,
]


def _fake_run(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
    del timeout, maximum
    out_dir = Path(cmd[cmd.index("-o") + 1])
    if not any(out_dir.iterdir()):
        for index in range(20):
            (out_dir / f"mod-{index:02d}.js").write_text("x", encoding="utf-8")
    return "", "", 0


@pytest.mark.parametrize("bad", _HOSTILE)
def test_unpack_hostile_offset_is_invalid_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: object
) -> None:
    monkeypatch.setattr(jsre_client, "_run", _fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError) as excinfo:
        client.unpack_bundle(bundle, tmp_path / "out", offset=bad, limit=10)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", _HOSTILE)
def test_unpack_hostile_limit_is_invalid_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: object
) -> None:
    monkeypatch.setattr(jsre_client, "_run", _fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError) as excinfo:
        client.unpack_bundle(bundle, tmp_path / "out", offset=0, limit=bad)  # type: ignore[arg-type]
    assert excinfo.value.code == "invalid_params"


def test_hostile_page_fails_before_spawning_webcrack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bad page is a caller error; it must not cost an unpack run."""
    calls: list[list[str]] = []

    def _spy_run(cmd: list[str], *, timeout: float, maximum: float = 0.0) -> tuple[str, str, int]:
        calls.append(cmd)
        return "", "", 0

    monkeypatch.setattr(jsre_client, "_run", _spy_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError):
        client.unpack_bundle(bundle, tmp_path / "out", offset=math.inf, limit=10)  # type: ignore[arg-type]
    assert calls == []


def test_valid_and_clampable_bounds_still_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative and oversized numeric bounds clamp; int-like strings still parse."""
    monkeypatch.setattr(jsre_client, "_run", _fake_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    client = JsClient(executable=Path("/bin/true"))
    page = client.unpack_bundle(bundle, tmp_path / "out", offset=-5, limit=10**9)
    assert page["offset"] == 0
    assert page["count"] == 20
    page = client.unpack_bundle(bundle, tmp_path / "out2", offset="2", limit="3")  # type: ignore[arg-type]
    assert page["offset"] == 2
    assert page["count"] == 3
