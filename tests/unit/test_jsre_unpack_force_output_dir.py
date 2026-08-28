"""unpack_bundle must pass --force so webcrack writes into the dir we made.

webcrack (2.x, the line the backend targets on Node 22/24) refuses a
pre-existing ``-o`` directory with "output directory already exists", exit 1,
and writes nothing. ``unpack_bundle`` creates ``out_dir`` itself before
invoking webcrack (retention needs a stable path it owns), so without
``--force`` every real unpack tripped that guard and raised "webcrack unpack
failed". The other unpack tests fake ``_run`` without modelling the guard, so
they never caught it; this one encodes webcrack's actual contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError


def _webcrack_contract_run(
    cmd: list[str], *, timeout: float, maximum: float = 0.0
) -> tuple[str, str, int]:
    """Mimic webcrack: refuse an *existing* -o dir unless --force is present.

    Real webcrack refuses any directory that already exists — including an empty
    one — and the backend's own ``mkdir(exist_ok=True)`` means the directory
    always exists by the time webcrack runs. So the refusal turns on existence,
    not emptiness.
    """
    del timeout, maximum
    out_dir = Path(cmd[cmd.index("-o") + 1])
    forced = "-f" in cmd or "--force" in cmd
    if out_dir.exists() and not forced:
        return "", "output directory already exists\n", 1
    out_dir.mkdir(parents=True, exist_ok=True)
    for index in range(3):
        (out_dir / f"mod-{index}.js").write_text("x", encoding="utf-8")
    return "", "", 0


def test_unpack_passes_force_so_a_precreated_dir_is_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_run", _webcrack_contract_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    # A dir that already holds output, exactly like a repeated unpack — the
    # backend's own mkdir(exist_ok=True) plus a prior run's files.
    out = tmp_path / "out"
    out.mkdir()
    (out / "stale.js").write_text("old", encoding="utf-8")

    client = JsClient(executable=Path("/bin/true"))
    result = client.unpack_bundle(bundle, out)

    assert result["file_count"] >= 3
    assert result.get("tool_failed") is None


def test_without_force_the_webcrack_contract_would_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard the guard: strip -f from argv and the same run must fail.

    This is the exact shipped bug — a *fresh* unpack. The backend's own
    ``out_dir.mkdir(exist_ok=True)`` leaves an empty directory, webcrack without
    --force refuses it ("already exists", exit 1, nothing written), the listing
    finds nothing, and ``code != 0 and not files`` raises. Proving the flag is
    load-bearing: if a refactor drops it, this fails instead of passing quietly.
    """

    def strip_force_run(
        cmd: list[str], *, timeout: float, maximum: float = 0.0
    ) -> tuple[str, str, int]:
        stripped = [arg for arg in cmd if arg not in ("-f", "--force")]
        return _webcrack_contract_run(stripped, timeout=timeout, maximum=maximum)

    monkeypatch.setattr(jsre_client, "_run", strip_force_run)
    bundle = tmp_path / "app.js"
    bundle.write_text("bundle", encoding="utf-8")
    # No pre-population: the backend's mkdir makes this empty, which is what
    # makes the fresh-unpack failure raise rather than return stale files.
    out = tmp_path / "out"

    client = JsClient(executable=Path("/bin/true"))
    with pytest.raises(JsReError) as caught:
        client.unpack_bundle(bundle, out)
    assert caught.value.code == "backend_error"
