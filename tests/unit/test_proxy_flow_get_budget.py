"""proxy.flow.get must spill a body whose JSON-encoded form overruns the budget.

The inline gate was a raw char count (200000). A UTF-8 text body under that
length but full of quotes/backslashes encodes to far more -- a quote-heavy
180000-char body is ~360 KB encoded, past the 262144 result budget -- so the
whole flow_get reply would be discarded for a ~16 KiB summary. flow_get now
spills such a body to a file instead, the same way web.network_get does.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
from headless_re_mcp.backends.proxy.client import ProxyBackend


def test_flow_get_spills_a_quote_heavy_body_that_encodes_past_the_budget(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # 180000 quote chars: under the 200000 char cap (so the raw gate does not
    # fire) but ~360 KB once JSON-encoded, so the encoded-size gate must spill.
    raw = b'"' * 180_000
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/1", headers={"accept": "text/plain"}
    )
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=raw
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            del flow_id
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )

    payload = backend.flow_get("s", "f1", tmp_path)

    assert "body" not in payload["response"]
    spilled = Path(str(payload["response"]["body_path"]))
    assert spilled.parent == tmp_path
    assert spilled.read_bytes() == raw
    assert payload["response"]["size"] == 180_000
    encoded = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    assert encoded <= RESULT_BUDGET_BYTES
