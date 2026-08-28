"""jsre's inline output must fit under the transport result budget.

Both transports run every tool reply through ``bounded_tool_result`` with the
tool's ``ResourcePolicy.max_result_bytes`` (262_144). That helper does not trim
an over-budget reply -- it replaces the whole thing with a ~16 KB text summary,
dropping the structured envelope. So an inline field bigger than the budget is
not shortened, it is destroyed together with the ``code`` / ``wat`` / ``objdump``
value the caller asked for.

js.deobfuscate / js.beautify and wasm.wat / wasm.info return their output inline
(capped at ``jsre._MAX_INLINE``) and, unlike the web/proxy backends, never spill
the overflow to an artifact. When that cap sat at 400 KB there was a dead zone:
output between 262 KB and 400 KB left jsre with ``truncated=False`` and then the
transport summarised the entire reply away. This pins the cap under the budget so
jsre's own honest truncation fires first, and pins it consistent with the sibling
backends that made the same choice.
"""

from __future__ import annotations

import json

import pytest

from headless_re_mcp.agent.context import bounded_tool_result
from headless_re_mcp.backends.jsre.client import _MAX_INLINE, _bounded_output
from headless_re_mcp.core.commands import COMMAND_CATALOG

_JSRE_INLINE_TOOLS = ("js.deobfuscate", "js.beautify", "wasm.wat", "wasm.info")


@pytest.mark.parametrize("name", _JSRE_INLINE_TOOLS)
def test_inline_cap_stays_under_the_transport_budget(name: str) -> None:
    budget = COMMAND_CATALOG.require(name).resource_policy.max_result_bytes
    assert budget >= _MAX_INLINE, (
        f"{name} inlines up to {_MAX_INLINE} bytes but the transport budget is only "
        f"{budget}; a reply in that gap is replaced wholesale by a ~16 KB summary, "
        "destroying the structured output field. Lower jsre._MAX_INLINE."
    )


def test_inline_cap_matches_the_web_and_proxy_backends() -> None:
    # The three backends that inline captured text all face the same transport
    # budget; keeping the caps equal stops one drifting back into the dead zone.
    from headless_re_mcp.backends.proxy.client import _MAX_INLINE_BODY as proxy_body
    from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY as web_body

    assert _MAX_INLINE == web_body == proxy_body


def test_a_capped_reply_survives_the_transport_budget_intact() -> None:
    # webcrack emits far more than the cap; jsre truncates to _MAX_INLINE. The
    # capped reply -- newline-heavy like real formatted code, so JSON escaping is
    # exercised -- must then pass the transport budget without being summarised,
    # i.e. the caller still receives the `code` field rather than a text blob.
    oversized = ("const value = compute();\n" * 40_000)
    assert len(oversized.encode("utf-8")) > _MAX_INLINE

    reply = _bounded_output(oversized, "code", include_bytes=True)
    assert reply["truncated"] is True
    assert len(reply["code"].encode("utf-8")) <= _MAX_INLINE

    budget = COMMAND_CATALOG.require("js.deobfuscate").resource_policy.max_result_bytes
    envelope = {"ok": True, "data": reply, "meta": {}}
    bounded, was_summarised = bounded_tool_result(envelope, max_bytes=budget)

    assert was_summarised is False, (
        "a jsre reply truncated to its own inline cap still overflowed the transport "
        "budget and was summarised away -- the inline cap is too close to the budget "
        "once JSON escaping and the envelope are counted."
    )
    assert bounded["data"]["code"], "the structured code field did not survive"
    assert len(json.dumps(bounded).encode("utf-8")) <= budget
